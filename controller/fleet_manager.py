"""Fleet Lifecycle Manager for orchestrating Axiom scanner VMs with guaranteed cleanup."""

import json
import logging
import os
import shutil
import subprocess  # nosec B404
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from controller.config import settings
from controller.profiles import ScannerProfile, get_profile

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("controller.fleet_manager")


class FleetError(Exception):
    """Base exception for fleet orchestration errors."""

    pass


class FleetManager:
    """Manages Axiom fleet lifecycle, execution, and fail-safe teardown."""

    def __init__(self, axiom_bin_dir: str | None = None, dry_run: bool | None = None):
        self.axiom_bin_dir = Path(axiom_bin_dir or settings.axiom_bin_path)
        self.dry_run = dry_run if dry_run is not None else settings.dry_run
        self.work_dir = Path(settings.work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Binary resolution helpers
    # ------------------------------------------------------------------

    def _resolve_httpx_binary(self) -> str:
        """Locate ProjectDiscovery httpx binary for standalone direct execution."""
        candidates = [
            str(Path.home() / "go" / "bin" / "httpx.exe"),
            str(Path.home() / "go" / "bin" / "httpx"),
            "/usr/local/bin/httpx",
            "/usr/bin/httpx",
            shutil.which("httpx-pd"),
            shutil.which("httpx"),
        ]
        for candidate in candidates:
            if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
                # Verify it is not the python httpx package inside venv or python Scripts
                cand_str = str(candidate).lower()
                if "venv" not in cand_str and "programs\\python" not in cand_str and "programs/python" not in cand_str:
                    return candidate

        system_bin = shutil.which("httpx")
        if system_bin and "venv" not in system_bin.lower() and "programs\\python" not in system_bin.lower():
            return system_bin

        if self.dry_run:
            return "mock-httpx"

        raise FileNotFoundError("ProjectDiscovery 'httpx' binary not found at ~/go/bin/httpx, /usr/local/bin/httpx, or in PATH.")

    def _resolve_binary(self, binary_name: str) -> str:
        """Locate Axiom binary either in configured path or system PATH."""
        custom_path = self.axiom_bin_dir / binary_name
        if custom_path.is_file() and os.access(custom_path, os.X_OK):
            return str(custom_path)

        system_bin = shutil.which(binary_name)
        if system_bin:
            return system_bin

        if self.dry_run:
            return f"mock-{binary_name}"

        raise FileNotFoundError(
            f"Axiom binary '{binary_name}' not found at '{custom_path}' or in system PATH. "
            "Ensure Axiom is installed or enable dry_run mode."
        )

    def _resolve_scanner_binary_for_profile(self, profile: ScannerProfile) -> str:
        """Resolve the correct standalone scanner binary for a given profile.

        Resolution order: Go bin dir → common system paths → system PATH → dry-run mock.
        """
        binary_name = profile.standalone_binary

        # httpx gets special treatment to avoid python httpx package collision
        if binary_name == "httpx":
            return self._resolve_httpx_binary()

        # Go-installed binaries (nuclei, ffuf live here by default)
        go_bin_candidates = [
            str(Path.home() / "go" / "bin" / f"{binary_name}.exe"),
            str(Path.home() / "go" / "bin" / binary_name),
        ]
        for candidate in go_bin_candidates:
            if Path(candidate).is_file() and os.access(candidate, os.X_OK):
                return candidate

        # Python virtual environment Scripts directory
        import sys

        venv_bin_candidates = [
            str(Path(sys.executable).parent / f"{binary_name}.exe"),
            str(Path(sys.executable).parent / binary_name),
        ]
        for candidate in venv_bin_candidates:
            if Path(candidate).is_file() and os.access(candidate, os.X_OK):
                return candidate

        # System PATH
        system_bin = shutil.which(binary_name)
        if system_bin:
            return system_bin

        if self.dry_run:
            return f"mock-{binary_name}"

        raise FileNotFoundError(
            f"Scanner binary '{binary_name}' not found in ~/go/bin or system PATH. "
            f"Install it before running profile '{profile.name}', or enable CONTROLLER_DRY_RUN=true."
        )

    def _resolve_ffuf_wordlist(self) -> str:
        """Return the FFUF wordlist path, validating it exists."""
        wl = settings.ffuf_wordlist
        if Path(wl).is_file():
            return wl
        # Fallback to bundled wordlist
        bundled = str(Path(__file__).parent.parent / "scripts" / "wordlists" / "common.txt")
        if Path(bundled).is_file():
            logger.warning("FFUF wordlist '%s' not found; falling back to bundled wordlist '%s'.", wl, bundled)
            return bundled
        if self.dry_run:
            return wl  # dry-run never reads the file
        raise FileNotFoundError(
            f"FFUF wordlist not found at '{wl}'. Set CONTROLLER_FFUF_WORDLIST to a valid path, or install SecLists to ~/.axiom/wordlists/."
        )

    # ------------------------------------------------------------------
    # Command execution
    # ------------------------------------------------------------------

    def _run_command(self, cmd: list[str], timeout: int | None = None) -> subprocess.CompletedProcess[str]:
        """Execute subprocess command safely without shell=True."""
        logger.info("Executing: %s", " ".join(cmd))
        if self.dry_run:
            logger.info("[DRY-RUN] Simulating command execution: %s", cmd)
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="[dry-run success]\n", stderr="")

        try:
            result = subprocess.run(  # nosec B603
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=timeout or settings.scan_timeout_seconds,
                check=False,
            )
            if result.returncode != 0:
                logger.error("Command failed (code %d): %s\nStderr: %s", result.returncode, " ".join(cmd), result.stderr)
            return result
        except subprocess.TimeoutExpired as exc:
            logger.error("Command timed out after %s seconds: %s", timeout, " ".join(cmd))
            raise FleetError(f"Command timed out after {timeout} seconds: {' '.join(cmd)}") from exc
        except Exception as exc:
            logger.error("Failed to execute command %s: %s", " ".join(cmd), exc)
            raise FleetError(f"Failed to execute command: {exc}") from exc

    # ------------------------------------------------------------------
    # Fleet lifecycle
    # ------------------------------------------------------------------

    def create_fleet(self, fleet_name: str, count: int = 1) -> bool:
        """Spin up a disposable scanner fleet (or use standalone direct mode)."""
        if count > settings.max_fleet_size:
            raise ValueError(f"Requested count ({count}) exceeds maximum allowed fleet size ({settings.max_fleet_size})")

        try:
            bin_path = self._resolve_binary("axiom-fleet")
            cmd = [bin_path, fleet_name, "-i", str(count)]
            result = self._run_command(cmd, timeout=480)
            if result.returncode != 0 and not self.dry_run:
                raise FleetError(f"Failed to create fleet '{fleet_name}': {result.stderr}")
            logger.info("Fleet '%s' with %d instance(s) created successfully.", fleet_name, count)
            return True
        except FileNotFoundError:
            logger.info("Axiom cloud fleet not configured; running in standalone direct engine mode.")
            return True

    def destroy_fleet(self, fleet_name: str) -> bool:
        """Forcefully destroy a scanner fleet to eliminate cloud costs."""
        try:
            try:
                bin_path = self._resolve_binary("axiom-rm")
                cmd = [bin_path, fleet_name, "-f"]
            except FileNotFoundError:
                bin_path = self._resolve_binary("axiom-fleet")
                cmd = [bin_path, "-rm", fleet_name, "-f"]

            result = self._run_command(cmd, timeout=120)
            if result.returncode == 0 or self.dry_run:
                logger.info("Fleet '%s' destroyed successfully.", fleet_name)
                return True
            logger.warning("Failed to destroy fleet '%s': %s", fleet_name, result.stderr)
            return False
        except FileNotFoundError:
            return True

    # ------------------------------------------------------------------
    # Dry-run mock output generators (one per output format)
    # ------------------------------------------------------------------

    def _write_dry_run_output(self, profile: ScannerProfile, target_value: str, output_file_path: Path) -> None:
        """Write a minimal but parseable mock output file for each profile in dry-run mode."""
        if profile.name in ("recon", "web-discovery"):
            output_file_path.write_text(
                json.dumps(
                    {
                        "host": target_value,
                        "status_code": 200,
                        "webserver": "nginx/1.18.0 (Ubuntu)",
                        "title": "Authorized Testing Target",
                        "technologies": ["Nginx", "Ubuntu", "OpenSSL"],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
        elif profile.name == "network-portscan":
            # Minimal nmap XML output
            xml = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<nmaprun scanner="nmap" args="nmap -sV -T4" start="0" '
                f'version="7.94" xmloutputversion="1.05">\n'
                f'<host><status state="up" reason="echo-reply"/>'
                f'<address addr="{target_value}" addrtype="ipv4"/>'
                "<ports>"
                '<port protocol="tcp" portid="80">'
                '<state state="open" reason="syn-ack"/>'
                '<service name="http" product="nginx" version="1.18.0"/>'
                "</port>"
                '<port protocol="tcp" portid="22">'
                '<state state="open" reason="syn-ack"/>'
                '<service name="ssh" product="OpenSSH" version="8.9"/>'
                "</port>"
                "</ports></host></nmaprun>\n"
            )
            output_file_path.write_text(xml, encoding="utf-8")
        elif profile.name == "fast-portscan":
            # Masscan JSON output format
            output_file_path.write_text(
                json.dumps(
                    [
                        {
                            "ip": target_value,
                            "timestamp": str(int(time.time())),
                            "ports": [{"port": 80, "proto": "tcp", "status": "open", "ttl": 64}],
                        },
                        {
                            "ip": target_value,
                            "timestamp": str(int(time.time())),
                            "ports": [{"port": 443, "proto": "tcp", "status": "open", "ttl": 64}],
                        },
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
        elif profile.name == "content-discovery":
            # FFUF JSON output format
            output_file_path.write_text(
                json.dumps(
                    {
                        "results": [
                            {"url": f"https://{target_value}/admin", "status": 301, "length": 0, "words": 0, "lines": 0, "duration": 12},
                            {"url": f"https://{target_value}/api", "status": 200, "length": 512, "words": 8, "lines": 1, "duration": 18},
                            {
                                "url": f"https://{target_value}/login",
                                "status": 200,
                                "length": 2048,
                                "words": 40,
                                "lines": 60,
                                "duration": 25,
                            },
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )
        elif profile.name == "vuln-assessment":
            # Nuclei JSONL output (one JSON object per line)
            findings = [
                {
                    "template-id": "http-missing-security-headers",
                    "info": {"name": "HTTP Missing Security Headers", "severity": "info"},
                    "host": f"https://{target_value}",
                    "matched-at": f"https://{target_value}",
                    "extracted-results": [],
                },
                {
                    "template-id": "cve-2021-44228",
                    "info": {"name": "Log4Shell RCE", "severity": "critical"},
                    "host": f"https://{target_value}",
                    "matched-at": f"https://{target_value}/api/v1/login",
                    "extracted-results": [],
                },
            ]
            output_file_path.write_text("\n".join(json.dumps(f) for f in findings) + "\n", encoding="utf-8")

        elif profile.name == "sast-joern":
            # Joern structured SAST findings output format
            findings = [
                {
                    "rule_id": "sql-injection",
                    "title": "SQL Injection in User Query Handler",
                    "description": "Untrusted input reaches SQL execute sink without parameterization.",
                    "score": 9.2,
                    "severity": "CRITICAL",
                    "file": f"src/{target_value}/db/queries.py",
                    "line": 42,
                    "function": "get_user_by_id",
                    "evidence": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
                    "remediation": "Use parameterized queries or ORM abstractions instead of string formatting.",
                },
                {
                    "rule_id": "command-injection",
                    "title": "Unsanitized System Command Execution",
                    "description": "External user argument passed to shell execution sink.",
                    "score": 8.5,
                    "severity": "HIGH",
                    "file": f"src/{target_value}/utils/system.py",
                    "line": 105,
                    "function": "run_backup_cmd",
                    "evidence": "os.system(f'tar -czf backup.tar.gz {path}')",
                    "remediation": "Avoid executing dynamic shell commands. Use subprocess with argument lists.",
                },
                {
                    "rule_id": "hardcoded-secret",
                    "title": "Hardcoded API Key / Secret Disclosed",
                    "description": "High-entropy secret token identified in source file.",
                    "score": 5.0,
                    "severity": "MEDIUM",
                    "file": f"src/{target_value}/config.py",
                    "line": 14,
                    "function": "None",
                    "evidence": "API_SECRET = 'ak_live_9981293182391283'",
                    "remediation": "Store secrets in environment variables or a secure key management service.",
                },
            ]
            output_file_path.write_text(json.dumps(findings, indent=2) + "\n", encoding="utf-8")

        elif profile.name == "sast-semgrep":
            semgrep_data = {
                "results": [
                    {
                        "check_id": "python.lang.security.audit.sqli.raw-sql-format",
                        "path": f"src/{target_value}/db/queries.py",
                        "start": {"line": 42, "col": 5},
                        "end": {"line": 42, "col": 48},
                        "extra": {
                            "message": "User input directly formatted into SQL query string without parameterization.",
                            "severity": "ERROR",
                            "lines": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
                            "metadata": {
                                "cwe": ["CWE-89: SQL Injection"],
                                "owasp": ["A03:2021 - Injection"],
                                "category": "security",
                            },
                        },
                    },
                    {
                        "check_id": "python.lang.security.audit.dangerous-system-call",
                        "path": f"src/{target_value}/utils/system.py",
                        "start": {"line": 105, "col": 5},
                        "end": {"line": 105, "col": 35},
                        "extra": {
                            "message": "Unsanitized external input passed directly to os.system.",
                            "severity": "ERROR",
                            "lines": "os.system(f'tar -czf backup.tar.gz {path}')",
                            "metadata": {
                                "cwe": ["CWE-78: Command Injection"],
                                "owasp": ["A03:2021 - Injection"],
                                "category": "security",
                            },
                        },
                    },
                    {
                        "check_id": "generic.secrets.security.detected-hardcoded-secret",
                        "path": f"src/{target_value}/config.py",
                        "start": {"line": 14, "col": 1},
                        "end": {"line": 14, "col": 45},
                        "extra": {
                            "message": "Hardcoded high-entropy secret detected.",
                            "severity": "WARNING",
                            "lines": "API_SECRET = 'ak_live_9981293182391283'",
                            "metadata": {
                                "cwe": ["CWE-798: Use of Hard-coded Credentials"],
                                "owasp": ["A07:2021 - Identification and Authentication Failures"],
                                "category": "security",
                            },
                        },
                    },
                ],
                "errors": [],
                "paths": {
                    "scanned": [f"src/{target_value}/db/queries.py", f"src/{target_value}/utils/system.py", f"src/{target_value}/config.py"]
                },
            }
            output_file_path.write_text(json.dumps(semgrep_data, indent=2) + "\n", encoding="utf-8")

        elif profile.name == "sast-trufflehog":
            truffle_records = [
                {
                    "SourceMetadata": {
                        "Data": {
                            "Filesystem": {
                                "file": f"src/{target_value}/config.py",
                                "line": 14,
                            }
                        }
                    },
                    "DetectorName": "AWS",
                    "DetectorType": 2,
                    "Verified": True,
                    "Raw": "<REDACTED>",
                    "Redacted": "AKIAIOSFODNN7EXAMPLE",
                    "ExtraData": {"account": "123456789012"},
                },
                {
                    "SourceMetadata": {
                        "Data": {
                            "Filesystem": {
                                "file": f"src/{target_value}/auth.py",
                                "line": 28,
                            }
                        }
                    },
                    "DetectorName": "GitHub",
                    "DetectorType": 5,
                    "Verified": False,
                    "Raw": "<REDACTED>",
                    "Redacted": "ghp_xxxxxxxxxxxxxxxxxxxx",
                    "ExtraData": {},
                },
                {
                    "SourceMetadata": {
                        "Data": {
                            "Filesystem": {
                                "file": f"src/{target_value}/secrets.env",
                                "line": 5,
                            }
                        }
                    },
                    "DetectorName": "Slack",
                    "DetectorType": 12,
                    "Verified": False,
                    "Raw": "<REDACTED>",
                    "Redacted": "xoxb-xxxxxxxxxxxx-xxxxxxxxxxxx",
                    "ExtraData": {},
                },
            ]
            ndjson = "\n".join(json.dumps(r) for r in truffle_records) + "\n"
            output_file_path.write_text(ndjson, encoding="utf-8")

    # ------------------------------------------------------------------
    # Main scan execution — routes to Axiom or standalone per profile
    # ------------------------------------------------------------------

    def execute_scan(
        self,
        fleet_name: str,
        profile_name: str,
        target_value: str,
        output_file_path: Path,
    ) -> Path:
        """Execute a fixed scanner profile against an authorized target."""
        profile: ScannerProfile = get_profile(profile_name)

        # Write sanitized target to temporary file (used by most tools)
        target_file = self.work_dir / f"target_{fleet_name}_{int(time.time())}.txt"
        target_file.write_text(f"{target_value}\n", encoding="utf-8")

        output_file_path.parent.mkdir(parents=True, exist_ok=True)

        # Determine if Axiom or standalone direct scanner is used
        use_axiom = False
        if not self.dry_run:
            try:
                axiom_scan = self._resolve_binary("axiom-scan")
                use_axiom = True
            except FileNotFoundError:
                use_axiom = False

        try:
            if self.dry_run:
                self._write_dry_run_output(profile, target_value, output_file_path)
                self._run_command(["mock-scan", "--profile", profile_name], timeout=profile.default_timeout_sec)
                return output_file_path

            if use_axiom:
                cmd = [
                    axiom_scan,
                    str(target_file),
                    "-m",
                    profile.axiom_module,
                    "--fleet",
                    fleet_name,
                    "-o",
                    str(output_file_path),
                ] + profile.extra_flags
            else:
                cmd = self._build_standalone_cmd(profile, target_value, target_file, output_file_path)

            result = self._run_command(cmd, timeout=profile.default_timeout_sec)
            if result.returncode != 0:
                raise FleetError(f"Scan failed for target '{target_value}' (profile: {profile_name}): {result.stderr}")
            return output_file_path
        finally:
            if target_file.exists():
                target_file.unlink(missing_ok=True)

    def _build_standalone_cmd(
        self,
        profile: ScannerProfile,
        target_value: str,
        target_file: Path,
        output_file_path: Path,
    ) -> list[str]:
        """Build the CLI command for standalone (non-Axiom) execution per profile."""
        if profile.name in ("recon", "web-discovery"):
            scanner_bin = self._resolve_scanner_binary_for_profile(profile)
            return [scanner_bin, "-l", str(target_file), "-o", str(output_file_path)] + profile.extra_flags

        elif profile.name == "network-portscan":
            scanner_bin = self._resolve_scanner_binary_for_profile(profile)
            return [
                scanner_bin,
                "-iL",
                str(target_file),
                "-sV",
                "-T4",
                "--open",
                "-oX",
                str(output_file_path),
            ]

        elif profile.name == "fast-portscan":
            scanner_bin = self._resolve_scanner_binary_for_profile(profile)
            return [
                scanner_bin,
                "-iL",
                str(target_file),
                "--rate=1000",
                "-p",
                "1-65535",
                "-oJ",
                str(output_file_path),
            ]

        elif profile.name == "content-discovery":
            scanner_bin = self._resolve_scanner_binary_for_profile(profile)
            wordlist = self._resolve_ffuf_wordlist()
            url = f"{target_value.rstrip('/')}/FUZZ" if target_value.startswith(("http://", "https://")) else f"https://{target_value}/FUZZ"
            return [
                scanner_bin,
                "-w",
                wordlist,
                "-u",
                url,
                "-of",
                "json",
                "-o",
                str(output_file_path),
            ] + profile.extra_flags

        elif profile.name == "vuln-assessment":
            scanner_bin = self._resolve_scanner_binary_for_profile(profile)
            return [
                scanner_bin,
                "-l",
                str(target_file),
                "-jle",
                str(output_file_path),
            ] + profile.extra_flags

        elif profile.name == "sast-joern":
            scanner_bin = self._resolve_scanner_binary_for_profile(profile)
            return [
                scanner_bin,
                str(target_value),
                "--ignore-dir-names",
                "node_modules,venv,.venv,.git,dist,build,target,.next,vendor,Pods",
                "-J-Xmx4G",
            ] + profile.extra_flags

        elif profile.name == "sast-semgrep":
            scanner_bin = self._resolve_scanner_binary_for_profile(profile)
            return [
                scanner_bin,
                "scan",
                "--json",
                "--json-output",
                str(output_file_path),
                "--exclude",
                "node_modules",
                "--exclude",
                "venv",
                "--exclude",
                ".venv",
                "--exclude",
                "dist",
                "--exclude",
                "build",
                "--exclude",
                "target",
                "--exclude",
                ".git",
                str(target_value),
            ] + profile.extra_flags

        elif profile.name == "sast-trufflehog":
            scanner_bin = self._resolve_scanner_binary_for_profile(profile)
            return [
                scanner_bin,
                "filesystem",
                str(target_value),
                "--json",
                "--exclude-paths",
                "node_modules,venv,.venv,dist,build,target,.git",
            ] + profile.extra_flags

        else:
            raise FleetError(f"No standalone command mapping defined for profile '{profile.name}'.")

    @contextmanager
    def managed_fleet(self, fleet_name: str, count: int = 1) -> Generator[str, None, None]:
        """Context manager guaranteeing fleet teardown upon completion or error."""
        try:
            self.create_fleet(fleet_name, count)
            yield fleet_name
        finally:
            logger.info("Initiating mandatory teardown for fleet '%s'", fleet_name)
            self.destroy_fleet(fleet_name)
