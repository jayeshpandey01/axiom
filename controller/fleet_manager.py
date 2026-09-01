"""Fleet Lifecycle Manager for orchestrating Axiom scanner VMs with guaranteed cleanup."""
import json
import logging
import os
import shutil
import subprocess
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
            f"FFUF wordlist not found at '{wl}'. "
            "Set CONTROLLER_FFUF_WORDLIST to a valid path, or install SecLists to ~/.axiom/wordlists/."
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
            result = subprocess.run(
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
                json.dumps({
                    "host": target_value,
                    "status_code": 200,
                    "webserver": "nginx/1.18.0 (Ubuntu)",
                    "title": "Authorized Testing Target",
                    "technologies": ["Nginx", "Ubuntu", "OpenSSL"],
                }) + "\n",
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
                '<ports>'
                '<port protocol="tcp" portid="80">'
                '<state state="open" reason="syn-ack"/>'
                '<service name="http" product="nginx" version="1.18.0"/>'
                '</port>'
                '<port protocol="tcp" portid="22">'
                '<state state="open" reason="syn-ack"/>'
                '<service name="ssh" product="OpenSSH" version="8.9"/>'
                '</port>'
                '</ports></host></nmaprun>\n'
            )
            output_file_path.write_text(xml, encoding="utf-8")
        elif profile.name == "fast-portscan":
            # Masscan JSON output format
            output_file_path.write_text(
                json.dumps([
                    {"ip": target_value, "timestamp": str(int(time.time())), "ports": [{"port": 80, "proto": "tcp", "status": "open", "ttl": 64}]},
                    {"ip": target_value, "timestamp": str(int(time.time())), "ports": [{"port": 443, "proto": "tcp", "status": "open", "ttl": 64}]},
                ]) + "\n",
                encoding="utf-8",
            )
        elif profile.name == "content-discovery":
            # FFUF JSON output format
            output_file_path.write_text(
                json.dumps({
                    "results": [
                        {"url": f"https://{target_value}/admin", "status": 301, "length": 0, "words": 0, "lines": 0, "duration": 12},
                        {"url": f"https://{target_value}/api", "status": 200, "length": 512, "words": 8, "lines": 1, "duration": 18},
                        {"url": f"https://{target_value}/login", "status": 200, "length": 2048, "words": 40, "lines": 60, "duration": 25},
                    ]
                }) + "\n",
                encoding="utf-8",
            )
        elif profile.name == "vuln-assessment":
            # Nuclei JSONL output (one JSON object per line)
            findings = [
                {"template-id": "http-missing-security-headers", "info": {"name": "HTTP Missing Security Headers", "severity": "info"}, "host": f"https://{target_value}", "matched-at": f"https://{target_value}", "extracted-results": []},
                {"template-id": "cve-2021-44228", "info": {"name": "Log4Shell RCE", "severity": "critical"}, "host": f"https://{target_value}", "matched-at": f"https://{target_value}/api/v1/login", "extracted-results": []},
            ]
            output_file_path.write_text("\n".join(json.dumps(f) for f in findings) + "\n", encoding="utf-8")

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
                "-iL", str(target_file),
                "-sV", "-T4",
                "--open",
                "-oX", str(output_file_path),
            ]

        elif profile.name == "fast-portscan":
            scanner_bin = self._resolve_scanner_binary_for_profile(profile)
            return [
                scanner_bin,
                "-iL", str(target_file),
                "--rate=1000",
                "-p", "1-65535",
                "-oJ", str(output_file_path),
            ]

        elif profile.name == "content-discovery":
            scanner_bin = self._resolve_scanner_binary_for_profile(profile)
            wordlist = self._resolve_ffuf_wordlist()
            return [
                scanner_bin,
                "-w", wordlist,
                "-u", f"https://{target_value}/FUZZ",
                "-of", "json",
                "-o", str(output_file_path),
            ] + profile.extra_flags

        elif profile.name == "vuln-assessment":
            scanner_bin = self._resolve_scanner_binary_for_profile(profile)
            return [
                scanner_bin,
                "-l", str(target_file),
                "-json-export", str(output_file_path),
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




