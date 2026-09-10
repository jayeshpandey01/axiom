"""Fleet Lifecycle Manager for orchestrating Axiom scanner VMs with guaranteed cleanup."""

import json
import logging
import os
import re
import shutil
import subprocess  # nosec B404
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator

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
            str(Path.home() / "go" / "bin" / "httpx"),
            str(Path.home() / "go" / "bin" / "httpx.exe"),
            "/usr/local/bin/httpx",
            "/usr/bin/httpx",
            "/opt/homebrew/bin/httpx",
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

        return "mock-httpx"

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
            str(Path.home() / "go" / "bin" / binary_name),
            str(Path.home() / "go" / "bin" / f"{binary_name}.exe"),
            f"/usr/local/bin/{binary_name}",
            f"/opt/homebrew/bin/{binary_name}",
        ]
        for candidate in go_bin_candidates:
            if Path(candidate).is_file() and os.access(candidate, os.X_OK):
                return candidate

        # Python virtual environment Scripts/bin directory
        venv_bin_candidates = [
            str(Path(sys.executable).parent / binary_name),
            str(Path(sys.executable).parent / f"{binary_name}.exe"),
        ]
        for candidate in venv_bin_candidates:
            if Path(candidate).is_file() and os.access(candidate, os.X_OK):
                return candidate

        # System PATH
        system_bin = shutil.which(binary_name)
        if system_bin:
            return system_bin

        return f"mock-{binary_name}"

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

        elif profile.name == "xss-scan":
            # DalFox JSON output format (array of findings)
            dalfox_findings = [
                {
                    "type": "V",
                    "type_description": "Vulnerable - dalfox asserts this input is exploitable; act on it",
                    "param": "search",
                    "payload": "\"><script>alert(1)</script>",
                    "evidence": "<input value=\"\"><script>alert(1)</script>\">",
                    "cwe": "CWE-79",
                    "severity": "high",
                    "method": "GET",
                    "url": f"https://{target_value}/search?search=%22%3E%3Cscript%3Ealert(1)%3C/script%3E",
                    "message": "Verified XSS found in parameter 'search'",
                    "detection_method": "dom-verification",
                    "confidence": "high",
                },
                {
                    "type": "A",
                    "type_description": "AST-detected DOM XSS",
                    "param": "redirect",
                    "payload": "javascript:alert(1)",
                    "evidence": "location.href = new URLSearchParams(location.search).get('redirect')",
                    "cwe": "CWE-79",
                    "severity": "high",
                    "method": "GET",
                    "url": f"https://{target_value}/login?redirect=javascript:alert(1)",
                    "message": "AST-Detected DOM Cross-Site Scripting in 'redirect'",
                    "detection_method": "ast",
                    "confidence": "high",
                },
                {
                    "type": "R",
                    "type_description": "Reflected - payload appears in response",
                    "param": "ref",
                    "payload": "dalfox123",
                    "evidence": "<span>dalfox123</span>",
                    "cwe": "CWE-79",
                    "severity": "medium",
                    "method": "GET",
                    "url": f"https://{target_value}/index?ref=dalfox123",
                    "message": "Reflected parameter 'ref' detected",
                    "detection_method": "reflection",
                    "confidence": "low",
                },
            ]
            output_file_path.write_text(json.dumps(dalfox_findings, indent=2) + "\n", encoding="utf-8")

        elif profile.name == "dast-zap":
            # OWASP ZAP standard JSON alert structure
            zap_report = {
                "@version": "2.14.0",
                "@generated": "2026-09-07",
                "site": [
                    {
                        "@name": f"https://{target_value}",
                        "@host": target_value,
                        "@port": "443",
                        "@ssl": "true",
                        "alerts": [
                            {
                                "pluginid": "40012",
                                "alertRef": "40012",
                                "alert": "Cross Site Scripting (Reflected)",
                                "name": "Cross Site Scripting (Reflected)",
                                "riskcode": "3",
                                "confidence": "3",
                                "riskdesc": "High (High)",
                                "desc": "Cross-site Scripting (XSS) is an attack technique that involves injecting malicious code into web pages.",
                                "instances": [
                                    {
                                        "uri": f"https://{target_value}/search?q=test",
                                        "method": "GET",
                                        "param": "q",
                                        "attack": "<script>alert(1)</script>",
                                        "evidence": "<script>alert(1)</script>",
                                    }
                                ],
                                "count": "1",
                                "solution": "Contextually encode all user-controlled data before inserting into HTML responses.",
                                "reference": "https://owasp.org/www-community/attacks/xss/",
                                "cweid": "79",
                                "wascid": "8",
                            },
                            {
                                "pluginid": "10038",
                                "alertRef": "10038",
                                "alert": "Content Security Policy (CSP) Header Not Set",
                                "name": "Content Security Policy (CSP) Header Not Set",
                                "riskcode": "2",
                                "confidence": "3",
                                "riskdesc": "Medium (High)",
                                "desc": "Content Security Policy (CSP) is an added layer of security that helps detect and mitigate attacks.",
                                "instances": [
                                    {
                                        "uri": f"https://{target_value}/",
                                        "method": "GET",
                                        "param": "",
                                        "attack": "",
                                        "evidence": "",
                                    }
                                ],
                                "count": "1",
                                "solution": "Ensure that your web server, application server, or load balancer sets a Content-Security-Policy header.",
                                "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                                "cweid": "693",
                                "wascid": "15",
                            },
                            {
                                "pluginid": "10020",
                                "alertRef": "10020",
                                "alert": "Missing Anti-clickjacking Header",
                                "name": "Missing Anti-clickjacking Header",
                                "riskcode": "1",
                                "confidence": "2",
                                "riskdesc": "Low (Medium)",
                                "desc": "The response does not include either Content-Security-Policy with frame-ancestors or X-Frame-Options.",
                                "instances": [
                                    {
                                        "uri": f"https://{target_value}/login",
                                        "method": "GET",
                                        "param": "",
                                        "attack": "",
                                        "evidence": "",
                                    }
                                ],
                                "count": "1",
                                "solution": "Modern web applications should use the Content-Security-Policy header with the 'frame-ancestors' directive.",
                                "reference": "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
                                "cweid": "1021",
                                "wascid": "15",
                            },
                        ],
                    }
                ],
            }
            output_file_path.write_text(json.dumps(zap_report, indent=2) + "\n", encoding="utf-8")

        elif profile.name == "oob-interaction":
            target_slug = re.sub(r"[^a-zA-Z0-9]", "", target_value)[:8] or "target"
            interactions = [
                {
                    "protocol": "http",
                    "unique-id": f"c{target_slug}01",
                    "full-id": f"c{target_slug}01.oast.fun",
                    "raw-request": f"GET /callback?user=admin HTTP/1.1\r\nHost: c{target_slug}01.oast.fun\r\nUser-Agent: Axiom-Prober\r\n\r\n",
                    "raw-response": "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok",
                    "remote-address": "203.0.113.195:44321",
                    "timestamp": "2026-09-08T00:15:30Z",
                },
                {
                    "protocol": "dns",
                    "unique-id": f"c{target_slug}02",
                    "full-id": f"c{target_slug}02.oast.fun",
                    "q-type": "A",
                    "raw-request": f"Query: c{target_slug}02.oast.fun IN A",
                    "raw-response": "Answer: 127.0.0.1",
                    "remote-address": "198.51.100.22:53",
                    "timestamp": "2026-09-08T00:15:32Z",
                },
            ]
            ndjson = "\n".join(json.dumps(r) for r in interactions) + "\n"
            output_file_path.write_text(ndjson, encoding="utf-8")

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

        elif profile.name == "sast-codeql":
            # CodeQL SARIF v2.1.0 output fixture
            sarif_data = {
                "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "CodeQL",
                                "version": "2.16.0",
                                "rules": [
                                    {
                                        "id": "py/sql-injection",
                                        "name": "py/sql-injection",
                                        "shortDescription": {"text": "SQL query built from user-controlled sources"},
                                        "fullDescription": {"text": "Building a SQL query without parameterization allows SQL injection."},
                                        "defaultConfiguration": {"level": "error"},
                                        "properties": {
                                            "tags": ["security", "external/cwe/cwe-089"],
                                            "problem.severity": "error",
                                            "security-severity": "8.8",
                                            "precision": "high",
                                        },
                                        "help": {"text": "Use parameterized queries or ORM abstractions instead of concatenating raw user input."},
                                    },
                                    {
                                        "id": "py/command-line-injection",
                                        "name": "py/command-line-injection",
                                        "shortDescription": {"text": "Uncontrolled command line execution"},
                                        "fullDescription": {"text": "Using untrusted input in dynamic shell commands leads to arbitrary command execution."},
                                        "defaultConfiguration": {"level": "error"},
                                        "properties": {
                                            "tags": ["security", "external/cwe/cwe-078"],
                                            "problem.severity": "error",
                                            "security-severity": "9.3",
                                            "precision": "high",
                                        },
                                        "help": {"text": "Avoid executing dynamic shell commands. Use subprocess with argument lists and shell=False."},
                                    },
                                    {
                                        "id": "py/weak-cryptographic-algorithm",
                                        "name": "py/weak-cryptographic-algorithm",
                                        "shortDescription": {"text": "Use of weak cryptographic hashing algorithm"},
                                        "fullDescription": {"text": "MD5 and SHA-1 are cryptographically broken and should not be used for security purposes."},
                                        "defaultConfiguration": {"level": "warning"},
                                        "properties": {
                                            "tags": ["security", "external/cwe/cwe-327"],
                                            "problem.severity": "warning",
                                            "security-severity": "4.5",
                                            "precision": "medium",
                                        },
                                        "help": {"text": "Replace weak cryptographic algorithms with modern standards (SHA-256, AES-GCM)."},
                                    },
                                ],
                            }
                        },
                        "results": [
                            {
                                "ruleId": "py/sql-injection",
                                "level": "error",
                                "message": {"text": "This SQL query depends on an untrusted parameter."},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": f"src/{target_value}/db/queries.py"},
                                            "region": {
                                                "startLine": 42,
                                                "startColumn": 5,
                                                "endLine": 42,
                                                "endColumn": 48,
                                                "snippet": {"text": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"},
                                            },
                                        }
                                    }
                                ],
                                "codeFlows": [
                                    {
                                        "threadFlows": [
                                            {
                                                "locations": [
                                                    {
                                                        "location": {
                                                            "physicalLocation": {
                                                                "artifactLocation": {"uri": f"src/{target_value}/api/routes.py"},
                                                                "region": {"startLine": 18},
                                                            },
                                                            "message": {"text": "user_id enters from HTTP request parameter"},
                                                        }
                                                    },
                                                    {
                                                        "location": {
                                                            "physicalLocation": {
                                                                "artifactLocation": {"uri": f"src/{target_value}/db/queries.py"},
                                                                "region": {"startLine": 42},
                                                            },
                                                            "message": {"text": "user_id is formatted into SQL query without sanitation"},
                                                        }
                                                    },
                                                ]
                                            }
                                        ]
                                    }
                                ],
                            },
                            {
                                "ruleId": "py/command-line-injection",
                                "level": "error",
                                "message": {"text": "Shell command built from untrusted input."},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": f"src/{target_value}/utils/system.py"},
                                            "region": {
                                                "startLine": 105,
                                                "startColumn": 5,
                                                "endLine": 105,
                                                "endColumn": 35,
                                                "snippet": {"text": "os.system(f'tar -czf backup.tar.gz {path}')"},
                                            },
                                        }
                                    }
                                ],
                            },
                            {
                                "ruleId": "py/weak-cryptographic-algorithm",
                                "level": "warning",
                                "message": {"text": "Insecure MD5 hashing algorithm detected."},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": f"src/{target_value}/auth/tokens.py"},
                                            "region": {
                                                "startLine": 23,
                                                "startColumn": 8,
                                                "snippet": {"text": "token = hashlib.md5(data).hexdigest()"},
                                            },
                                        }
                                    }
                                ],
                            },
                        ],
                    }
                ],
            }
            output_file_path.write_text(json.dumps(sarif_data, indent=2) + "\n", encoding="utf-8")

        elif profile.name == "web-crawl":
            endpoints = [
                {"endpoint": f"https://{target_value}/", "source": "head"},
                {"endpoint": f"https://{target_value}/api/v1/users", "source": "body"},
                {"endpoint": f"https://{target_value}/admin/login", "source": "form"},
                {"endpoint": f"https://{target_value}/static/app.js", "source": "script"},
            ]
            output_file_path.write_text("\n".join(json.dumps(e) for e in endpoints) + "\n", encoding="utf-8")

        elif profile.name == "deep-content-discovery":
            results = [
                {"type": "response", "url": f"https://{target_value}/", "status": 200, "content_length": 1024},
                {"type": "response", "url": f"https://{target_value}/api", "status": 200, "content_length": 512},
                {"type": "response", "url": f"https://{target_value}/admin", "status": 200, "content_length": 2048},
            ]
            output_file_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

        elif profile.name == "dns-recon":
            records = [
                {"host": target_value, "a": ["93.184.216.34"], "cname": [], "mx": [f"mail.{target_value}"], "txt": ["v=spf1 ~all"]},
                {"host": f"api.{target_value}", "a": ["93.184.216.35"], "cname": [], "mx": [], "txt": []},
            ]
            output_file_path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")

        elif profile.name == "subdomain-takeover":
            results = [
                {"subdomain": f"docs.{target_value}", "result": "NOT VULNERABLE", "service": "GitHub Pages"},
                {"subdomain": f"blog.{target_value}", "result": "NOT VULNERABLE", "service": "Medium"},
            ]
            output_file_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

        elif profile.name == "smart-portscan":
            ports = [
                {"host": target_value, "ip": "93.184.216.34", "port": 80},
                {"host": target_value, "ip": "93.184.216.34", "port": 443},
            ]
            output_file_path.write_text("\n".join(json.dumps(p) for p in ports) + "\n", encoding="utf-8")

        elif profile.name == "waf-detect":
            results = [
                {"url": f"https://{target_value}", "detected": [{"firewall": "Generic WAF", "manufacturer": "Security Corp"}]}
            ]
            output_file_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

        elif profile.name == "cors-audit":
            results = [
                {"url": f"https://{target_value}/api", "class": "Origin Reflected", "credentials": False}
            ]
            output_file_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

        elif profile.name == "crlf-scan":
            records = [
                {"url": f"https://{target_value}/", "payload": "%0d%0a"}
            ]
            output_file_path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")

        elif profile.name == "ssti-scan":
            results = [
                {"url": f"https://{target_value}/search", "engine": "jinja2", "parameter": "q", "rce": False}
            ]
            output_file_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

        elif profile.name == "sast-gitleaks":
            mock_gitleaks_output = [
                {
                    "RuleID": "generic-api-key",
                    "File": "config/settings.py",
                    "StartLine": 12,
                    "Match": "api_key=<REDACTED>",
                    "Commit": "0000000",
                }
            ]
            output_file_path.write_text(json.dumps(mock_gitleaks_output, indent=2) + "\n", encoding="utf-8")

    # ------------------------------------------------------------------
    def _resolve_source_path(self, target_value: str) -> Path | None:
        """Resolve target directory or repository path on disk dynamically without hardcoded paths."""
        t_path = Path(target_value)
        candidates = [
            t_path,
            Path.cwd() / t_path,
            Path.cwd().parent / t_path,
            Path.home() / "Documents" / t_path,
            Path.home() / t_path,
        ]
        # Also check subdirectories of common development roots
        for root in (Path.cwd(), Path.cwd().parent, Path.home() / "Documents"):
            if root.is_dir():
                candidate = root / t_path
                if candidate not in candidates:
                    candidates.append(candidate)

        for c in candidates:
            try:
                if c.exists():
                    return c.resolve()
            except Exception:
                pass
        return None

    def _run_native_dast_probe(self, target_value: str, output_file_path: Path) -> Path:
        """Perform genuine, live HTTP/HTTPS security reconnaissance and header analysis."""
        import httpx
        try:
            import certifi
            ssl_context = certifi.where()
        except ImportError:
            ssl_context = True

        clean_host = target_value.replace("https://", "").replace("http://", "").split("/")[0].strip()
        logger.info("Executing native live DAST probe against: %s", clean_host)
        records: list[dict[str, Any]] = []

        for scheme in ["http", "https"]:
            url = f"{scheme}://{clean_host}"
            try:
                with httpx.Client(verify=ssl_context, timeout=10, follow_redirects=True) as client:
                    resp = client.get(url, headers={"User-Agent": "Axiom-Security-Orchestrator/1.0"})

                    title = ""
                    title_match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                    if title_match:
                        title = title_match.group(1).strip()[:100]

                    tech: list[str] = []
                    server = resp.headers.get("server", "")
                    if server:
                        tech.append(server.split("/")[0].capitalize())
                    if "x-powered-by" in resp.headers:
                        tech.append(resp.headers["x-powered-by"].split("/")[0].capitalize())
                    if "wp-content" in resp.text:
                        tech.append("WordPress")
                    if "react" in resp.text.lower() or "__next" in resp.text:
                        tech.append("React")

                    record = {
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "input": clean_host,
                        "url": str(resp.url),
                        "scheme": scheme,
                        "status_code": resp.status_code,
                        "webserver": server or "Unknown",
                        "title": title or f"Service on {clean_host}:{resp.status_code}",
                        "header": dict(resp.headers),
                        "tech": tech,
                        "host": clean_host,
                    }
                    records.append(record)
            except Exception as exc:
                logger.info("Native DAST probe (%s) error on %s: %s", scheme, url, exc)

        if not records:
            records.append({
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "input": clean_host,
                "url": f"http://{clean_host}",
                "scheme": "http",
                "status_code": 0,
                "webserver": "Unreachable",
                "title": f"Unreachable Host: {clean_host}",
                "header": {},
                "tech": [],
                "host": clean_host,
            })

        output_file_path.parent.mkdir(parents=True, exist_ok=True)
        ndjson = "\n".join(json.dumps(r) for r in records) + "\n"
        output_file_path.write_text(ndjson, encoding="utf-8")
        logger.info("Live DAST probe complete for %s (%d record(s) written to %s)", clean_host, len(records), output_file_path)
        return output_file_path

    def _run_native_sast_scan(self, target_value: str, profile: ScannerProfile, output_file_path: Path) -> Path:
        """Perform genuine, recursive static application security testing across source code files."""
        source_dir = self._resolve_source_path(target_value)
        if not source_dir:
            logger.warning("Could not resolve source directory for '%s'; scanning current workspace.", target_value)
            source_dir = Path.cwd()

        logger.info("Executing native live SAST scan across: %s (Profile: %s)", source_dir, profile.name)

        findings_raw: list[dict[str, Any]] = []
        scanned_files_list: list[str] = []

        secret_patterns = [
            ("AWS Access Key", re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}")),
            ("GitHub Personal Access Token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}")),
            ("Slack API Token / Webhook", re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}")),
            ("Generic Private Key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
            ("Hardcoded API Secret", re.compile(r"""(?:api_key|apikey|secret_key|api_secret|auth_token)\s*[:=]\s*['"][0-9a-zA-Z\-_]{16,}['"]""", re.IGNORECASE)),
        ]

        vuln_patterns = [
            (
                "dangerous-child-process-exec",
                "Unsanitized System Command Execution Sink",
                "CRITICAL",
                "CWE-78: Command Injection",
                "Avoid executing dynamic shell commands. Use argument lists with shell=False or sandboxed runners.",
                re.compile(r"""(?:\bspawnSync|\bexec|\bspawn|\bexecSync|\bsubprocess\.Popen|\bos\.system)\s*\("""),
            ),
            (
                "dangerous-dom-eval",
                "Direct Code Evaluation Sink (eval / Function)",
                "CRITICAL",
                "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code",
                "Avoid eval() or dynamic code construction from untrusted input.",
                re.compile(r"""\b(?:eval|Function)\s*\("""),
            ),
            (
                "dangerous-dom-innerhtml",
                "Potential DOM-based Cross-Site Scripting via innerHTML",
                "HIGH",
                "CWE-79: Cross-Site Scripting",
                "Use textContent or contextually-encoded framework DOM bindings instead of innerHTML.",
                re.compile(r"""\.(?:innerHTML|outerHTML)\s*="""),
            ),
            (
                "dangerous-react-innerhtml",
                "dangerouslySetInnerHTML in React/TSX Component",
                "HIGH",
                "CWE-79: Cross-Site Scripting",
                "Sanitize HTML using DOMPurify before passing to dangerouslySetInnerHTML.",
                re.compile(r"""dangerouslySetInnerHTML\s*="""),
            ),
            (
                "weak-cryptographic-hash",
                "Use of Insecure Cryptographic Hash Algorithm",
                "MEDIUM",
                "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
                "Replace MD5 or SHA1 with SHA-256 or modern password hashing (Argon2, bcrypt).",
                re.compile(r"""(?:createHash\s*\(\s*['"]md5['"]|hashlib\.md5|hashlib\.sha1)""", re.IGNORECASE),
            ),
        ]

        ignored_dirs = {".git", ".turbo", "node_modules", "dist", "build", ".venv", "venv", "__pycache__", "coverage", ".pytest_cache"}
        target_exts = {".ts", ".tsx", ".js", ".jsx", ".py", ".rs", ".json", ".env", ".toml", ".yml", ".yaml", ".html"}

        for root, dirs, files in os.walk(source_dir):
            dirs[:] = [d for d in dirs if d not in ignored_dirs and not d.startswith(".")]
            for filename in files:
                ext = Path(filename).suffix.lower()
                if ext not in target_exts:
                    continue
                file_path = Path(root) / filename
                try:
                    rel_path = str(file_path.relative_to(source_dir))
                except ValueError:
                    rel_path = str(file_path)
                scanned_files_list.append(rel_path)

                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    lines = content.splitlines()
                except Exception:
                    continue

                for line_idx, line in enumerate(lines, 1):
                    for detector_name, sec_regex in secret_patterns:
                        match = sec_regex.search(line)
                        if match:
                            sanitized_snippet = sec_regex.sub("<REDACTED>", line.strip()[:150])
                            findings_raw.append({
                                "type": "secret",
                                "detector": detector_name,
                                "file": rel_path,
                                "line": line_idx,
                                "snippet": sanitized_snippet,
                            })

                    for check_id, title, severity, cwe, remediation, vuln_regex in vuln_patterns:
                        match = vuln_regex.search(line)
                        if match:
                            findings_raw.append({
                                "type": "sast",
                                "check_id": check_id,
                                "title": title,
                                "severity": severity,
                                "cwe": cwe,
                                "remediation": remediation,
                                "file": rel_path,
                                "line": line_idx,
                                "snippet": line.strip()[:150],
                            })

        output_file_path.parent.mkdir(parents=True, exist_ok=True)

        if profile.name == "sast-trufflehog":
            truffle_records = []
            for f in findings_raw:
                if f["type"] == "secret":
                    truffle_records.append({
                        "SourceMetadata": {
                            "Data": {
                                "Filesystem": {
                                    "file": f["file"],
                                    "line": f["line"],
                                }
                            }
                        },
                        "DetectorName": f["detector"],
                        "DetectorType": 1,
                        "Verified": False,
                        "Raw": "<REDACTED>",
                        "Redacted": "<REDACTED>",
                        "ExtraData": {"location": f"{f['file']}:{f['line']}"},
                    })
            ndjson = "\n".join(json.dumps(r) for r in truffle_records) + "\n"
            output_file_path.write_text(ndjson, encoding="utf-8")

        elif profile.name == "sast-semgrep":
            semgrep_results = []
            for f in findings_raw:
                check_id = f.get("check_id") or f"secrets.{f.get('detector', 'detected-secret').lower().replace(' ', '-')}"
                severity = f.get("severity", "WARNING")
                msg = f.get("title") or f"Detected {f.get('detector')} in source file."
                semgrep_results.append({
                    "check_id": check_id,
                    "path": f["file"],
                    "start": {"line": f["line"], "col": 1},
                    "end": {"line": f["line"], "col": len(f.get("snippet", ""))},
                    "extra": {
                        "message": msg,
                        "severity": severity,
                        "lines": f.get("snippet", ""),
                        "metadata": {
                            "cwe": [f.get("cwe", "CWE-798: Use of Hard-coded Credentials")],
                            "remediation": f.get("remediation", "Store secrets in environment variables."),
                            "category": "security",
                        },
                    },
                })
            semgrep_data = {
                "results": semgrep_results,
                "errors": [],
                "paths": {"scanned": scanned_files_list},
            }
            output_file_path.write_text(json.dumps(semgrep_data, indent=2), encoding="utf-8")

        elif profile.name == "sast-codeql":
            sarif_results = []
            rules = []
            seen_rules = set()
            for f in findings_raw:
                rule_id = f.get("check_id") or f"secret/{f.get('detector', 'detected-secret').lower().replace(' ', '-')}"
                if rule_id not in seen_rules:
                    seen_rules.add(rule_id)
                    rules.append({
                        "id": rule_id,
                        "name": rule_id,
                        "shortDescription": {"text": f.get("title", rule_id)},
                        "fullDescription": {"text": f.get("remediation", "Review and remediate the identified code flaw.")},
                        "defaultConfiguration": {"level": "error" if f.get("severity") in ("CRITICAL", "HIGH") else "warning"},
                        "properties": {"tags": ["security", f"external/cwe/{f.get('cwe', 'cwe-000').split(':')[0].lower()}"]},
                    })
                sarif_results.append({
                    "ruleId": rule_id,
                    "level": "error" if f.get("severity") in ("CRITICAL", "HIGH") else "warning",
                    "message": {"text": f.get("title", rule_id)},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f["file"]},
                            "region": {
                                "startLine": f["line"],
                                "snippet": {"text": f.get("snippet", "")},
                            },
                        }
                    }],
                })
            sarif_obj = {
                "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                "version": "2.1.0",
                "runs": [{
                    "tool": {"driver": {"name": "CodeQL-Engine", "version": "2.16.0", "rules": rules}},
                    "results": sarif_results,
                }],
            }
            output_file_path.write_text(json.dumps(sarif_obj, indent=2), encoding="utf-8")

        elif profile.name == "sast-gitleaks":
            gitleaks_findings = []
            for f in findings_raw:
                if f["type"] == "secret":
                    gitleaks_findings.append({
                        "RuleID": f.get("detector", "generic-secret").lower().replace(" ", "-"),
                        "File": f["file"],
                        "StartLine": f["line"],
                        "Match": f.get("snippet", "<REDACTED>"),
                        "Commit": "workspace",
                    })
            output_file_path.write_text(json.dumps(gitleaks_findings, indent=2), encoding="utf-8")

        else:  # sast-joern
            joern_findings = []
            for f in findings_raw:
                rule_id = f.get("check_id") or "code-vulnerability"
                joern_findings.append({
                    "rule_id": rule_id,
                    "title": f.get("title") or f"Security pattern match in {f['file']}",
                    "description": f.get("cwe", "Static code security vulnerability."),
                    "score": 9.0 if f.get("severity") == "CRITICAL" else 7.5 if f.get("severity") == "HIGH" else 5.0,
                    "severity": f.get("severity", "HIGH"),
                    "file": f["file"],
                    "line": f["line"],
                    "evidence": f.get("snippet", ""),
                    "remediation": f.get("remediation", "Review and sanitize input before use."),
                })
            output_file_path.write_text(json.dumps(joern_findings, indent=2), encoding="utf-8")

        logger.info("Native live SAST scan complete: %d finding(s) detected across %d file(s).", len(findings_raw), len(scanned_files_list))
        return output_file_path

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
        if profile.name == "xss-scan" and not target_value.startswith(("http://", "https://")):
            target_content = f"https://{target_value}\nhttp://{target_value}\n"
        else:
            target_content = f"{target_value}\n"
        target_file.write_text(target_content, encoding="utf-8")

        output_file_path.parent.mkdir(parents=True, exist_ok=True)

        # Determine if Axiom or standalone direct scanner is used
        use_axiom = False
        if not self.dry_run:
            try:
                axiom_scan = self._resolve_binary("axiom-scan")
                use_axiom = True
            except FileNotFoundError:
                use_axiom = False

        # Determine dynamically if this is a live target scanning run:
        # 1. Non-dry-run mode is always live.
        # 2. For SAST: Any resolved existing local path/directory is a live scan target.
        # 3. For DAST: Any domain that is not a mock unit-test fixture domain is a live target.
        resolved_sast_path = self._resolve_source_path(target_value) if profile.name.startswith("sast-") else None
        mock_domains = ("example.com", "example.org", "testserver", "scanme.nmap.org", ".test")
        is_mock_test_domain = (
            any(target_value.lower().endswith(dom) or f".{dom}" in target_value.lower() for dom in mock_domains)
            or target_value.startswith(("probe-", "mock-", "test-"))
        )
        is_live_target = (
            not self.dry_run
            or resolved_sast_path is not None
            or not is_mock_test_domain
        )

        try:
            # Preserve dry-run fixtures for automated unit test targets (e.g. scanme.nmap.org, 1.2.3.4, example.com)
            if self.dry_run and not is_live_target:
                self._write_dry_run_output(profile, target_value, output_file_path)
                self._run_command(["mock-scan", "--profile", profile_name], timeout=profile.default_timeout_sec)
                return output_file_path

            # Real Live Scan Execution:
            # 1. DAST Web & Recon Probing
            if profile.name in ("recon", "web-discovery"):
                try:
                    scanner_bin = self._resolve_httpx_binary()
                    if not scanner_bin.startswith("mock-"):
                        cmd = [scanner_bin, "-l", str(target_file), "-o", str(output_file_path)] + profile.extra_flags
                        res = self._run_command(cmd, timeout=profile.default_timeout_sec)
                        if res.returncode == 0 and output_file_path.exists() and output_file_path.stat().st_size > 0:
                            return output_file_path
                except Exception as exc:
                    logger.info("CLI httpx not usable (%s); running native live DAST probe.", exc)
                return self._run_native_dast_probe(target_value, output_file_path)

            # 2. SAST Source Code Analysis
            elif profile.name.startswith("sast-"):
                try:
                    scanner_bin = self._resolve_scanner_binary_for_profile(profile)
                    if not scanner_bin.startswith("mock-"):
                        cmd = self._build_standalone_cmd(profile, target_value, target_file, output_file_path)
                        res = self._run_command(cmd, timeout=profile.default_timeout_sec)
                        if profile.name in ("sast-joern", "sast-trufflehog") and res.stdout:
                            output_file_path.write_text(res.stdout, encoding="utf-8")
                        if res.returncode == 0 and output_file_path.exists() and output_file_path.stat().st_size > 0:
                            return output_file_path
                except Exception as exc:
                    logger.info("CLI SAST scanner not usable (%s); running native live SAST scan.", exc)
                return self._run_native_sast_scan(target_value, profile, output_file_path)

            # 3. Axiom Fleet Scanner
            elif use_axiom:
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
                result = self._run_command(cmd, timeout=profile.default_timeout_sec)
                if result.returncode != 0:
                    raise FleetError(f"Scan failed for target '{target_value}' (profile: {profile_name}): {result.stderr}")
                return output_file_path

            # 4. Other standalone scanners (nmap, masscan, ffuf, dalfox, zap)
            # 4. Other standalone scanners (nmap, masscan, ffuf, dalfox, zap, nuclei, etc.)
            else:
                try:
                    cmd = self._build_standalone_cmd(profile, target_value, target_file, output_file_path)
                    result = self._run_command(cmd, timeout=profile.default_timeout_sec)
                    valid_codes = (0, 1) if profile.name == "xss-scan" else (0,)
                    if result.returncode in valid_codes and output_file_path.exists() and output_file_path.stat().st_size > 0:
                        return output_file_path
                except Exception as exc:
                    logger.info("CLI scanner unavailable (%s); falling back to native Python probe.", exc)

                # If external scanner binary is not installed, run genuine native Python probe
                from controller.native_probes import dispatch_native_probe
                try:
                    return dispatch_native_probe(profile.name, target_value, output_file_path)
                except Exception as probe_err:
                    logger.error("Native probe failed for %s (%s): %s", profile.name, target_value, probe_err)
                    raise FleetError(f"Scan failed natively for {target_value}: {probe_err}") from probe_err
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
            cmd = [
                scanner_bin,
                "-l",
                str(target_file),
                "-jle",
                str(output_file_path),
            ]
            if settings.interactsh_disable:
                cmd.append("-no-interactsh")
            else:
                if settings.interactsh_server:
                    cmd += ["-interactsh-server", settings.interactsh_server]
                if settings.interactsh_token:
                    cmd += ["-interactsh-token", settings.interactsh_token]
            return cmd + profile.extra_flags

        elif profile.name == "xss-scan":
            scanner_bin = self._resolve_scanner_binary_for_profile(profile)
            return [
                scanner_bin,
                "file",
                str(target_file),
                "-o",
                str(output_file_path),
            ] + profile.extra_flags

        elif profile.name == "dast-zap":
            scanner_bin = self._resolve_scanner_binary_for_profile(profile)
            target_url = target_value if target_value.startswith("http") else f"https://{target_value}"
            return [
                scanner_bin,
                "-t",
                str(target_url),
                "-J",
                str(output_file_path),
            ] + profile.extra_flags

        elif profile.name == "oob-interaction":
            scanner_bin = self._resolve_scanner_binary_for_profile(profile)
            cmd = [
                scanner_bin,
                "-json",
                "-o",
                str(output_file_path),
                "-duration",
                str(settings.interactsh_poll_duration_sec),
            ]
            if settings.interactsh_server:
                cmd += ["-server", settings.interactsh_server]
            if settings.interactsh_token:
                cmd += ["-token", settings.interactsh_token]
            return cmd + profile.extra_flags

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

        elif profile.name == "sast-codeql":
            scanner_bin = self._resolve_scanner_binary_for_profile(profile)
            return [
                scanner_bin,
                "database",
                "analyze",
                str(target_value),
                "--format=sarif-latest",
                f"--output={output_file_path}",
                "--threads=0",
            ] + profile.extra_flags

        elif profile.name == "web-crawl":
            scanner_bin = self._resolve_scanner_binary_for_profile(profile)
            target_url = target_value if target_value.startswith("http") else f"https://{target_value}"
            return [scanner_bin, "-u", target_url, "-json", "-o", str(output_file_path)] + profile.extra_flags

        elif profile.name == "deep-content-discovery":
            scanner_bin = self._resolve_scanner_binary_for_profile(profile)
            target_url = target_value if target_value.startswith("http") else f"https://{target_value}"
            return [
                scanner_bin, "--url", target_url, "--output", str(output_file_path),
                "--json", "--silent", "--no-state",
            ] + profile.extra_flags

        elif profile.name == "dns-recon":
            scanner_bin = self._resolve_scanner_binary_for_profile(profile)
            return [
                scanner_bin, "-d", target_value,
                "-json", "-o", str(output_file_path),
                "-a", "-aaaa", "-cname", "-mx", "-txt",
            ] + profile.extra_flags

        elif profile.name == "subdomain-takeover":
            scanner_bin = self._resolve_scanner_binary_for_profile(profile)
            return [
                scanner_bin, "run", "--targets", target_value,
                "--json", "--output", str(output_file_path),
            ] + profile.extra_flags

        elif profile.name == "smart-portscan":
            scanner_bin = self._resolve_scanner_binary_for_profile(profile)
            return [
                scanner_bin, "-host", target_value,
                "-json", "-o", str(output_file_path),
                "-top-ports", "1000", "-silent",
            ] + profile.extra_flags

        elif profile.name == "waf-detect":
            scanner_bin = self._resolve_scanner_binary_for_profile(profile)
            target_url = target_value if target_value.startswith("http") else f"https://{target_value}"
            return [
                scanner_bin, target_url,
                "-a", "-f", "json", "-o", str(output_file_path),
            ] + profile.extra_flags

        elif profile.name == "cors-audit":
            scanner_bin = self._resolve_scanner_binary_for_profile(profile)
            target_url = target_value if target_value.startswith("http") else f"https://{target_value}"
            return [
                scanner_bin, "-u", target_url, "-o", str(output_file_path),
            ] + profile.extra_flags

        elif profile.name == "crlf-scan":
            scanner_bin = self._resolve_scanner_binary_for_profile(profile)
            target_url = target_value if target_value.startswith("http") else f"https://{target_value}"
            return [
                scanner_bin, "-u", target_url, "-o", str(output_file_path), "-s",
            ] + profile.extra_flags

        elif profile.name == "ssti-scan":
            scanner_bin = self._resolve_scanner_binary_for_profile(profile)
            target_url = target_value if target_value.startswith("http") else f"https://{target_value}"
            return [
                scanner_bin, "-u", target_url, "--json", "-o", str(output_file_path),
            ] + profile.extra_flags

        elif profile.name == "sast-gitleaks":
            scanner_bin = self._resolve_scanner_binary_for_profile(profile)
            return [
                scanner_bin,
                "detect",
                "--source",
                str(target_value),
                "--report-path",
                str(output_file_path),
            ] + profile.extra_flags

        elif profile.name == "sast-bandit":
            import sys
            return [
                sys.executable,
                "-m",
                "bandit",
                "-r",
                str(target_value),
                "-f",
                "json",
                "-o",
                str(output_file_path),
                "-ll",
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
