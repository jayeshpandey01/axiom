"""Fleet Lifecycle Manager for orchestrating Axiom scanner VMs with guaranteed cleanup."""
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

    def _resolve_scanner_binary(self) -> str:
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

    def execute_scan(
        self,
        fleet_name: str,
        profile_name: str,
        target_value: str,
        output_file_path: Path,
    ) -> Path:
        """Execute a fixed scanner profile against an authorized target."""
        profile: ScannerProfile = get_profile(profile_name)

        # Write sanitized target to temporary file
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
            scanner_bin = self._resolve_scanner_binary()
            cmd = [
                scanner_bin,
                "-l",
                str(target_file),
                "-o",
                str(output_file_path),
            ] + profile.extra_flags

        try:
            if self.dry_run:
                import json
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
            result = self._run_command(cmd, timeout=profile.default_timeout_sec)
            if result.returncode != 0 and not self.dry_run:
                raise FleetError(f"Scan failed for target '{target_value}' (profile: {profile_name}): {result.stderr}")
            return output_file_path
        finally:
            if target_file.exists():
                target_file.unlink(missing_ok=True)

    @contextmanager
    def managed_fleet(self, fleet_name: str, count: int = 1) -> Generator[str, None, None]:
        """Context manager guaranteeing fleet teardown upon completion or error."""
        try:
            self.create_fleet(fleet_name, count)
            yield fleet_name
        finally:
            logger.info("Initiating mandatory teardown for fleet '%s'", fleet_name)
            self.destroy_fleet(fleet_name)
