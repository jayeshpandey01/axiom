"""Production Controller Agent Daemon.

Pulls signed jobs from the API via outbound HTTPS, executes fixed scanner
profiles via FleetManager, normalizes findings, and reports completion/failure.
"""
import hashlib
import hmac
import json
import logging
import secrets
import time
from pathlib import Path
from typing import Any

import httpx

from controller.analyzer import VulnerabilityAnalyzer
from controller.config import settings
from controller.fleet_manager import FleetManager

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("controller.agent")


def generate_signed_headers(method: str, path: str, body: bytes = b"", shared_secret: str | None = None) -> dict[str, str]:
    """Generate replay-protected HMAC-SHA256 headers for outbound API requests."""
    secret = (shared_secret or settings.shared_secret).encode()
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    body_hash = hashlib.sha256(body).hexdigest()
    message = f"{method}\n{path}\n{timestamp}\n{nonce}\n{body_hash}".encode()
    signature = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return {
        "X-Controller-Timestamp": timestamp,
        "X-Controller-Nonce": nonce,
        "X-Controller-Signature": signature,
    }


def parse_httpx_output(output_file: Path) -> dict[str, Any]:
    """Parse JSON output from httpx and run security vulnerability analysis."""
    default_empty = {
        "live_hosts_count": 0,
        "risk_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
        "findings": [],
        "status_codes": {},
        "web_servers": [],
        "titles": [],
        "technologies": [],
    }
    if not output_file.exists():
        return default_empty

    content = output_file.read_text(encoding="utf-8").strip()
    if not content:
        return default_empty

    records = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            records.append({"raw": line})

    analyzer = VulnerabilityAnalyzer()
    return analyzer.analyze(records)


class ControllerAgent:
    """Outbound polling agent managing the full scan execution cycle."""

    def __init__(self, api_base_url: str | None = None, manager: FleetManager | None = None):
        self.api_base_url = (api_base_url or settings.api_endpoint or "http://localhost:8000").rstrip("/")
        self.manager = manager or FleetManager()

    def _request(self, method: str, path: str, json_data: dict | None = None) -> httpx.Response:
        url = f"{self.api_base_url}{path}"
        body = json.dumps(json_data).encode() if json_data is not None else b""
        headers = generate_signed_headers(method, path, body)
        headers["Content-Type"] = "application/json"
        with httpx.Client(timeout=30) as client:
            response = client.request(method, url, headers=headers, content=body)
            return response

    def claim_job(self) -> dict | None:
        """Poll the API for the next available queued scan job."""
        path = "/v1/internal/controller/jobs/claim"
        response = self._request("POST", path)
        if response.status_code == 200:
            return response.json()
        if response.status_code == 204 or response.status_code == 404:
            return None
        logger.warning("Unexpected status claiming job: %d %s", response.status_code, response.text)
        return None

    def check_job_status(self, job_id: str) -> str | None:
        """Check if job is still active or has been cancelled."""
        path = f"/v1/internal/controller/jobs/{job_id}/status"
        response = self._request("GET", path)
        if response.status_code == 200:
            return response.json().get("status")
        return None

    def complete_job(self, job_id: str, summary: dict) -> bool:
        """Report successful scan completion with findings summary."""
        path = f"/v1/internal/controller/jobs/{job_id}/complete"
        response = self._request("POST", path, json_data={"summary": summary})
        if response.status_code == 200:
            logger.info("Job %s marked as completed.", job_id)
            return True
        logger.error("Failed to complete job %s: %d %s", job_id, response.status_code, response.text)
        return False

    def fail_job(self, job_id: str, reason: str) -> bool:
        """Report scan failure with diagnostic reason."""
        path = f"/v1/internal/controller/jobs/{job_id}/fail"
        response = self._request("POST", path, json_data={"reason": reason[:500]})
        if response.status_code == 200:
            logger.info("Job %s marked as failed: %s", job_id, reason)
            return True
        logger.error("Failed to report failure for job %s: %d %s", job_id, response.status_code, response.text)
        return False

    def process_job(self, job: dict) -> bool:
        """Execute a claimed scan job with guaranteed lifecycle management."""
        job_id = job["id"]
        target = job["target"]
        profile = job["profile"]
        fleet_name = f"fleet-{job_id[:8]}"
        output_file = Path(settings.work_dir) / f"{job_id}_output.json"

        logger.info("Processing scan job %s (Target: %s, Profile: %s)", job_id, target, profile)

        try:
            # Check if cancelled before provisioning
            current_status = self.check_job_status(job_id)
            if current_status == "cancelled":
                logger.info("Job %s was cancelled before fleet creation. Skipping.", job_id)
                return True

            with self.manager.managed_fleet(fleet_name, count=1):
                # Execute fixed profile scan
                self.manager.execute_scan(
                    fleet_name=fleet_name,
                    profile_name=profile,
                    target_value=target,
                    output_file_path=output_file,
                )

                # Check if cancelled mid-scan
                if self.check_job_status(job_id) == "cancelled":
                    logger.info("Job %s was cancelled during scan. Teardown complete.", job_id)
                    return True

                # Parse output into normalized findings
                summary = parse_httpx_output(output_file)
                self.complete_job(job_id, summary)
                return True

        except Exception as exc:
            logger.error("Error executing job %s: %s", job_id, exc)
            self.fail_job(job_id, reason=str(exc))
            return False
        finally:
            if output_file.exists():
                output_file.unlink(missing_ok=True)

    def run_batch(self, max_idle_sec: int = 15, poll_interval_sec: int = 3) -> int:
        """Process all queued jobs until queue is empty for max_idle_sec, then exit cleanly."""
        logger.info("Starting Controller Agent in batch mode at %s...", self.api_base_url)
        processed = 0
        idle_time = 0
        while idle_time < max_idle_sec:
            try:
                job = self.claim_job()
                if job:
                    self.process_job(job)
                    processed += 1
                    idle_time = 0
                else:
                    time.sleep(poll_interval_sec)
                    idle_time += poll_interval_sec
            except Exception as exc:
                logger.error("Controller agent batch loop error: %s", exc)
                time.sleep(poll_interval_sec)
                idle_time += poll_interval_sec
        logger.info("Batch mode completed. Total jobs processed: %d.", processed)
        return processed

    def run_loop(self, poll_interval_sec: int = 5) -> None:
        """Continuous polling loop."""
        logger.info("Starting Controller Agent polling loop at %s (interval: %ds)...", self.api_base_url, poll_interval_sec)
        while True:
            try:
                job = self.claim_job()
                if job:
                    self.process_job(job)
                else:
                    time.sleep(poll_interval_sec)
            except Exception as exc:
                logger.error("Controller agent loop error: %s", exc)
                time.sleep(poll_interval_sec)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Authorized Scan Controller Agent")
    parser.add_argument("--once", action="store_true", help="Process queued jobs and exit cleanly (for CI/CD and Cloud Runners)")
    parser.add_argument("--idle-timeout", type=int, default=15, help="Idle timeout in seconds before batch mode exits")
    parser.add_argument("--interval", type=int, default=5, help="Polling interval in seconds")
    cli_args = parser.parse_args()

    agent = ControllerAgent()
    if cli_args.once:
        agent.run_batch(max_idle_sec=cli_args.idle_timeout, poll_interval_sec=cli_args.interval)
    else:
        agent.run_loop(poll_interval_sec=cli_args.interval)
