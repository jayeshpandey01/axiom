"""Production Controller Agent Daemon.

Pulls signed jobs from the API via outbound HTTPS, executes fixed scanner
profiles via FleetManager, normalizes findings, and reports completion/failure.
"""
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from pathlib import Path
from typing import Any

import httpx

from controller.config import settings
from controller.fleet_manager import FleetError, FleetManager

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
    """Parse JSON or line-delimited JSON output from httpx into a normalized summary."""
    if not output_file.exists():
        return {"live_hosts": 0, "findings": []}

    content = output_file.read_text(encoding="utf-8").strip()
    if not content:
        return {"live_hosts": 0, "findings": []}

    records = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            # Plain text line
            records.append({"raw": line})

    status_codes = {}
    web_servers = set()
    titles = []
    technologies = set()

    for item in records:
        if isinstance(item, dict):
            code = item.get("status_code") or item.get("status-code")
            if code:
                status_codes[str(code)] = status_codes.get(str(code), 0) + 1
            server = item.get("webserver") or item.get("web_server")
            if server:
                web_servers.add(str(server))
            title = item.get("title")
            if title:
                titles.append(str(title)[:80])
            tech = item.get("tech") or item.get("technologies") or []
            if isinstance(tech, list):
                for t in tech:
                    technologies.add(str(t))

    return {
        "live_hosts_count": len(records),
        "status_codes": status_codes,
        "web_servers": list(web_servers)[:10],
        "titles": titles[:10],
        "technologies": list(technologies)[:20],
    }


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
    agent = ControllerAgent()
    agent.run_loop()
