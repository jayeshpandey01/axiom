"""End-to-End workflow tests for the four new scan profiles.

Tests the full API lifecycle: register target -> queue scan with new profile ->
controller claims -> controller completes with tool-specific summary -> verify result.
All tests use dry-run output fixtures to avoid requiring real scanner binaries.
"""
import json
import uuid

from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.main import app
from controller.agent import (
    generate_signed_headers,
    parse_ffuf_output,
    parse_masscan_output,
    parse_nmap_output,
    parse_nuclei_output,
)


# ---------------------------------------------------------------------------
# Helper: register a target and queue a scan, return (target_id, scan_id)
# ---------------------------------------------------------------------------

def _register_and_queue(client: TestClient, profile: str) -> tuple[str, str]:
    settings = get_settings()
    admin_headers = {"X-API-Key": settings.admin_api_key}
    operator_headers = {"X-API-Key": settings.api_key}

    suffix = uuid.uuid4().hex[:8]
    target_res = client.post(
        "/v1/targets",
        headers=admin_headers,
        json={
            "value": f"probe-{suffix}.example.com",
            "owner_reference": "Security Team",
            "authorization_reference": f"AUTH-{profile.upper()}-TEST",
        },
    )
    assert target_res.status_code == 201, target_res.text
    target_id = target_res.json()["id"]

    scan_res = client.post(
        "/v1/scans",
        headers=operator_headers,
        json={"target_id": target_id, "profile": profile},
    )
    assert scan_res.status_code == 202, f"Queuing {profile}: {scan_res.text}"
    return target_id, scan_res.json()["id"]


def _claim_and_complete(client: TestClient, scan_id: str, summary: dict) -> None:
    """Simulate controller claiming and completing a scan."""
    claim_path = "/v1/internal/controller/jobs/claim"
    claim_headers = generate_signed_headers("POST", claim_path, b"")
    claim_res = client.post(claim_path, headers=claim_headers)
    assert claim_res.status_code == 200, claim_res.text
    assert claim_res.json()["id"] == scan_id

    complete_path = f"/v1/internal/controller/jobs/{scan_id}/complete"
    body = json.dumps({"summary": summary}).encode()
    complete_headers = generate_signed_headers("POST", complete_path, body)
    complete_headers["Content-Type"] = "application/json"
    complete_res = client.post(complete_path, headers=complete_headers, content=body)
    assert complete_res.status_code == 200, complete_res.text


# ---------------------------------------------------------------------------
# Profile-specific E2E tests
# ---------------------------------------------------------------------------

def test_nmap_scan_lifecycle() -> None:
    """Full lifecycle test for network-portscan (nmap) profile."""
    with TestClient(app) as client:
        settings = get_settings()
        _target_id, scan_id = _register_and_queue(client, "network-portscan")

        # Verify queued
        status_res = client.get(f"/v1/scans/{scan_id}", headers={"X-API-Key": settings.api_key})
        assert status_res.json()["status"] == "queued"
        assert status_res.json()["profile"] == "network-portscan"

        # Controller claims and completes with nmap-style summary
        nmap_summary = {
            "risk_summary": {"critical": 0, "high": 2, "medium": 1, "low": 2, "info": 1, "total": 6},
            "findings": [],
            "open_ports": [{"ip": "1.2.3.4", "port": 22, "protocol": "tcp", "service": "ssh"}],
            "hosts_up": 1,
        }
        _claim_and_complete(client, scan_id, nmap_summary)

        # Verify result
        result_res = client.get(f"/v1/scans/{scan_id}/result", headers={"X-API-Key": settings.api_key})
        assert result_res.status_code == 200
        result = result_res.json()
        assert result["summary"]["hosts_up"] == 1
        assert len(result["summary"]["open_ports"]) == 1


def test_masscan_scan_lifecycle() -> None:
    """Full lifecycle test for fast-portscan (masscan) profile."""
    with TestClient(app) as client:
        settings = get_settings()
        _target_id, scan_id = _register_and_queue(client, "fast-portscan")

        masscan_summary = {
            "risk_summary": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 1, "total": 2},
            "findings": [],
            "open_ports": [
                {"ip": "1.2.3.4", "port": 80, "protocol": "tcp", "service": "open"},
                {"ip": "1.2.3.4", "port": 443, "protocol": "tcp", "service": "open"},
            ],
            "hosts_up": 1,
        }
        _claim_and_complete(client, scan_id, masscan_summary)

        result_res = client.get(f"/v1/scans/{scan_id}/result", headers={"X-API-Key": settings.api_key})
        assert result_res.status_code == 200
        assert result_res.json()["summary"]["hosts_up"] == 1


def test_ffuf_scan_lifecycle() -> None:
    """Full lifecycle test for content-discovery (ffuf) profile."""
    with TestClient(app) as client:
        settings = get_settings()
        _target_id, scan_id = _register_and_queue(client, "content-discovery")

        ffuf_summary = {
            "risk_summary": {"critical": 0, "high": 2, "medium": 1, "low": 1, "info": 1, "total": 5},
            "findings": [],
            "discovered_paths": [
                {"url": "https://example.com/admin", "status": 200, "length": 1024},
                {"url": "https://example.com/api", "status": 200, "length": 512},
            ],
            "total_requests": 150,
        }
        _claim_and_complete(client, scan_id, ffuf_summary)

        result_res = client.get(f"/v1/scans/{scan_id}/result", headers={"X-API-Key": settings.api_key})
        assert result_res.status_code == 200
        assert result_res.json()["summary"]["total_requests"] == 150
        assert len(result_res.json()["summary"]["discovered_paths"]) == 2


def test_nuclei_scan_lifecycle() -> None:
    """Full lifecycle test for vuln-assessment (nuclei) profile."""
    with TestClient(app) as client:
        settings = get_settings()
        _target_id, scan_id = _register_and_queue(client, "vuln-assessment")

        nuclei_summary = {
            "risk_summary": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 1, "total": 2},
            "findings": [
                {"id": "SEC-001", "code": "NUCLEI_CVE_2021_44228", "severity": "CRITICAL",
                 "title": "Log4Shell RCE", "description": "Critical.", "evidence": "matched", "remediation": "Upgrade."},
            ],
            "cve_ids": ["CVE-2021-44228"],
            "templates_matched": 2,
        }
        _claim_and_complete(client, scan_id, nuclei_summary)

        result_res = client.get(f"/v1/scans/{scan_id}/result", headers={"X-API-Key": settings.api_key})
        assert result_res.status_code == 200
        result = result_res.json()
        assert result["summary"]["risk_summary"]["critical"] == 1
        assert "CVE-2021-44228" in result["summary"]["cve_ids"]


# ---------------------------------------------------------------------------
# Parser unit tests (no server needed)
# ---------------------------------------------------------------------------

def test_parse_nmap_output_from_dry_run(tmp_path):
    """parse_nmap_output must parse the dry-run mock XML correctly."""
    from controller.fleet_manager import FleetManager
    from controller.profiles import get_profile
    manager = FleetManager(dry_run=True)
    manager.work_dir = tmp_path
    output_file = tmp_path / "nmap.xml"
    manager._write_dry_run_output(get_profile("network-portscan"), "1.2.3.4", output_file)
    result = parse_nmap_output(output_file)
    assert "open_ports" in result
    assert result["hosts_up"] >= 0



def test_parse_masscan_output_from_dry_run(tmp_path):
    from controller.fleet_manager import FleetManager
    from controller.profiles import get_profile
    manager = FleetManager(dry_run=True)
    manager.work_dir = tmp_path
    output_file = tmp_path / "masscan.json"
    manager._write_dry_run_output(get_profile("fast-portscan"), "1.2.3.4", output_file)
    result = parse_masscan_output(output_file)
    assert "open_ports" in result
    assert result["hosts_up"] >= 1


def test_parse_ffuf_output_from_dry_run(tmp_path):
    from controller.fleet_manager import FleetManager
    from controller.profiles import get_profile
    manager = FleetManager(dry_run=True)
    manager.work_dir = tmp_path
    output_file = tmp_path / "ffuf.json"
    manager._write_dry_run_output(get_profile("content-discovery"), "example.com", output_file)
    result = parse_ffuf_output(output_file)
    assert "discovered_paths" in result
    assert len(result["discovered_paths"]) >= 1


def test_parse_nuclei_output_from_dry_run(tmp_path):
    from controller.fleet_manager import FleetManager
    from controller.profiles import get_profile
    manager = FleetManager(dry_run=True)
    manager.work_dir = tmp_path
    output_file = tmp_path / "nuclei.jsonl"
    manager._write_dry_run_output(get_profile("vuln-assessment"), "example.com", output_file)
    result = parse_nuclei_output(output_file)
    assert result["templates_matched"] >= 1
    assert result["risk_summary"]["critical"] >= 1
