"""E2E lifecycle tests for all 10 new Phase 2 & 3 scanner profiles.

Validates the complete workflow:
1. Target registration
2. Job queueing via /v1/scans or /v1/sast/scans
3. Internal HMAC-authenticated controller claim
4. Execution with mock dry-run fixture
5. Controller completion report
6. Result verification via /v1/scans/{id}/result or /v1/sast/scans/{id}/result
"""

import json
import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.main import app
from controller.agent import (
    generate_signed_headers,
)
from controller.fleet_manager import FleetManager
from controller.profiles import get_profile


@pytest.fixture
def client():
    return TestClient(app)


def _register_target(client: TestClient, is_sast: bool = False) -> str:
    settings = get_settings()
    suffix = uuid.uuid4().hex[:8]
    val = f"probe-{suffix}.example.com" if not is_sast else f"repo-{suffix}/app"
    ttype = "source_code" if is_sast else "network"
    res = client.post(
        "/v1/targets",
        headers={"X-API-Key": settings.admin_api_key},
        json={"value": val, "owner_reference": "SecOps", "authorization_reference": "AUTH-TEST", "target_type": ttype},
    )
    assert res.status_code == 201, res.text
    return res.json()["id"]


def _claim_and_complete(client: TestClient, scan_id: str, summary: dict) -> None:
    claim_path = "/v1/internal/controller/jobs/claim"
    claim_headers = generate_signed_headers("POST", claim_path, b"")
    claim_res = client.post(claim_path, headers=claim_headers)
    assert claim_res.status_code == 200, claim_res.text
    assert claim_res.json()["id"] == scan_id

    comp_path = f"/v1/internal/controller/jobs/{scan_id}/complete"
    body = json.dumps({"summary": summary}).encode()
    comp_headers = generate_signed_headers("POST", comp_path, body)
    comp_headers["Content-Type"] = "application/json"
    comp_res = client.post(comp_path, headers=comp_headers, content=body)
    assert comp_res.status_code == 200, comp_res.text


@pytest.mark.parametrize("profile_name", [
    "web-crawl",
    "deep-content-discovery",
    "dns-recon",
    "subdomain-takeover",
    "smart-portscan",
    "waf-detect",
    "cors-audit",
    "crlf-scan",
    "ssti-scan",
])
def test_dast_new_profile_lifecycle(client, profile_name):
    settings = get_settings()
    target_id = _register_target(client, is_sast=False)

    # Queue scan
    queue_res = client.post(
        "/v1/scans",
        headers={"X-API-Key": settings.api_key},
        json={"target_id": target_id, "profile": profile_name},
    )
    assert queue_res.status_code == 202, f"Failed queueing {profile_name}: {queue_res.text}"
    scan_id = queue_res.json()["id"]

    # Claim & complete with dry-run fixture simulation
    summary = {
        "profile": profile_name,
        "risk_summary": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0, "total": 1},
        "findings": [{"id": "SEC-001", "severity": "MEDIUM", "code": f"{profile_name.upper()}_TEST"}],
    }
    _claim_and_complete(client, scan_id, summary)

    # Verify result
    result_res = client.get(f"/v1/scans/{scan_id}/result", headers={"X-API-Key": settings.api_key})
    assert result_res.status_code == 200
    data = result_res.json()
    assert data["summary"]["profile"] == profile_name
    assert data["summary"]["risk_summary"]["total"] == 1


def test_sast_gitleaks_lifecycle(client):
    settings = get_settings()
    target_id = _register_target(client, is_sast=True)

    # Queue SAST scan
    queue_res = client.post(
        "/v1/sast/scans",
        headers={"X-API-Key": settings.api_key},
        json={"target_id": target_id, "profile": "sast-gitleaks"},
    )
    assert queue_res.status_code == 202, queue_res.text
    scan_id = queue_res.json()["id"]

    # Claim & complete
    summary = {
        "profile": "sast-gitleaks",
        "secrets_found": 1,
        "risk_summary": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 1},
        "findings": [{"id": "SEC-001", "severity": "CRITICAL", "code": "GITLEAKS_AWS_TOKEN"}],
    }
    _claim_and_complete(client, scan_id, summary)

    # Verify result
    result_res = client.get(f"/v1/sast/scans/{scan_id}/result", headers={"X-API-Key": settings.api_key})
    assert result_res.status_code == 200
    data = result_res.json()
    assert data["summary"]["secrets_found"] == 1


def test_fleet_manager_dry_run_generation(tmp_path):
    """Verify fleet manager writes valid mock outputs for all 10 new profiles."""
    fm = FleetManager(dry_run=True)
    for profile_name in [
        "web-crawl", "deep-content-discovery", "dns-recon", "subdomain-takeover",
        "smart-portscan", "waf-detect", "cors-audit", "crlf-scan", "ssti-scan", "sast-gitleaks"
    ]:
        prof = get_profile(profile_name)
        out_file = tmp_path / f"{profile_name}.out"
        fm._write_dry_run_output(prof, "example.com", out_file)
        assert out_file.exists()
        assert out_file.stat().st_size > 0
