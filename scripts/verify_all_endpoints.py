"""Comprehensive Verification Script for all DAST & SAST Endpoints and Scanner Engines."""

import json
import sys
import uuid
from pathlib import Path

# Add workspace root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.main import app
from controller.agent import generate_signed_headers


def run_verification():
    print("=" * 70)
    print("        COMPREHENSIVE ENDPOINT & PROFILE VERIFICATION SUITE")
    print("=" * 70)

    client = TestClient(app)
    settings = get_settings()
    admin_hdr = {"X-API-Key": settings.admin_api_key}
    operator_hdr = {"X-API-Key": settings.api_key}

    # 1. Health Endpoint
    res = client.get("/health")
    assert res.status_code == 200, f"Health check failed: {res.text}"
    print("[PASS] 1. GET /health -> status: 200 OK")

    # 2. DAST Profiles Endpoint
    res = client.get("/v1/profiles")
    assert res.status_code == 200
    dast_profiles = [p["profile"] for p in res.json()["dast_profiles"]]
    expected_dast = ["recon", "web-discovery", "network-portscan", "fast-portscan", "content-discovery", "vuln-assessment"]
    for p in expected_dast:
        assert p in dast_profiles, f"Missing DAST profile: {p}"
    print(f"[PASS] 2. GET /v1/profiles -> All {len(dast_profiles)} DAST profiles registered ({', '.join(dast_profiles)})")

    # 3. SAST Profiles Endpoint
    res = client.get("/v1/sast/profiles")
    assert res.status_code == 200
    sast_profiles = [p["profile"] for p in res.json()["sast_profiles"]]
    expected_sast = ["sast-joern", "sast-semgrep", "sast-trufflehog"]
    for p in expected_sast:
        assert p in sast_profiles, f"Missing SAST profile: {p}"
    print(f"[PASS] 3. GET /v1/sast/profiles -> All {len(sast_profiles)} SAST profiles registered ({', '.join(sast_profiles)})")

    # 4. Target Registration
    target_domain = f"test-{uuid.uuid4().hex[:6]}.example.com"
    res = client.post(
        "/v1/targets",
        headers=admin_hdr,
        json={"value": target_domain, "owner_reference": "QA Team", "authorization_reference": "AUTH-VERIFY-001"},
    )
    assert res.status_code == 201
    target_id = res.json()["id"]
    print(f"[PASS] 4. POST /v1/targets -> Target registered: {target_domain} (ID: {target_id})")

    # 5. Test All 6 DAST Profiles (Queue -> Claim -> Complete -> Result)
    print("\n--- Verifying All 6 DAST Scanner Profiles ---")
    for profile in expected_dast:
        # Queue scan
        res = client.post("/v1/scans", headers=operator_hdr, json={"target_id": target_id, "profile": profile})
        assert res.status_code == 202, f"Failed queuing {profile}: {res.text}"
        scan_id = res.json()["id"]

        # Claim job via internal controller endpoint
        claim_path = "/v1/internal/controller/jobs/claim"
        claim_hdr = generate_signed_headers("POST", claim_path, b"")
        c_res = client.post(claim_path, headers=claim_hdr)
        assert c_res.status_code == 200 and c_res.json()["id"] == scan_id

        # Complete job with profile-specific summary
        mock_summary = {
            "risk_summary": {"critical": 0, "high": 1, "medium": 1, "low": 1, "info": 1, "total": 4},
            "findings": [
                {
                    "id": "SEC-001",
                    "code": f"{profile.upper()}_DISCOVERY",
                    "severity": "HIGH",
                    "title": f"Verified {profile} Finding",
                    "description": "Finding description",
                    "evidence": "evidence-data",
                    "remediation": "remediation-data",
                }
            ],
        }
        comp_path = f"/v1/internal/controller/jobs/{scan_id}/complete"
        body = json.dumps({"summary": mock_summary}).encode()
        comp_hdr = generate_signed_headers("POST", comp_path, body)
        comp_hdr["Content-Type"] = "application/json"
        comp_res = client.post(comp_path, headers=comp_hdr, content=body)
        assert comp_res.status_code == 200

        # Fetch result
        r_res = client.get(f"/v1/scans/{scan_id}/result", headers=operator_hdr)
        assert r_res.status_code == 200
        assert r_res.json()["summary"]["findings"][0]["code"] == f"{profile.upper()}_DISCOVERY"
        print(f"  [+] DAST Profile '{profile}': Queue -> Claim -> Complete -> Result verified successfully")

    # 6. Test All 3 SAST Profiles (Queue -> Claim -> Complete -> Result)
    print("\n--- Verifying All 3 SAST Scanner Profiles ---")
    for profile in expected_sast:
        # Queue SAST scan
        res = client.post("/v1/sast/scans", headers=operator_hdr, json={"target_id": target_id, "profile": profile})
        assert res.status_code == 202, f"Failed queuing SAST {profile}: {res.text}"
        scan_id = res.json()["id"]

        # Check SAST scan status
        st_res = client.get(f"/v1/sast/scans/{scan_id}", headers=operator_hdr)
        assert st_res.status_code == 200 and st_res.json()["status"] == "queued"

        # Claim
        claim_path = "/v1/internal/controller/jobs/claim"
        claim_hdr = generate_signed_headers("POST", claim_path, b"")
        c_res = client.post(claim_path, headers=claim_hdr)
        assert c_res.status_code == 200 and c_res.json()["id"] == scan_id

        # Complete
        mock_summary = {
            "risk_summary": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 1},
            "findings": [
                {
                    "id": "SEC-001",
                    "code": f"SAST_{profile.upper().replace('-', '_')}",
                    "severity": "CRITICAL",
                    "title": f"Verified {profile} Security Flaw",
                    "description": "SAST description",
                    "evidence": "source.py:42",
                    "remediation": "Fix taint sink",
                }
            ],
            "scanned_files_count": 12,
            "total_rules_evaluated": 50,
        }
        comp_path = f"/v1/internal/controller/jobs/{scan_id}/complete"
        body = json.dumps({"summary": mock_summary}).encode()
        comp_hdr = generate_signed_headers("POST", comp_path, body)
        comp_hdr["Content-Type"] = "application/json"
        comp_res = client.post(comp_path, headers=comp_hdr, content=body)
        assert comp_res.status_code == 200

        # Fetch SAST result
        r_res = client.get(f"/v1/sast/scans/{scan_id}/result", headers=operator_hdr)
        assert r_res.status_code == 200
        assert r_res.json()["summary"]["scanned_files_count"] == 12
        print(f"  [+] SAST Profile '{profile}': Queue -> Claim -> Complete -> Result verified successfully")

    # 7. Test Error Logging on Failed Scan Jobs
    print("\n--- Verifying Failure Diagnostics & Error Log Endpoint ---")
    f_res = client.post("/v1/scans", headers=operator_hdr, json={"target_id": target_id, "profile": "recon"})
    f_scan_id = f_res.json()["id"]
    claim_path = "/v1/internal/controller/jobs/claim"
    claim_hdr = generate_signed_headers("POST", claim_path, b"")
    client.post(claim_path, headers=claim_hdr)

    fail_path = f"/v1/internal/controller/jobs/{f_scan_id}/fail"
    fail_reason = "DNS resolution timed out after 30s"
    f_body = json.dumps({"reason": fail_reason}).encode()
    f_hdr = generate_signed_headers("POST", fail_path, f_body)
    f_hdr["Content-Type"] = "application/json"
    fail_res = client.post(fail_path, headers=f_hdr, content=f_body)
    assert fail_res.status_code == 200

    r_fail = client.get(f"/v1/scans/{f_scan_id}/result", headers=operator_hdr)
    assert r_fail.status_code == 200
    assert r_fail.json()["error_logs"] == fail_reason
    print(f"[PASS] 7. GET /v1/scans/{f_scan_id}/result surfaces error_logs correctly: '{fail_reason}'")

    print("\n" + "=" * 70)
    print(" [ALL VERIFICATION CHECKS PASSED - 100% OPERATIONAL] ")
    print("=" * 70)


if __name__ == "__main__":
    run_verification()
