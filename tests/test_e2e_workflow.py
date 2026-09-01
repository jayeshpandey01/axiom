import json
import uuid

from fastapi.testclient import TestClient

from app.main import app
from controller.agent import generate_signed_headers


def test_full_end_to_end_scan_lifecycle() -> None:
    with TestClient(app) as client:
        # 1. Admin registers an authorized target
        admin_headers = {"X-API-Key": "development-only-change-me-admin"}
        target_payload = {
            "value": f"target-{uuid.uuid4().hex[:8]}.example.com",
            "owner_reference": "Security Team A",
            "authorization_reference": "AUTH-DOC-2026-09",
        }
        target_res = client.post("/v1/targets", headers=admin_headers, json=target_payload)
        assert target_res.status_code == 201
        target_data = target_res.json()
        target_id = target_data["id"]

        # 2. Operator queues a scan with fixed profile 'recon'
        operator_headers = {"X-API-Key": "development-only-change-me"}
        scan_payload = {"target_id": target_id, "profile": "recon"}
        scan_res = client.post("/v1/scans", headers=operator_headers, json=scan_payload)
        assert scan_res.status_code == 202
        scan_data = scan_res.json()
        scan_id = scan_data["id"]
        assert scan_data["status"] == "queued"

        # 3. Controller claims the job via HMAC
        claim_path = "/v1/internal/controller/jobs/claim"
        claim_headers = generate_signed_headers("POST", claim_path, b"")
        claim_res = client.post(claim_path, headers=claim_headers)
        assert claim_res.status_code == 200
        claimed_job = claim_res.json()
        assert claimed_job["id"] == scan_id
        assert claimed_job["profile"] == "recon"

        # 4. Verify scan state transitioned to 'running'
        status_res = client.get(f"/v1/scans/{scan_id}", headers=operator_headers)
        assert status_res.status_code == 200
        assert status_res.json()["status"] == "running"

        # 5. Controller completes the scan with normalized findings
        complete_path = f"/v1/internal/controller/jobs/{scan_id}/complete"
        summary_data = {
            "summary": {
                "live_hosts_count": 1,
                "status_codes": {"200": 1},
                "web_servers": ["Apache/2.4.41"],
                "titles": ["Authorized Testing Target"],
                "technologies": ["OpenSSL", "Ubuntu"],
            }
        }
        complete_body = json.dumps(summary_data).encode()
        complete_headers = generate_signed_headers("POST", complete_path, complete_body)
        complete_headers["Content-Type"] = "application/json"

        complete_res = client.post(complete_path, headers=complete_headers, content=complete_body)
        assert complete_res.status_code == 200

        # 6. Verify scan status is 'completed'
        completed_status_res = client.get(f"/v1/scans/{scan_id}", headers=operator_headers)
        assert completed_status_res.status_code == 200
        assert completed_status_res.json()["status"] == "completed"

        # 7. Operator retrieves normalized results
        result_res = client.get(f"/v1/scans/{scan_id}/result", headers=operator_headers)
        assert result_res.status_code == 200
        result_data = result_res.json()
        assert result_data["scan_job_id"] == scan_id
        assert result_data["summary"]["live_hosts_count"] == 1
        assert "Apache/2.4.41" in result_data["summary"]["web_servers"]

        # 8. Admin reviews the immutable audit log
        audit_res = client.get("/v1/audit-events", headers=admin_headers)
        assert audit_res.status_code == 200
        audit_actions = [event["action"] for event in audit_res.json()]
        assert "target.created" in audit_actions
        assert "scan.queued" in audit_actions
        assert "scan.claimed" in audit_actions
        assert "scan.completed" in audit_actions


def test_scan_cancellation_workflow() -> None:
    with TestClient(app) as client:
        admin_headers = {"X-API-Key": "development-only-change-me-admin"}
        operator_headers = {"X-API-Key": "development-only-change-me"}

        # 1. Register target & queue scan
        target_res = client.post(
            "/v1/targets",
            headers=admin_headers,
            json={
                "value": f"cancel-target-{uuid.uuid4().hex[:6]}.com",
                "owner_reference": "Security Team B",
                "authorization_reference": "AUTH-CANCEL-TEST",
            },
        )
        target_id = target_res.json()["id"]

        scan_res = client.post("/v1/scans", headers=operator_headers, json={"target_id": target_id, "profile": "recon"})
        scan_id = scan_res.json()["id"]

        # 2. Operator requests cancellation
        cancel_res = client.post(f"/v1/scans/{scan_id}/cancel", headers=operator_headers)
        assert cancel_res.status_code == 200
        assert cancel_res.json()["status"] == "cancelled"

        # 3. Controller checks status and detects cancellation
        status_path = f"/v1/internal/controller/jobs/{scan_id}/status"
        status_headers = generate_signed_headers("GET", status_path, b"")
        status_res = client.get(status_path, headers=status_headers)
        assert status_res.status_code == 200
        assert status_res.json()["status"] == "cancelled"
