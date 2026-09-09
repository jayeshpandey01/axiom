"""Tests for the new router-based FastAPI architecture."""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from app.main import app
    return TestClient(app, raise_server_exceptions=False)


class TestHealthEndpoints:
    def test_root_redirects_to_docs(self, client):
        response = client.get("/", follow_redirects=False)
        assert response.status_code == 307
        assert response.headers["location"] == "/docs"

    def test_health_returns_ok(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    def test_health_live(self, client):
        response = client.get("/health/live")
        assert response.status_code == 200
        assert response.json()["status"] == "alive"

    def test_health_ready(self, client):
        response = client.get("/health/ready")
        # May be 200 or 503 depending on db; just check it responds
        assert response.status_code in (200, 503)

    def test_security_headers_present(self, client):
        response = client.get("/health")
        assert response.headers.get("x-content-type-options") == "nosniff"
        assert response.headers.get("x-frame-options") == "DENY"
        assert response.headers.get("referrer-policy") == "no-referrer"
        assert response.headers.get("cache-control") == "no-store"

    def test_request_id_header_injected(self, client):
        response = client.get("/health")
        assert "x-request-id" in response.headers

    def test_custom_request_id_propagated(self, client):
        response = client.get("/health", headers={"X-Request-ID": "test-uuid-1234"})
        assert response.headers.get("x-request-id") == "test-uuid-1234"


class TestProfileEndpoints:
    def test_dast_profiles_listed(self, client):
        response = client.get("/v1/profiles")
        assert response.status_code == 200
        data = response.json()
        assert "dast_profiles" in data
        profiles = [p["profile"] for p in data["dast_profiles"]]
        for expected in ["recon", "web-discovery", "vuln-assessment", "xss-scan", "web-crawl", "dns-recon", "smart-portscan"]:
            assert expected in profiles

    def test_sast_profiles_listed(self, client):
        response = client.get("/v1/profiles/sast")
        assert response.status_code == 200
        data = response.json()
        assert "sast_profiles" in data
        profiles = [p["profile"] for p in data["sast_profiles"]]
        for expected in ["sast-joern", "sast-semgrep", "sast-trufflehog", "sast-codeql", "sast-gitleaks"]:
            assert expected in profiles


class TestDASTScanEndpoints:
    def test_list_scans_requires_auth(self, client):
        response = client.get("/v1/scans")
        assert response.status_code == 401

    def test_queue_scan_requires_auth(self, client):
        response = client.post("/v1/scans", json={"target_id": "00000000-0000-0000-0000-000000000001", "profile": "recon"})
        assert response.status_code == 401

    def test_get_scan_requires_auth(self, client):
        response = client.get("/v1/scans/00000000-0000-0000-0000-000000000001")
        assert response.status_code == 401

    def test_cancel_scan_requires_auth(self, client):
        response = client.post("/v1/scans/00000000-0000-0000-0000-000000000001/cancel")
        assert response.status_code == 401

    def test_retry_scan_requires_auth(self, client):
        response = client.post("/v1/scans/00000000-0000-0000-0000-000000000001/retry")
        assert response.status_code == 401


class TestSASTScanEndpoints:
    def test_list_sast_scans_requires_auth(self, client):
        response = client.get("/v1/sast/scans")
        assert response.status_code == 401

    def test_queue_sast_scan_requires_auth(self, client):
        response = client.post("/v1/sast/scans", json={"target_id": "00000000-0000-0000-0000-000000000001", "profile": "sast-semgrep"})
        assert response.status_code == 401


class TestTargetEndpoints:
    def test_list_targets_requires_auth(self, client):
        response = client.get("/v1/targets")
        assert response.status_code == 401

    def test_post_target_requires_auth(self, client):
        response = client.post("/v1/targets", json={
            "value": "example.com",
            "owner_reference": "test",
            "authorization_reference": "auth-doc-001"
        })
        assert response.status_code == 401


class TestAuditEndpoints:
    def test_audit_events_requires_auth(self, client):
        response = client.get("/v1/audit-events")
        assert response.status_code == 401


class TestErrorHandling:
    def test_404_returns_json_envelope(self, client):
        response = client.get("/v1/nonexistent-route-xyz")
        assert response.status_code == 404
        data = response.json()
        assert "error" in data
        assert data["error"]["status"] == 404

    def test_validation_error_returns_json_envelope(self, client):
        # POST with wrong body to a validation-requiring endpoint
        from app.core.config import get_settings
        key = get_settings().admin_api_key
        response = client.post(
            "/v1/targets",
            json={"value": "", "owner_reference": "x", "authorization_reference": "y"},
            headers={"X-API-Key": key},
        )
        assert response.status_code in (400, 422)


class TestStatsEndpoint:
    def test_stats_requires_auth(self, client):
        response = client.get("/v1/stats")
        assert response.status_code == 401

    def test_stats_authenticated_returns_counts(self, client):
        from app.core.config import get_settings
        key = get_settings().api_key
        response = client.get("/v1/stats", headers={"X-API-Key": key})
        assert response.status_code == 200
        data = response.json()
        assert "targets_count" in data
        assert "scans_count" in data
        assert "results_count" in data
        assert "scans_by_status" in data
        assert "scans_by_profile" in data
