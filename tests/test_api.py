from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.main import app


def test_health() -> None:
    with TestClient(app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_scan_requires_api_key() -> None:
    with TestClient(app) as client:
        response = client.post("/v1/scans", json={"target_id": "00000000-0000-0000-0000-000000000000", "profile": "recon"})
    assert response.status_code == 401


def test_target_rejects_urls() -> None:
    settings = get_settings()
    with TestClient(app) as client:
        response = client.post(
            "/v1/targets",
            headers={"X-API-Key": settings.admin_api_key},
            json={"value": "https://example.com/path", "owner_reference": "customer-1", "authorization_reference": "ticket-123"},
        )
    assert response.status_code == 422


def test_operator_cannot_register_target() -> None:
    settings = get_settings()
    with TestClient(app) as client:
        response = client.post(
            "/v1/targets",
            headers={"X-API-Key": settings.api_key},
            json={"value": "example.com", "owner_reference": "customer-1", "authorization_reference": "ticket-123"},
        )
    assert response.status_code == 403


def test_invalid_profile_rejected() -> None:
    """An arbitrary string (e.g. injected nmap flags) must be rejected with 422."""
    settings = get_settings()
    with TestClient(app) as client:
        response = client.post(
            "/v1/scans",
            headers={"X-API-Key": settings.api_key},
            json={"target_id": "00000000-0000-0000-0000-000000000000", "profile": "nmap -oX /etc/passwd"},
        )
    assert response.status_code == 422


def test_new_profiles_accepted_by_schema() -> None:
    """All new profile names must pass schema validation (we only test 422 vs non-422 here;
    the full flow is covered by test_e2e_new_profiles.py)."""
    settings = get_settings()
    new_profiles = ["network-portscan", "fast-portscan", "content-discovery", "vuln-assessment"]
    with TestClient(app) as client:
        for profile in new_profiles:
            response = client.post(
                "/v1/scans",
                headers={"X-API-Key": settings.api_key},
                json={"target_id": "00000000-0000-0000-0000-000000000000", "profile": profile},
            )
            # 404 (target not found) is acceptable here — it means the profile passed validation
            assert response.status_code != 422, f"Profile '{profile}' was incorrectly rejected as invalid."


def test_sast_profile_rejected_on_dast_endpoint() -> None:
    """sast-joern must be rejected on /v1/scans because SAST scans belong to /v1/sast/scans."""
    settings = get_settings()
    with TestClient(app) as client:
        response = client.post(
            "/v1/scans",
            headers={"X-API-Key": settings.api_key},
            json={"target_id": "00000000-0000-0000-0000-000000000000", "profile": "sast-joern"},
        )
    assert response.status_code == 422


def test_sast_endpoint_accepts_sast_joern() -> None:
    """sast-joern must pass schema validation on the dedicated /v1/sast/scans endpoint."""
    settings = get_settings()
    with TestClient(app) as client:
        response = client.post(
            "/v1/sast/scans",
            headers={"X-API-Key": settings.api_key},
            json={"target_id": "00000000-0000-0000-0000-000000000000", "profile": "sast-joern"},
        )
    assert response.status_code != 422
