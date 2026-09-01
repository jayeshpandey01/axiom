from fastapi.testclient import TestClient

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
    with TestClient(app) as client:
        response = client.post(
            "/v1/targets",
            headers={"X-API-Key": "development-only-change-me-admin"},
            json={"value": "https://example.com/path", "owner_reference": "customer-1", "authorization_reference": "ticket-123"},
        )
    assert response.status_code == 422


def test_operator_cannot_register_target() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/v1/targets",
            headers={"X-API-Key": "development-only-change-me"},
            json={"value": "example.com", "owner_reference": "customer-1", "authorization_reference": "ticket-123"},
        )
    assert response.status_code == 403
