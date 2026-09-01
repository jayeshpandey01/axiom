import hashlib
import hmac
import secrets
import time

from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.main import app
from controller.agent import generate_signed_headers


def test_missing_controller_headers_rejected() -> None:
    with TestClient(app) as client:
        response = client.post("/v1/internal/controller/jobs/claim")
    assert response.status_code == 401
    assert "missing controller authentication headers" in response.json()["detail"]


def test_valid_hmac_signature_passes() -> None:
    path = "/v1/internal/controller/jobs/claim"
    headers = generate_signed_headers("POST", path, b"")
    with TestClient(app) as client:
        response = client.post(path, headers=headers)
    # When queue is empty, returns 200 with null or 204
    assert response.status_code in {200, 204}


def test_tampered_payload_rejected() -> None:
    path = "/v1/internal/controller/jobs/claim"
    headers = generate_signed_headers("POST", path, b'{"original": true}')
    with TestClient(app) as client:
        # Send modified body that doesn't match signed body hash
        response = client.post(path, headers=headers, content=b'{"tampered": true}')
    assert response.status_code == 401
    assert "invalid controller signature" in response.json()["detail"]


def test_expired_timestamp_rejected() -> None:
    path = "/v1/internal/controller/jobs/claim"
    old_timestamp = str(int(time.time()) - 400)  # Exceeds 300s clock skew
    nonce = secrets.token_urlsafe(24)
    body_hash = hashlib.sha256(b"").hexdigest()
    message = f"POST\n{path}\n{old_timestamp}\n{nonce}\n{body_hash}".encode()
    signature = hmac.new(get_settings().controller_shared_secret.encode(), message, hashlib.sha256).hexdigest()

    headers = {
        "X-Controller-Timestamp": old_timestamp,
        "X-Controller-Nonce": nonce,
        "X-Controller-Signature": signature,
    }
    with TestClient(app) as client:
        response = client.post(path, headers=headers)
    assert response.status_code == 401
    assert "expired controller request" in response.json()["detail"]


def test_replay_nonce_rejected() -> None:
    path = "/v1/internal/controller/jobs/claim"
    headers = generate_signed_headers("POST", path, b"")
    with TestClient(app) as client:
        # First request succeeds
        res1 = client.post(path, headers=headers)
        assert res1.status_code in {200, 204}

        # Replayed second request with same nonce fails
        res2 = client.post(path, headers=headers)
        assert res2.status_code == 401
        assert "replayed controller request" in res2.json()["detail"]
