"""Replay-protected HMAC authentication for the controller's outbound API calls."""

import hashlib
import hmac
import time
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import ControllerNonce

MAX_CLOCK_SKEW_SECONDS = 300


async def require_controller(request: Request, db: Session) -> None:
    """Validate HMAC-SHA256 signature and nonce freshness on internal controller requests."""
    x_controller_timestamp = request.headers.get("x-controller-timestamp")
    x_controller_nonce = request.headers.get("x-controller-nonce")
    x_controller_signature = request.headers.get("x-controller-signature")

    if not x_controller_timestamp or not x_controller_nonce or not x_controller_signature:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing controller authentication headers",
        )

    try:
        timestamp = int(x_controller_timestamp)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid controller timestamp") from error

    if abs(time.time() - timestamp) > MAX_CLOCK_SKEW_SECONDS:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="expired controller request")

    if len(x_controller_nonce) < 16 or len(x_controller_nonce) > 80:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid controller nonce")

    if db.get(ControllerNonce, x_controller_nonce):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="replayed controller request")

    body = await request.body()
    body_hash = hashlib.sha256(body).hexdigest()
    message = f"{request.method}\n{request.url.path}\n{timestamp}\n{x_controller_nonce}\n{body_hash}".encode()
    expected = hmac.new(get_settings().controller_shared_secret.encode(), message, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(x_controller_signature, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid controller signature")

    db.add(ControllerNonce(nonce=x_controller_nonce, expires_at=datetime.now(UTC) + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS)))
    db.commit()
