import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, Header, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db import get_db
from app.models import ControllerNonce

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False, description="Admin or Operator API Key")
bearer_scheme = HTTPBearer(auto_error=False, description="OIDC JWT Bearer token (Production)")


@dataclass(frozen=True)
class Principal:
    role: str
    subject: str


def _api_key_principal(x_api_key: str) -> Principal:
    settings = get_settings()
    if secrets.compare_digest(x_api_key, settings.admin_api_key):
        return Principal(role="admin", subject="local-admin")
    if secrets.compare_digest(x_api_key, settings.api_key):
        return Principal(role="operator", subject="local-operator")
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid API key")


def _oidc_principal(authorization: str | None) -> Principal:
    settings = get_settings()
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="bearer token required")
    try:
        signing_key = jwt.PyJWKClient(settings.oidc_jwks_url).get_signing_key_from_jwt(authorization[7:]).key
        claims = jwt.decode(
            authorization[7:],
            signing_key,
            algorithms=["RS256", "ES256"],
            audience=settings.oidc_audience,
            issuer=settings.oidc_issuer,
        )
    except jwt.PyJWTError as error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid bearer token") from error
    roles = claims.get(settings.oidc_role_claim, [])
    if isinstance(roles, str):
        roles = [roles]
    role = "admin" if "admin" in roles else "operator" if "operator" in roles else None
    subject = claims.get("sub")
    if role is None or not isinstance(subject, str) or not subject:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="required scan-tool role missing")
    return Principal(role=role, subject=subject)


def authenticate(
    x_api_key: str | None = Security(api_key_header),
    auth_credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> Principal:
    settings = get_settings()
    if settings.auth_mode == "oidc":
        authorization = f"Bearer {auth_credentials.credentials}" if auth_credentials else None
        return _oidc_principal(authorization)
    if settings.auth_mode == "api_key" and settings.app_env.lower() != "production":
        provided_key = x_api_key or (auth_credentials.credentials if auth_credentials else None)
        if provided_key:
            return _api_key_principal(provided_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required (pass via X-API-Key header or Bearer token)",
        )
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication is not configured")


async def authenticate_controller(
    request: Request,
    x_controller_timestamp: str | None = Header(default=None, alias="X-Controller-Timestamp"),
    x_controller_nonce: str | None = Header(default=None, alias="X-Controller-Nonce"),
    x_controller_signature: str | None = Header(default=None, alias="X-Controller-Signature"),
    db: Session = Depends(get_db),
) -> Principal:
    """Validate HMAC-SHA256 signature and nonce freshness on internal controller requests."""
    if not x_controller_timestamp or not x_controller_nonce or not x_controller_signature:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing controller authentication headers",
        )

    try:
        ts = int(x_controller_timestamp)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid controller timestamp")

    now = int(time.time())
    if abs(now - ts) > 300:  # 5-minute skew tolerance
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="controller timestamp expired or skewed")

    body = await request.body()
    body_hash = hashlib.sha256(body).hexdigest()
    message = f"{request.method}\n{request.url.path}\n{x_controller_timestamp}\n{x_controller_nonce}\n{body_hash}".encode()

    settings = get_settings()
    secret = settings.controller_shared_secret.encode()
    expected_signature = hmac.new(secret, message, hashlib.sha256).hexdigest()

    if not secrets.compare_digest(x_controller_signature, expected_signature):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid controller signature")

    # Anti-replay nonce check
    existing_nonce = db.get(ControllerNonce, x_controller_nonce)
    if existing_nonce is not None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="controller nonce has already been used")

    nonce_record = ControllerNonce(
        nonce=x_controller_nonce,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    db.add(nonce_record)
    db.commit()

    return Principal(role="controller", subject="axiom-controller")
