import secrets
from dataclasses import dataclass

import jwt
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import get_settings

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
        keys = [k for k in (x_api_key, auth_credentials.credentials if auth_credentials else None) if k]
        if not keys:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key required (pass via X-API-Key header or Bearer token)",
            )
        for key in keys:
            if secrets.compare_digest(key, settings.admin_api_key):
                return Principal(role="admin", subject="local-admin")
        for key in keys:
            if secrets.compare_digest(key, settings.api_key):
                return Principal(role="operator", subject="local-operator")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid API key")
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication is not configured")
