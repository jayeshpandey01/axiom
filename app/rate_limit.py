"""Redis-backed fixed-window request limiting keyed by authenticated subject."""

from functools import lru_cache

from fastapi import Depends, HTTPException, status
from redis import Redis

from app.core.config import get_settings
from app.security import Principal, authenticate


@lru_cache
def _redis_client() -> Redis | None:
    url = get_settings().rate_limit_redis_url
    return Redis.from_url(url, decode_responses=True) if url else None


def enforce_rate_limit(principal: Principal = Depends(authenticate)) -> Principal:
    settings = get_settings()
    client = _redis_client()
    if client is None:
        # Local development remains usable without a Redis process.
        return principal
    key = f"scan-tool:rate-limit:{principal.subject}"
    try:
        count = client.incr(key)
        if count == 1:
            client.expire(key, 60)
    except Exception as error:
        if settings.app_env.lower() == "production":
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="rate limiter unavailable") from error
        return principal
    if count > settings.rate_limit_requests_per_minute:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="request rate limit exceeded")
    return principal
