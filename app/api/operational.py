"""Operational health check endpoints."""

import logging

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.db import get_db

logger = logging.getLogger("app.operational")

router = APIRouter(tags=["Operational"])


@router.get("/", include_in_schema=False)
def root():
    """Redirect root path to interactive API documentation."""
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/docs")


@router.get("/health", summary="Basic Health Check")
def health() -> dict[str, str]:
    """Returns 200 OK if the service process is alive."""
    return {"status": "ok"}


@router.get("/health/live", summary="Liveness Probe")
def liveness() -> dict[str, str]:
    """Kubernetes/Render liveness probe - returns 200 if the process is running."""
    return {"status": "alive"}


@router.get("/health/ready", summary="Readiness Probe")
def readiness(db: Session = Depends(get_db)) -> JSONResponse:
    """Readiness probe - checks DB connectivity. Returns 503 if not ready."""
    try:
        db.execute(__import__('sqlalchemy').text("SELECT 1"))
        return JSONResponse(status_code=status.HTTP_200_OK, content={"status": "ready", "database": "ok"})
    except Exception as exc:
        logger.error("Readiness check failed: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "not_ready", "database": "unreachable"},
        )
