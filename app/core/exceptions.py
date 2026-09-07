"""Centralized exception handlers for the Axiom Security Platform API."""

import logging

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("app.exceptions")


def _error_envelope(status_code: int, detail: str, error_type: str = "api_error") -> dict:
    return {"error": {"type": error_type, "detail": detail, "status": status_code}}


def register_exception_handlers(app: FastAPI) -> None:
    """Register all global exception handlers on the FastAPI application instance."""

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "unknown")
        logger.warning("HTTP %d at %s [req_id=%s]: %s", exc.status_code, request.url.path, request_id, exc.detail)
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_envelope(exc.status_code, str(exc.detail)),
            headers={"X-Request-ID": request_id},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "unknown")
        errors = exc.errors()
        detail = "; ".join(f"{'.'.join(str(loc) for loc in e['loc'])}: {e['msg']}" for e in errors)
        logger.warning("Validation error at %s [req_id=%s]: %s", request.url.path, request_id, detail)
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=_error_envelope(status.HTTP_422_UNPROCESSABLE_ENTITY, detail, "validation_error"),
            headers={"X-Request-ID": request_id},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "unknown")
        logger.error("Unhandled exception at %s [req_id=%s]: %s", request.url.path, request_id, exc, exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=_error_envelope(status.HTTP_500_INTERNAL_SERVER_ERROR, "An internal server error occurred."),
            headers={"X-Request-ID": request_id},
        )
