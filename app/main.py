"""Axiom Security Platform — FastAPI application factory.

This module contains only application setup:
- App factory with metadata
- Middleware registration
- Router mounting
- Exception handler registration

All endpoint logic lives in app/api/v1/.
"""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.operational import router as operational_router
from app.api.v1.router import v1_router
from app.core.exceptions import register_exception_handlers
from app.middleware.request_id import RequestIDMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware


@asynccontextmanager
async def lifespan(_: FastAPI):
    from app.core.config import get_settings
    get_settings().validate_production()
    yield


tags_metadata = [
    {"name": "Targets", "description": "Authorized target registration and asset scope validation."},
    {"name": "DAST Scans", "description": "Dynamic Application Security Testing & Network Scanning."},
    {"name": "SAST Scans", "description": "Static Application Security Testing & Secret Auditing."},
    {"name": "Audit", "description": "Administrative security audit logs and compliance event tracking."},
    {"name": "Profiles", "description": "Available scanner profile listing."},
    {"name": "AI", "description": "AI-assisted security triage, vulnerability explanation, and remediation diff generation."},
    {"name": "Operational", "description": "Health checks and service status probes."},
]


def create_app() -> FastAPI:
    """Application factory."""
    application = FastAPI(
        title="Axiom Security Platform",
        description=(
            "Authorized Security Scan Orchestrator — DAST (network & web) and SAST "
            "(source code, secrets & Code Property Graph) security testing."
        ),
        version="0.3.0",
        openapi_tags=tags_metadata,
        lifespan=lifespan,
    )

    # --- Middleware (order matters: outermost = first to process request)
    application.add_middleware(RequestIDMiddleware)
    application.add_middleware(SecurityHeadersMiddleware)
    cors_origins = [
        origin.strip()
        for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8000").split(",")
        if origin.strip()
    ]
    application.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    # --- Exception handlers
    register_exception_handlers(application)

    # --- Routers
    application.include_router(operational_router)
    application.include_router(v1_router, prefix="/v1")

    return application


app = create_app()
