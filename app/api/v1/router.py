"""Master v1 API router - composes all sub-routers."""

from fastapi import APIRouter

from app.api.v1.audit import router as audit_router
from app.api.v1.dast import router as dast_router
from app.api.v1.internal.controller import router as internal_router
from app.api.v1.profiles import router as profiles_router
from app.api.v1.sast import router as sast_router
from app.api.v1.stats import router as stats_router
from app.api.v1.targets import router as targets_router

v1_router = APIRouter()

v1_router.include_router(targets_router, prefix="/targets")
v1_router.include_router(dast_router, prefix="/scans")
v1_router.include_router(sast_router, prefix="/sast")
v1_router.include_router(audit_router, prefix="/audit-events")
v1_router.include_router(profiles_router, prefix="/profiles")
v1_router.include_router(stats_router, prefix="/stats")
v1_router.include_router(internal_router, prefix="/internal/controller")
