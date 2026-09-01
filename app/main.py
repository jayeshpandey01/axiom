from contextlib import asynccontextmanager
from uuid import UUID

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.controller_auth import require_controller
from app.db import get_db
from app.github_dispatcher import trigger_cloud_scanner_if_needed
from app.models import AuditEvent, ScanJob, ScanResult
from app.rate_limit import enforce_rate_limit
from app.result_storage import persist_completed_result
from app.schemas import (
    ControllerCompletion,
    ControllerFailure,
    ControllerJobRead,
    ScanCreate,
    ScanRead,
    ScanResultRead,
    TargetCreate,
    TargetRead,
)
from app.security import Principal
from app.services import cancel_scan, claim_next_scan, create_target, fail_scan, queue_scan, record_audit


@asynccontextmanager
async def lifespan(_: FastAPI):
    from app.core.config import get_settings
    get_settings().validate_production()
    yield


app = FastAPI(title="Authorized Scan Orchestrator", version="0.1.0", lifespan=lifespan)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/health", tags=["operational"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/targets", response_model=TargetRead, status_code=status.HTTP_201_CREATED)
def post_target(payload: TargetCreate, principal: Principal = Depends(enforce_rate_limit), db: Session = Depends(get_db)) -> TargetRead:
    if principal.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin role required to register targets")
    target = create_target(db, payload)
    record_audit(db, actor_role=principal.role, action="target.created", resource_type="target", resource_id=str(target.id))
    return target


@app.post("/v1/scans", response_model=ScanRead, status_code=status.HTTP_202_ACCEPTED)
def post_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    principal: Principal = Depends(enforce_rate_limit),
    db: Session = Depends(get_db),
) -> ScanRead:
    try:
        scan = queue_scan(db, payload, idempotency_key)
        record_audit(db, actor_role=principal.role, action="scan.queued", resource_type="scan", resource_id=str(scan.id))
        background_tasks.add_task(trigger_cloud_scanner_if_needed)
        return scan
    except LookupError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error)) from error


@app.get("/v1/scans/{scan_id}", response_model=ScanRead)
def get_scan(scan_id: UUID, _: Principal = Depends(enforce_rate_limit), db: Session = Depends(get_db)) -> ScanRead:
    scan = db.get(ScanJob, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return scan


@app.post("/v1/scans/{scan_id}/cancel", response_model=ScanRead)
def post_cancel(scan_id: UUID, principal: Principal = Depends(enforce_rate_limit), db: Session = Depends(get_db)) -> ScanRead:
    scan = db.get(ScanJob, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    scan = cancel_scan(db, scan)
    record_audit(db, actor_role=principal.role, action="scan.cancelled", resource_type="scan", resource_id=str(scan.id))
    return scan


@app.get("/v1/scans/{scan_id}/result", response_model=ScanResultRead)
def get_result(scan_id: UUID, _: Principal = Depends(enforce_rate_limit), db: Session = Depends(get_db)) -> ScanResultRead:
    scan = db.get(ScanJob, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")

    if scan.status == "failed":
        return ScanResultRead(
            id=scan.id,
            scan_job_id=scan.id,
            summary={"status": "failed"},
            created_at=scan.updated_at,
            artifact=None,
            error_logs=scan.failure_reason
        )

    result = db.query(ScanResult).filter(ScanResult.scan_job_id == scan_id).first()
    if result is None:
        if scan.status in ("queued", "dispatching", "running"):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="scan is still processing")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan result not found")
    return result


@app.get("/v1/audit-events")
def get_audit_events(principal: Principal = Depends(enforce_rate_limit), db: Session = Depends(get_db)) -> list[dict[str, str | None]]:
    if principal.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin role required")
    events = db.query(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(100).all()
    return [{"id": str(event.id), "action": event.action, "resource_type": event.resource_type, "resource_id": event.resource_id, "detail": event.detail} for event in events]


@app.post("/v1/internal/controller/jobs/claim", response_model=ControllerJobRead | None, include_in_schema=False)
async def claim_controller_job(request: Request, db: Session = Depends(get_db)) -> ControllerJobRead | None:
    await require_controller(request, db)
    job = claim_next_scan(db)
    if job is None:
        return None
    record_audit(db, actor_role="controller", action="scan.claimed", resource_type="scan", resource_id=str(job.id))
    return ControllerJobRead(id=job.id, target=job.target.value, profile=job.profile, authorization_reference=job.target.authorization_reference)


@app.post("/v1/internal/controller/jobs/{scan_id}/complete", response_model=ScanResultRead, include_in_schema=False)
async def complete_controller_job(scan_id: UUID, payload: ControllerCompletion, request: Request, db: Session = Depends(get_db)) -> ScanResultRead:
    await require_controller(request, db)
    job = db.get(ScanJob, scan_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    if job.status != "running":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="scan is not running")
    result = persist_completed_result(db, job=job, summary=payload.summary)
    record_audit(db, actor_role="controller", action="scan.completed", resource_type="scan", resource_id=str(job.id))
    return result


@app.post("/v1/internal/controller/jobs/{scan_id}/fail", response_model=ScanRead, include_in_schema=False)
async def fail_controller_job(scan_id: UUID, payload: ControllerFailure, request: Request, db: Session = Depends(get_db)) -> ScanRead:
    await require_controller(request, db)
    job = db.get(ScanJob, scan_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    try:
        failed = fail_scan(db, job, payload.reason)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error
    record_audit(db, actor_role="controller", action="scan.failed", resource_type="scan", resource_id=str(job.id), detail=payload.reason)
    return failed


@app.get("/v1/internal/controller/jobs/{scan_id}/status", include_in_schema=False)
async def get_controller_job_status(scan_id: UUID, request: Request, db: Session = Depends(get_db)) -> dict[str, str]:
    await require_controller(request, db)
    job = db.get(ScanJob, scan_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return {"id": str(job.id), "status": job.status.value}
