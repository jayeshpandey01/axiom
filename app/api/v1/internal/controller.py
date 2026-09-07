"""Hidden internal controller protocol endpoints (claim, complete, fail, status)."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.controller_auth import require_controller
from app.db import get_db
from app.models import ScanJob
from app.schemas import ControllerCompletion, ControllerFailure, ControllerJobRead, ScanRead, ScanResultRead
from app.services.audit_service import record_audit
from app.services.scan_service import claim_next_scan, complete_scan, fail_scan

router = APIRouter(include_in_schema=False)


@router.post("/jobs/claim", response_model=ControllerJobRead | None)
async def claim_controller_job(request: Request, db: Session = Depends(get_db)) -> ControllerJobRead | None:
    await require_controller(request, db)
    job = claim_next_scan(db)
    if job is None:
        return None
    record_audit(db, actor_role="controller", action="scan.claimed", resource_type="scan", resource_id=str(job.id))
    return ControllerJobRead(
        id=job.id, target=job.target.value, profile=job.profile, authorization_reference=job.target.authorization_reference
    )


@router.post("/jobs/{scan_id}/complete", response_model=ScanResultRead)
async def complete_controller_job(
    scan_id: UUID, payload: ControllerCompletion, request: Request, db: Session = Depends(get_db)
) -> ScanResultRead:
    await require_controller(request, db)
    job = db.get(ScanJob, scan_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    if job.status != "running":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="scan is not running")
    result = complete_scan(db, job=job, summary=payload.summary)
    record_audit(db, actor_role="controller", action="scan.completed", resource_type="scan", resource_id=str(job.id))
    return result


@router.post("/jobs/{scan_id}/fail", response_model=ScanRead)
async def fail_controller_job(
    scan_id: UUID, payload: ControllerFailure, request: Request, db: Session = Depends(get_db)
) -> ScanRead:
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


@router.get("/jobs/{scan_id}/status")
async def get_controller_job_status(
    scan_id: UUID, request: Request, db: Session = Depends(get_db)
) -> dict[str, str]:
    await require_controller(request, db)
    job = db.get(ScanJob, scan_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return {"id": str(job.id), "status": job.status.value}
