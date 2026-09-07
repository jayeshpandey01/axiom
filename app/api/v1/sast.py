"""SAST scan management router."""

from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.sanitizer import sanitize_error_logs as _sanitize_error_logs
from app.db import get_db
from app.github_dispatcher import trigger_cloud_scanner_if_needed
from app.models import ScanResult
from app.rate_limit import enforce_rate_limit
from app.schemas import SASTScanCreate, ScanRead, ScanResultRead
from app.security import Principal
from app.services.audit_service import record_audit
from app.services.scan_service import cancel_scan, get_scan, list_scans, queue_scan, retry_scan

router = APIRouter(tags=["SAST Scans"])




@router.get("/scans", response_model=list[ScanRead], summary="List SAST Scans")
def get_sast_scans(
    scan_status: str | None = Query(default=None, alias="status"),
    profile: str | None = Query(default=None),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    _: Principal = Depends(enforce_rate_limit),
    db: Session = Depends(get_db),
) -> list[ScanRead]:
    """List SAST scan jobs with optional filters and pagination."""
    return list_scans(db, status=scan_status, profile=profile, skip=skip, limit=limit)


@router.post("/scans", response_model=ScanRead, status_code=status.HTTP_202_ACCEPTED, summary="Queue SAST Code Analysis Job")
def post_sast_scan(
    payload: SASTScanCreate,
    background_tasks: BackgroundTasks,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    principal: Principal = Depends(enforce_rate_limit),
    db: Session = Depends(get_db),
) -> ScanRead:
    try:
        scan = queue_scan(db, payload, idempotency_key)
        record_audit(db, actor_role=principal.role, action="sast_scan.queued", resource_type="scan", resource_id=str(scan.id))
        background_tasks.add_task(trigger_cloud_scanner_if_needed)
        return scan
    except LookupError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error)) from error


@router.get("/scans/{scan_id}", response_model=ScanRead, summary="Get SAST Scan Status")
def get_sast_scan(
    scan_id: UUID,
    _: Principal = Depends(enforce_rate_limit),
    db: Session = Depends(get_db),
) -> ScanRead:
    scan = get_scan(db, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return scan


@router.post("/scans/{scan_id}/cancel", response_model=ScanRead, summary="Cancel SAST Scan")
def post_sast_cancel(
    scan_id: UUID,
    principal: Principal = Depends(enforce_rate_limit),
    db: Session = Depends(get_db),
) -> ScanRead:
    scan = get_scan(db, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    scan = cancel_scan(db, scan)
    record_audit(db, actor_role=principal.role, action="sast_scan.cancelled", resource_type="scan", resource_id=str(scan.id))
    return scan


@router.post("/scans/{scan_id}/retry", response_model=ScanRead, summary="Retry Failed SAST Scan")
def post_sast_retry(
    scan_id: UUID,
    background_tasks: BackgroundTasks,
    principal: Principal = Depends(enforce_rate_limit),
    db: Session = Depends(get_db),
) -> ScanRead:
    scan = get_scan(db, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    try:
        new_scan = retry_scan(db, scan)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error
    record_audit(db, actor_role=principal.role, action="sast_scan.retried", resource_type="scan", resource_id=str(new_scan.id))
    background_tasks.add_task(trigger_cloud_scanner_if_needed)
    return new_scan


@router.get("/scans/{scan_id}/result", response_model=ScanResultRead, summary="Retrieve Normalized SAST Findings")
def get_sast_result(
    scan_id: UUID,
    _: Principal = Depends(enforce_rate_limit),
    db: Session = Depends(get_db),
) -> ScanResultRead:
    scan = get_scan(db, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    if scan.status == "failed":
        return ScanResultRead(
            id=scan.id,
            scan_job_id=scan.id,
            summary={"status": "failed"},
            created_at=scan.updated_at,
            artifact=None,
            error_logs=_sanitize_error_logs(scan.failure_reason),
        )
    result = db.query(ScanResult).filter(ScanResult.scan_job_id == scan_id).first()
    if result is None:
        if scan.status in ("queued", "dispatching", "running"):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="scan is still processing")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan result not found")
    return result


@router.get("/profiles", summary="List Available SAST Profiles")
def get_sast_profiles() -> dict:
    from app.api.v1.profiles import get_sast_profiles as _get
    return _get()
