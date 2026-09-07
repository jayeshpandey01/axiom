"""Scan lifecycle service layer — queue, claim, complete, fail, cancel, retry."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ScanJob, ScanResult, ScanStatus, Target
from app.result_storage import persist_completed_result
from app.schemas import SASTScanCreate, ScanCreate
from app.telemetry import get_axiom_client


def queue_scan(db: Session, payload: ScanCreate | SASTScanCreate, idempotency_key: str | None) -> ScanJob:
    if idempotency_key:
        existing = db.scalar(select(ScanJob).where(ScanJob.idempotency_key == idempotency_key))
        if existing:
            return existing
    target = db.get(Target, payload.target_id)
    if target is None:
        raise LookupError("target not found")
    job = ScanJob(
        target_id=payload.target_id,
        profile=payload.profile,
        idempotency_key=idempotency_key,
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def get_scan(db: Session, scan_id) -> ScanJob | None:
    return db.get(ScanJob, scan_id)


def list_scans(
    db: Session,
    status: str | None = None,
    profile: str | None = None,
    target_id=None,
    skip: int = 0,
    limit: int = 50,
) -> list[ScanJob]:
    q = select(ScanJob).order_by(ScanJob.created_at.desc())
    if status:
        q = q.where(ScanJob.status == status)
    if profile:
        q = q.where(ScanJob.profile == profile)
    if target_id:
        q = q.where(ScanJob.target_id == target_id)
    return list(db.scalars(q.offset(skip).limit(limit)).all())


def cancel_scan(db: Session, job: ScanJob) -> ScanJob:
    if job.status in {ScanStatus.completed, ScanStatus.failed, ScanStatus.cancelled}:
        return job
    job.status = ScanStatus.cancelled
    db.commit()
    db.refresh(job)
    get_axiom_client().ingest_scan_telemetry(
        scan_id=str(job.id),
        profile=job.profile,
        target_id=str(job.target_id) if job.target_id else None,
        status="cancelled",
    )
    return job


def retry_scan(db: Session, job: ScanJob) -> ScanJob:
    """Re-queue a failed or cancelled scan job."""
    if job.status not in {ScanStatus.failed, ScanStatus.cancelled}:
        raise ValueError("only failed or cancelled scans can be retried")
    new_job = ScanJob(
        target_id=job.target_id,
        profile=job.profile,
    )
    db.add(new_job)
    db.commit()
    db.refresh(new_job)
    return new_job


def claim_next_scan(db: Session) -> ScanJob | None:
    job = db.scalar(
        select(ScanJob).where(ScanJob.status == ScanStatus.queued).order_by(ScanJob.created_at).limit(1).with_for_update(skip_locked=True)
    )
    if job is None:
        return None
    job.status = ScanStatus.running
    db.commit()
    db.refresh(job)
    return job


def complete_scan(db: Session, job: ScanJob, summary: dict, raw_artifact: bytes | None = None) -> ScanResult:
    res = persist_completed_result(db, job=job, summary=summary, raw_artifact=raw_artifact)
    get_axiom_client().ingest_scan_telemetry(
        scan_id=str(job.id),
        profile=job.profile,
        target_id=str(job.target_id) if job.target_id else None,
        status="completed",
        summary=summary,
    )
    return res


def fail_scan(db: Session, job: ScanJob, reason: str) -> ScanJob:
    if job.status in {ScanStatus.completed, ScanStatus.cancelled}:
        raise ValueError("cannot fail a terminal scan")
    job.status = ScanStatus.failed
    job.failure_reason = reason
    db.commit()
    db.refresh(job)
    get_axiom_client().ingest_scan_telemetry(
        scan_id=str(job.id),
        profile=job.profile,
        target_id=str(job.target_id) if job.target_id else None,
        status="failed",
        failure_reason=reason,
    )
    return job
