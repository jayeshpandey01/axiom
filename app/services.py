from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditEvent, ScanJob, ScanResult, ScanStatus, Target
from app.result_storage import persist_completed_result
from app.schemas import SASTScanCreate, ScanCreate, TargetCreate
from app.telemetry import get_axiom_client


def create_target(db: Session, payload: TargetCreate) -> Target:
    existing = db.scalar(select(Target).where(Target.value == payload.value))
    if existing:
        return existing
    target = Target(**payload.model_dump())
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


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


def record_audit(db: Session, *, actor_role: str, action: str, resource_type: str, resource_id: str, detail: str | None = None) -> None:
    db.add(AuditEvent(actor_role=actor_role, action=action, resource_type=resource_type, resource_id=resource_id, detail=detail))
    db.commit()
    get_axiom_client().ingest_audit_event(
        actor_role=actor_role,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
    )


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
