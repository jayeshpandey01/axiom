"""Audit event recording service layer."""

from sqlalchemy.orm import Session

from app.models import AuditEvent
from app.telemetry import get_axiom_client


def record_audit(
    db: Session,
    *,
    actor_role: str,
    action: str,
    resource_type: str,
    resource_id: str,
    detail: str | None = None,
) -> None:
    db.add(AuditEvent(actor_role=actor_role, action=action, resource_type=resource_type, resource_id=resource_id, detail=detail))
    db.commit()
    get_axiom_client().ingest_audit_event(
        actor_role=actor_role,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
    )


def list_audit_events(db: Session, limit: int = 100) -> list[AuditEvent]:
    from sqlalchemy import select
    return list(db.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)).all())
