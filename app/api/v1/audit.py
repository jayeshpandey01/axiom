"""Audit events and compliance log router."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.rate_limit import enforce_rate_limit
from app.security import Principal
from app.services.audit_service import list_audit_events

router = APIRouter(tags=["Audit"])


@router.get("", summary="List Audit Events")
def get_audit_events(
    principal: Principal = Depends(enforce_rate_limit),
    db: Session = Depends(get_db),
) -> list[dict[str, str | None]]:
    """List the 100 most recent audit events. Admin role required."""
    if principal.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin role required")
    events = list_audit_events(db)
    return [
        {
            "id": str(event.id),
            "action": event.action,
            "resource_type": event.resource_type,
            "resource_id": event.resource_id,
            "detail": event.detail,
            "created_at": event.created_at.isoformat(),
        }
        for event in events
    ]
