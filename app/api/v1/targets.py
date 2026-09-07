"""Target management router - registration, listing, and retrieval."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.rate_limit import enforce_rate_limit
from app.schemas import TargetCreate, TargetRead
from app.security import Principal
from app.services.audit_service import record_audit
from app.services.target_service import create_target, get_target, list_targets

router = APIRouter(tags=["Targets"])


@router.post("", response_model=TargetRead, status_code=status.HTTP_201_CREATED, summary="Register Authorized Target")
def post_target(
    payload: TargetCreate,
    principal: Principal = Depends(enforce_rate_limit),
    db: Session = Depends(get_db),
) -> TargetRead:
    """Register a new authorized scan target. Admin role required."""
    if principal.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin role required to register targets")
    target = create_target(db, payload)
    record_audit(db, actor_role=principal.role, action="target.created", resource_type="target", resource_id=str(target.id))
    return target


@router.get("", response_model=list[TargetRead], summary="List Registered Targets")
def get_targets(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    principal: Principal = Depends(enforce_rate_limit),
    db: Session = Depends(get_db),
) -> list[TargetRead]:
    """List all registered authorized targets with pagination. Admin role required."""
    if principal.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin role required")
    return list_targets(db, skip=skip, limit=limit)


@router.get("/{target_id}", response_model=TargetRead, summary="Get Target Details")
def get_target_detail(
    target_id: UUID,
    principal: Principal = Depends(enforce_rate_limit),
    db: Session = Depends(get_db),
) -> TargetRead:
    """Retrieve a specific registered target by ID."""
    if principal.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin role required")
    target = get_target(db, target_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="target not found")
    return target
