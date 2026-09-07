"""Target management service layer."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Target
from app.schemas import TargetCreate


def create_target(db: Session, payload: TargetCreate) -> Target:
    existing = db.scalar(select(Target).where(Target.value == payload.value))
    if existing:
        return existing
    target_data = payload.model_dump()
    target_data.pop("target_type", None)
    target = Target(**target_data)
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


def get_target(db: Session, target_id) -> Target | None:
    return db.get(Target, target_id)


def list_targets(db: Session, skip: int = 0, limit: int = 50) -> list[Target]:
    return list(db.scalars(select(Target).order_by(Target.created_at.desc()).offset(skip).limit(limit)).all())
