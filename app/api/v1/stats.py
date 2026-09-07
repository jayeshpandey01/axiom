"""Dashboard statistics and telemetry aggregation endpoints."""

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import ScanJob, ScanResult, Target
from app.rate_limit import enforce_rate_limit
from app.security import Principal

router = APIRouter(tags=["Stats"])


@router.get("", summary="Get Platform Dashboard Statistics")
def get_stats(
    _: Principal = Depends(enforce_rate_limit),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Return high-level dashboard metrics for the platform."""
    total_targets = db.scalar(select(func.count(Target.id))) or 0
    total_scans = db.scalar(select(func.count(ScanJob.id))) or 0

    # Counts by status
    status_counts_raw = db.execute(
        select(ScanJob.status, func.count(ScanJob.id)).group_by(ScanJob.status)
    ).all()
    status_counts = {str(row[0].value if hasattr(row[0], "value") else row[0]): row[1] for row in status_counts_raw}

    # Counts by profile
    profile_counts_raw = db.execute(
        select(ScanJob.profile, func.count(ScanJob.id)).group_by(ScanJob.profile)
    ).all()
    profile_counts = {str(row[0]): row[1] for row in profile_counts_raw}

    total_results = db.scalar(select(func.count(ScanResult.id))) or 0

    return {
        "targets_count": total_targets,
        "scans_count": total_scans,
        "results_count": total_results,
        "scans_by_status": status_counts,
        "scans_by_profile": profile_counts,
    }
