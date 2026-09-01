"""Background Maintenance & Stale Job Watchdog Worker.

Runs periodically on Render to:
1. Reap stuck or timed-out scan jobs where the controller disconnected or crashed.
2. Purge expired encrypted raw artifacts from S3/R2 storage.
"""
import logging
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.db import SessionLocal
from app.models import AuditEvent, ScanJob, ScanStatus
from app.result_storage import purge_expired_artifacts

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] worker: %(message)s")
logger = logging.getLogger("worker")

STALE_JOB_TIMEOUT_SECONDS = 3600  # 1 hour maximum duration for uncompleted scans


def reap_stale_jobs() -> int:
    """Find jobs stuck in running/dispatching state exceeding max timeout and mark as failed."""
    cutoff = datetime.now(UTC) - timedelta(seconds=STALE_JOB_TIMEOUT_SECONDS)
    reaped = 0

    with SessionLocal() as db:
        stale_jobs = db.scalars(
            select(ScanJob).where(
                ScanJob.status.in_([ScanStatus.running, ScanStatus.dispatching]),
                ScanJob.updated_at <= cutoff,
            )
        ).all()

        for job in stale_jobs:
            job.status = ScanStatus.failed
            job.failure_reason = f"Controller timeout: job exceeded maximum runtime ({STALE_JOB_TIMEOUT_SECONDS}s)"
            db.add(
                AuditEvent(
                    actor_role="worker-watchdog",
                    action="scan.timed_out",
                    resource_type="scan",
                    resource_id=str(job.id),
                    detail=job.failure_reason,
                )
            )
            reaped += 1

        if reaped > 0:
            db.commit()
            logger.warning("Reaped %d stale uncompleted scan job(s).", reaped)

    return reaped


def purge_results() -> int:
    """Purge expired raw scan artifacts from object storage."""
    with SessionLocal() as db:
        deleted = purge_expired_artifacts(db)
        if deleted:
            logger.info("Purged %d expired raw result artifact(s).", deleted)
        return deleted


def main() -> None:
    logger.info("Starting Background Maintenance Worker...")
    cycle = 0
    while True:
        try:
            # Check for stale jobs every 60 seconds (every 30 cycles at 2s sleep)
            if cycle % 30 == 0:
                reap_stale_jobs()

            # Hourly artifact purge (every 1800 cycles)
            if cycle % 1800 == 0:
                purge_results()

        except Exception as exc:
            logger.error("Maintenance cycle error: %s", exc)

        cycle += 1
        time.sleep(2)


if __name__ == "__main__":
    main()
