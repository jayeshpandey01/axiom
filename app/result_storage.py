"""Encrypted raw-result storage. Only controller-side services may call this module."""
import hashlib
import uuid
from datetime import UTC, datetime, timedelta

import boto3
from cryptography.fernet import Fernet
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import ResultArtifact, ScanJob, ScanResult, ScanStatus


def _client():
    settings = get_settings()
    return boto3.client("s3", region_name=settings.result_storage_region, endpoint_url=settings.result_storage_endpoint_url)


def _fernet() -> Fernet:
    key = get_settings().result_encryption_key
    if not key:
        raise RuntimeError("RESULT_ENCRYPTION_KEY is required before storing raw results")
    return Fernet(key.encode())


def persist_completed_result(db: Session, *, job: ScanJob, summary: dict, raw_artifact: bytes | None = None) -> ScanResult:
    """Persist normalized result metadata and optionally an encrypted raw artifact.

    The caller must have already validated controller identity and job state.
    """
    if job.status == ScanStatus.cancelled:
        raise ValueError("cannot persist a cancelled scan")
    result = db.scalar(select(ScanResult).where(ScanResult.scan_job_id == job.id))
    if result is None:
        result = ScanResult(scan_job_id=job.id, summary=summary)
        db.add(result)
        db.flush()
    else:
        result.summary = summary
    job.status = ScanStatus.completed

    if raw_artifact is not None and result.artifact is None:
        settings = get_settings()
        if not settings.result_storage_bucket:
            raise RuntimeError("RESULT_STORAGE_BUCKET is required before storing raw results")
        encrypted = _fernet().encrypt(raw_artifact)
        key = f"raw-results/{job.id}/{uuid.uuid4()}.bin"
        put_args = {"Bucket": settings.result_storage_bucket, "Key": key, "Body": encrypted, "ContentType": "application/octet-stream"}
        if settings.result_storage_kms_key_id:
            put_args.update({"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": settings.result_storage_kms_key_id})
        _client().put_object(**put_args)
        result.artifact = ResultArtifact(
            object_key=key,
            sha256=hashlib.sha256(raw_artifact).hexdigest(),
            byte_count=len(raw_artifact),
            expires_at=datetime.now(UTC) + timedelta(days=settings.result_retention_days),
        )
    db.commit()
    db.refresh(result)
    return result


def purge_expired_artifacts(db: Session) -> int:
    """Delete expired encrypted objects and retain tombstone metadata for auditing."""
    settings = get_settings()
    now = datetime.now(UTC)
    artifacts = db.scalars(select(ResultArtifact).where(ResultArtifact.deleted_at.is_(None), ResultArtifact.expires_at <= now)).all()
    for artifact in artifacts:
        _client().delete_object(Bucket=settings.result_storage_bucket, Key=artifact.object_key)
        artifact.deleted_at = now
    db.commit()
    return len(artifacts)
