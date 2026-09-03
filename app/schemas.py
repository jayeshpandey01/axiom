from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from app.scope import validate_target_scope

SAFE_PROFILES = {
    "recon",
    "web-discovery",
    "network-portscan",
    "fast-portscan",
    "content-discovery",
    "vuln-assessment",
}

# DAST profile literal used for standard /v1/scans endpoint
ProfileLiteral = Literal[
    "recon",
    "web-discovery",
    "network-portscan",
    "fast-portscan",
    "content-discovery",
    "vuln-assessment",
]

# SAST profile definitions for /v1/sast/scans
SAST_SAFE_PROFILES = {
    "sast-joern",
    "sast-semgrep",
    "sast-trufflehog",
}

SASTProfileLiteral = Literal[
    "sast-joern",
    "sast-semgrep",
    "sast-trufflehog",
]

# Union of all profiles used by controller worker
ALL_SAFE_PROFILES = SAFE_PROFILES | SAST_SAFE_PROFILES

AllProfileLiteral = Literal[
    "recon",
    "web-discovery",
    "network-portscan",
    "fast-portscan",
    "content-discovery",
    "vuln-assessment",
    "sast-joern",
    "sast-semgrep",
    "sast-trufflehog",
]


class TargetCreate(BaseModel):
    value: str = Field(min_length=1, max_length=253, examples=["example.com"])
    owner_reference: str = Field(min_length=3, max_length=200)
    authorization_reference: str = Field(min_length=3, max_length=200)

    @field_validator("value")
    @classmethod
    def normalize_target(cls, value: str) -> str:
        return validate_target_scope(value)


class TargetRead(BaseModel):
    id: UUID
    value: str
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanCreate(BaseModel):
    target_id: UUID
    profile: ProfileLiteral


class SASTScanCreate(BaseModel):
    target_id: UUID
    profile: SASTProfileLiteral = Field(default="sast-joern", description="SAST analysis profile (sast-joern or sast-semgrep)")
    rule_tags: list[str] | None = Field(default=None, description="Optional rule tags (e.g. ['sqli', 'rce', 'default'])")


class ScanRead(BaseModel):
    id: UUID
    target_id: UUID
    profile: str
    status: str
    controller_job_id: str | None
    failure_reason: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ArtifactRead(BaseModel):
    id: UUID
    sha256: str
    byte_count: int
    expires_at: datetime
    deleted_at: datetime | None

    model_config = {"from_attributes": True}


class ScanResultRead(BaseModel):
    id: UUID
    scan_job_id: UUID
    summary: dict
    created_at: datetime
    artifact: ArtifactRead | None
    error_logs: str | None = None

    model_config = {"from_attributes": True}


class ControllerJobRead(BaseModel):
    id: UUID
    target: str
    profile: AllProfileLiteral
    authorization_reference: str


class ControllerCompletion(BaseModel):
    summary: dict[str, Any] = Field(default_factory=dict, max_length=100)


class ControllerFailure(BaseModel):
    reason: str = Field(min_length=1, max_length=500)
