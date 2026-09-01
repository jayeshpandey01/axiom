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

# Shared profile literal used across request schemas and controller job schemas.
ProfileLiteral = Literal[
    "recon",
    "web-discovery",
    "network-portscan",
    "fast-portscan",
    "content-discovery",
    "vuln-assessment",
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

    model_config = {"from_attributes": True}


class ControllerJobRead(BaseModel):
    id: UUID
    target: str
    profile: ProfileLiteral
    authorization_reference: str


class ControllerCompletion(BaseModel):
    summary: dict[str, Any] = Field(default_factory=dict, max_length=100)


class ControllerFailure(BaseModel):
    reason: str = Field(min_length=1, max_length=500)
