from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

from app.scope import validate_sast_target_scope, validate_target_scope

SAFE_PROFILES = {
    "recon",
    "web-discovery",
    "network-portscan",
    "fast-portscan",
    "content-discovery",
    "deep-content-discovery",
    "web-crawl",
    "vuln-assessment",
    "xss-scan",
    "dast-zap",
    "oob-interaction",
    "dns-recon",
    "subdomain-takeover",
    "smart-portscan",
    "waf-detect",
    "cors-audit",
    "crlf-scan",
    "ssti-scan",
}

# DAST profile literal used for standard /v1/scans endpoint
ProfileLiteral = Literal[
    "recon",
    "web-discovery",
    "network-portscan",
    "fast-portscan",
    "content-discovery",
    "deep-content-discovery",
    "web-crawl",
    "vuln-assessment",
    "xss-scan",
    "dast-zap",
    "oob-interaction",
    "dns-recon",
    "subdomain-takeover",
    "smart-portscan",
    "waf-detect",
    "cors-audit",
    "crlf-scan",
    "ssti-scan",
]

# SAST profile definitions for /v1/sast/scans
SAST_SAFE_PROFILES = {
    "sast-joern",
    "sast-semgrep",
    "sast-trufflehog",
    "sast-codeql",
    "sast-gitleaks",
}

SASTProfileLiteral = Literal[
    "sast-joern",
    "sast-semgrep",
    "sast-trufflehog",
    "sast-codeql",
    "sast-gitleaks",
]

# Union of all profiles used by controller worker
ALL_SAFE_PROFILES = SAFE_PROFILES | SAST_SAFE_PROFILES

AllProfileLiteral = Literal[
    "recon",
    "web-discovery",
    "network-portscan",
    "fast-portscan",
    "content-discovery",
    "deep-content-discovery",
    "web-crawl",
    "vuln-assessment",
    "xss-scan",
    "dast-zap",
    "oob-interaction",
    "dns-recon",
    "subdomain-takeover",
    "smart-portscan",
    "waf-detect",
    "cors-audit",
    "crlf-scan",
    "ssti-scan",
    "sast-joern",
    "sast-semgrep",
    "sast-trufflehog",
    "sast-codeql",
    "sast-gitleaks",
]


class TargetCreate(BaseModel):
    value: str = Field(min_length=1, max_length=253, examples=["example.com", "my-org/backend-service"])
    owner_reference: str = Field(min_length=3, max_length=200)
    authorization_reference: str = Field(min_length=3, max_length=200)
    target_type: Literal["network", "source_code"] = Field(
        default="network",
        description="Target type: 'network' for DAST scans (hostnames/IPs) or 'source_code' for SAST scans (local paths/git repos)",
    )

    @model_validator(mode="after")
    def validate_target_value(self) -> "TargetCreate":
        if self.target_type == "source_code":
            self.value = validate_sast_target_scope(self.value)
        else:
            self.value = validate_target_scope(self.value)
        return self


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
    profile: SASTProfileLiteral = Field(
        default="sast-joern",
        description="SAST analysis profile (sast-joern, sast-semgrep, sast-trufflehog, or sast-codeql)",
    )
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
