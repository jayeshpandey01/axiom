from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.controller_auth import require_controller
from app.db import get_db
from app.github_dispatcher import trigger_cloud_scanner_if_needed
from app.models import AuditEvent, ScanJob, ScanResult
from app.rate_limit import enforce_rate_limit
from app.result_storage import persist_completed_result
from app.schemas import (
    ControllerCompletion,
    ControllerFailure,
    ControllerJobRead,
    SASTScanCreate,
    ScanCreate,
    ScanRead,
    ScanResultRead,
    TargetCreate,
    TargetRead,
)
from app.security import Principal
from app.services import cancel_scan, claim_next_scan, create_target, fail_scan, queue_scan, record_audit


@asynccontextmanager
async def lifespan(_: FastAPI):
    from app.core.config import get_settings

    get_settings().validate_production()
    yield


tags_metadata = [
    {
        "name": "Targets",
        "description": "Authorized target registration and asset scope validation.",
    },
    {
        "name": "DAST Scans",
        "description": "Dynamic Application Security Testing & Network Scanning (httpx, nmap, masscan, ffuf, nuclei).",
    },
    {
        "name": "SAST Scans (Joern CPG, Semgrep & TruffleHog)",
        "description": "Static Application Security Testing & Secret Auditing (Joern CPG taint engine, Semgrep rule engine & TruffleHog secrets engine).",
    },
    {
        "name": "Audit",
        "description": "Administrative security audit logs and compliance event tracking.",
    },
    {
        "name": "Operational",
        "description": "Health checks and service status probes.",
    },
]

app = FastAPI(
    title="Authorized Scan Orchestrator",
    description="FastAPI service for scheduling authorized DAST (network & web) and SAST (source code, secrets & Code Property Graph) security testing jobs.",
    version="0.2.0",
    openapi_tags=tags_metadata,
    lifespan=lifespan,
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


# ==============================================================================
# 1. Operational Endpoints
# ==============================================================================


@app.get("/health", tags=["Operational"], summary="Health Check")
def health() -> dict[str, str]:
    return {"status": "ok"}


# ==============================================================================
# 2. Targets Management
# ==============================================================================


@app.post(
    "/v1/targets", response_model=TargetRead, status_code=status.HTTP_201_CREATED, tags=["Targets"], summary="Register Authorized Target"
)
def post_target(payload: TargetCreate, principal: Principal = Depends(enforce_rate_limit), db: Session = Depends(get_db)) -> TargetRead:
    if principal.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin role required to register targets")
    target = create_target(db, payload)
    record_audit(db, actor_role=principal.role, action="target.created", resource_type="target", resource_id=str(target.id))
    return target


# ==============================================================================
# 3. DAST (Dynamic Application & Network) Scans
# ==============================================================================


@app.get("/v1/profiles", tags=["DAST Scans"], summary="List Available DAST Profiles")
def get_dast_profiles() -> dict[str, Any]:
    """Retrieve all supported DAST scan profiles and scanner tools."""
    return {
        "dast_profiles": [
            {"profile": "recon", "scanner": "httpx", "purpose": "Fast HTTP service, security headers, and title discovery"},
            {
                "profile": "web-discovery",
                "scanner": "httpx",
                "purpose": "Comprehensive HTTP/HTTPS port, technology, and vulnerability discovery",
            },
            {"profile": "network-portscan", "scanner": "nmap", "purpose": "Detailed TCP service and version detection (nmap -sV -T4)"},
            {"profile": "fast-portscan", "scanner": "masscan", "purpose": "High-speed full port availability scan (masscan)"},
            {"profile": "content-discovery", "scanner": "ffuf", "purpose": "Web directory, route, and endpoint enumeration via fuzzing"},
            {
                "profile": "vuln-assessment",
                "scanner": "nuclei",
                "purpose": "Template-based vulnerability detection (info through critical severity)",
            },
        ]
    }


@app.post("/v1/scans", response_model=ScanRead, status_code=status.HTTP_202_ACCEPTED, tags=["DAST Scans"], summary="Queue DAST Scan Job")
def post_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    principal: Principal = Depends(enforce_rate_limit),
    db: Session = Depends(get_db),
) -> ScanRead:
    try:
        scan = queue_scan(db, payload, idempotency_key)
        record_audit(db, actor_role=principal.role, action="scan.queued", resource_type="scan", resource_id=str(scan.id))
        background_tasks.add_task(trigger_cloud_scanner_if_needed)
        return scan
    except LookupError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error)) from error


@app.get("/v1/scans/{scan_id}", response_model=ScanRead, tags=["DAST Scans"], summary="Get DAST Scan Status")
def get_scan(scan_id: UUID, _: Principal = Depends(enforce_rate_limit), db: Session = Depends(get_db)) -> ScanRead:
    scan = db.get(ScanJob, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return scan


@app.post("/v1/scans/{scan_id}/cancel", response_model=ScanRead, tags=["DAST Scans"], summary="Cancel DAST Scan")
def post_cancel(scan_id: UUID, principal: Principal = Depends(enforce_rate_limit), db: Session = Depends(get_db)) -> ScanRead:
    scan = db.get(ScanJob, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    scan = cancel_scan(db, scan)
    record_audit(db, actor_role=principal.role, action="scan.cancelled", resource_type="scan", resource_id=str(scan.id))
    return scan


@app.get("/v1/scans/{scan_id}/result", response_model=ScanResultRead, tags=["DAST Scans"], summary="Get DAST Scan Results")
def get_result(scan_id: UUID, _: Principal = Depends(enforce_rate_limit), db: Session = Depends(get_db)) -> ScanResultRead:
    scan = db.get(ScanJob, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")

    if scan.status == "failed":
        return ScanResultRead(
            id=scan.id,
            scan_job_id=scan.id,
            summary={"status": "failed"},
            created_at=scan.updated_at,
            artifact=None,
            error_logs=scan.failure_reason,
        )

    result = db.query(ScanResult).filter(ScanResult.scan_job_id == scan_id).first()
    if result is None:
        if scan.status in ("queued", "dispatching", "running"):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="scan is still processing")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan result not found")
    return result


# ==============================================================================
# 4. SAST (Static Application Security Testing & Secret Audits) [NEW SECTION]
# ==============================================================================


@app.get("/v1/sast/profiles", tags=["SAST Scans (Joern CPG, Semgrep & TruffleHog)"], summary="List Available SAST Profiles")
def get_sast_profiles() -> dict[str, Any]:
    """Retrieve supported SAST profiles, query bundles, and language engines."""
    return {
        "sast_profiles": [
            {
                "profile": "sast-joern",
                "engine": "Joern CPG",
                "languages": ["C", "C++", "Java", "Kotlin", "JavaScript", "TypeScript", "Python", "Go", "PHP", "Binary/LLVM"],
                "capabilities": [
                    "AST/CFG/PDG graph queries",
                    "Inter-procedural taint analysis",
                    "Fuzzy build-free parsing",
                    "Pre-scan directory filtering",
                ],
                "purpose": "Static application security testing and dataflow vulnerability discovery via Code Property Graphs",
            },
            {
                "profile": "sast-semgrep",
                "engine": "Semgrep",
                "languages": [
                    "Python",
                    "JavaScript",
                    "TypeScript",
                    "Java",
                    "Go",
                    "C",
                    "C++",
                    "Ruby",
                    "PHP",
                    "Rust",
                    "Dockerfile",
                    "Terraform",
                ],
                "capabilities": [
                    "Fast semantic pattern matching",
                    "OWASP Top 10 & CWE rule packs",
                    "Hardcoded secrets detection",
                    "Multi-language framework security audits",
                ],
                "purpose": "High-speed semantic AST pattern matching and comprehensive vulnerability rule scanning",
            },
            {
                "profile": "sast-trufflehog",
                "engine": "TruffleHog",
                "languages": ["All Languages", "Configuration Files", "Git History", "Environment Files"],
                "capabilities": [
                    "800+ secret detectors",
                    "Active live credential verification",
                    "High-entropy key analysis",
                    "Safe secret masking & redaction",
                ],
                "purpose": "Automated secret scanning and live API key/credential leak verification",
            },
        ]
    }


@app.post(
    "/v1/sast/scans",
    response_model=ScanRead,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["SAST Scans (Joern CPG, Semgrep & TruffleHog)"],
    summary="Queue SAST Code Analysis Job",
)
def post_sast_scan(
    payload: SASTScanCreate,
    background_tasks: BackgroundTasks,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    principal: Principal = Depends(enforce_rate_limit),
    db: Session = Depends(get_db),
) -> ScanRead:
    """Submit an authorized source code target for SAST analysis (Joern CPG, Semgrep, or TruffleHog)."""
    try:
        scan = queue_scan(db, payload, idempotency_key)
        record_audit(db, actor_role=principal.role, action="sast_scan.queued", resource_type="scan", resource_id=str(scan.id))
        background_tasks.add_task(trigger_cloud_scanner_if_needed)
        return scan
    except LookupError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error)) from error


@app.get(
    "/v1/sast/scans/{scan_id}",
    response_model=ScanRead,
    tags=["SAST Scans (Joern CPG, Semgrep & TruffleHog)"],
    summary="Get SAST Scan Status",
)
def get_sast_scan(scan_id: UUID, _: Principal = Depends(enforce_rate_limit), db: Session = Depends(get_db)) -> ScanRead:
    """Check lifecycle status of a SAST analysis job."""
    return get_scan(scan_id=scan_id, _=_, db=db)


@app.post(
    "/v1/sast/scans/{scan_id}/cancel",
    response_model=ScanRead,
    tags=["SAST Scans (Joern CPG, Semgrep & TruffleHog)"],
    summary="Cancel SAST Scan",
)
def post_sast_cancel(scan_id: UUID, principal: Principal = Depends(enforce_rate_limit), db: Session = Depends(get_db)) -> ScanRead:
    """Cancel an active or queued SAST analysis job."""
    return post_cancel(scan_id=scan_id, principal=principal, db=db)


@app.get(
    "/v1/sast/scans/{scan_id}/result",
    response_model=ScanResultRead,
    tags=["SAST Scans (Joern CPG, Semgrep & TruffleHog)"],
    summary="Get SAST Scan Results",
)
def get_sast_result(scan_id: UUID, _: Principal = Depends(enforce_rate_limit), db: Session = Depends(get_db)) -> ScanResultRead:
    """Retrieve normalized SAST vulnerability findings, code snippets, line numbers, and taint flows."""
    return get_result(scan_id=scan_id, _=_, db=db)


# ==============================================================================
# 5. Audit & Compliance
# ==============================================================================


@app.get("/v1/audit-events", tags=["Audit"], summary="List Audit Events")
def get_audit_events(principal: Principal = Depends(enforce_rate_limit), db: Session = Depends(get_db)) -> list[dict[str, str | None]]:
    if principal.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin role required")
    events = db.query(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(100).all()
    return [
        {
            "id": str(event.id),
            "action": event.action,
            "resource_type": event.resource_type,
            "resource_id": event.resource_id,
            "detail": event.detail,
        }
        for event in events
    ]


@app.post("/v1/internal/controller/jobs/claim", response_model=ControllerJobRead | None, include_in_schema=False)
async def claim_controller_job(request: Request, db: Session = Depends(get_db)) -> ControllerJobRead | None:
    await require_controller(request, db)
    job = claim_next_scan(db)
    if job is None:
        return None
    record_audit(db, actor_role="controller", action="scan.claimed", resource_type="scan", resource_id=str(job.id))
    return ControllerJobRead(
        id=job.id, target=job.target.value, profile=job.profile, authorization_reference=job.target.authorization_reference
    )


@app.post("/v1/internal/controller/jobs/{scan_id}/complete", response_model=ScanResultRead, include_in_schema=False)
async def complete_controller_job(
    scan_id: UUID, payload: ControllerCompletion, request: Request, db: Session = Depends(get_db)
) -> ScanResultRead:
    await require_controller(request, db)
    job = db.get(ScanJob, scan_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    if job.status != "running":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="scan is not running")
    result = persist_completed_result(db, job=job, summary=payload.summary)
    record_audit(db, actor_role="controller", action="scan.completed", resource_type="scan", resource_id=str(job.id))
    return result


@app.post("/v1/internal/controller/jobs/{scan_id}/fail", response_model=ScanRead, include_in_schema=False)
async def fail_controller_job(scan_id: UUID, payload: ControllerFailure, request: Request, db: Session = Depends(get_db)) -> ScanRead:
    await require_controller(request, db)
    job = db.get(ScanJob, scan_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    try:
        failed = fail_scan(db, job, payload.reason)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error
    record_audit(db, actor_role="controller", action="scan.failed", resource_type="scan", resource_id=str(job.id), detail=payload.reason)
    return failed


@app.get("/v1/internal/controller/jobs/{scan_id}/status", include_in_schema=False)
async def get_controller_job_status(scan_id: UUID, request: Request, db: Session = Depends(get_db)) -> dict[str, str]:
    await require_controller(request, db)
    job = db.get(ScanJob, scan_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return {"id": str(job.id), "status": job.status.value}
