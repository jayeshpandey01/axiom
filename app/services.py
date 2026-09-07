"""Backward-compatible re-export layer.

All service logic has been moved to app/services/ sub-modules.
This module re-exports everything for backward compatibility with
existing tests and any external code that imports from app.services.
"""

from app.services.audit_service import list_audit_events, record_audit
from app.services.scan_service import (
    cancel_scan,
    claim_next_scan,
    complete_scan,
    fail_scan,
    get_scan,
    list_scans,
    queue_scan,
    retry_scan,
)
from app.services.target_service import create_target, get_target, list_targets

__all__ = [
    "create_target",
    "get_target",
    "list_targets",
    "queue_scan",
    "get_scan",
    "list_scans",
    "cancel_scan",
    "retry_scan",
    "claim_next_scan",
    "complete_scan",
    "fail_scan",
    "record_audit",
    "list_audit_events",
]
