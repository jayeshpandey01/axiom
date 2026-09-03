"""Axiom Cloud Telemetry & Observability Client (axiomhq/axiom-py)."""

import logging
from datetime import datetime, timezone
from typing import Any

import axiom_py

from app.core.config import get_settings

logger = logging.getLogger("app.telemetry.axiom")


class AxiomTelemetryClient:
    """Encapsulates Axiom cloud event streaming for audit logs and scan analytics."""

    def __init__(
        self,
        token: str | None = None,
        dataset: str | None = None,
        url: str | None = None,
    ):
        settings = get_settings()
        self.token = token or settings.axiom_token
        self.dataset = dataset or settings.axiom_dataset
        self.url = url or settings.axiom_url
        self._client: axiom_py.Client | None = None

        if self.token:
            try:
                if self.url:
                    self._client = axiom_py.Client(token=self.token, url=self.url)
                else:
                    self._client = axiom_py.Client(token=self.token)
                logger.info("Axiom telemetry client initialized for dataset '%s'", self.dataset)
            except Exception as exc:
                logger.warning("Failed to initialize Axiom client: %s", exc)
                self._client = None

    @property
    def is_enabled(self) -> bool:
        """Return True if Axiom client is successfully initialized and ready to stream."""
        return self._client is not None

    def ingest_events(self, events: list[dict[str, Any]]) -> bool:
        """Stream a list of event dictionaries to the configured Axiom dataset.

        Returns True on success, False if skipped or errored. Errors are suppressed
        to ensure telemetry never blocks production scan execution.
        """
        if not self.is_enabled or not events:
            return False

        try:
            self._client.ingest_events(dataset=self.dataset, events=events)
            return True
        except Exception as exc:
            logger.warning("Axiom event ingestion error: %s", exc)
            return False

    def ingest_audit_event(
        self,
        actor_role: str,
        action: str,
        resource_type: str,
        resource_id: str,
        created_at: datetime | None = None,
    ) -> bool:
        """Stream an administrative security audit event to Axiom."""
        ts = (created_at or datetime.now(timezone.utc)).isoformat()
        event = {
            "_time": ts,
            "event_type": "security_audit",
            "actor_role": actor_role,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
        }
        return self.ingest_events([event])

    def ingest_scan_telemetry(
        self,
        scan_id: str,
        profile: str,
        target_id: str | None = None,
        status: str = "completed",
        summary: dict[str, Any] | None = None,
        failure_reason: str | None = None,
    ) -> bool:
        """Stream scan lifecycle telemetry and finding aggregates to Axiom."""
        ts = datetime.now(timezone.utc).isoformat()
        telemetry: dict[str, Any] = {
            "_time": ts,
            "event_type": "scan_telemetry",
            "scan_id": str(scan_id),
            "profile": profile,
            "target_id": str(target_id) if target_id else None,
            "status": status,
        }

        if failure_reason:
            telemetry["failure_reason"] = failure_reason

        if summary:
            if "risk_summary" in summary and isinstance(summary["risk_summary"], dict):
                telemetry["risk_summary"] = summary["risk_summary"]
                telemetry["total_findings"] = summary["risk_summary"].get("total", 0)
                telemetry["critical_count"] = summary["risk_summary"].get("critical", 0)
                telemetry["high_count"] = summary["risk_summary"].get("high", 0)

            if "scanned_files_count" in summary:
                telemetry["scanned_files_count"] = summary["scanned_files_count"]

            if "total_rules_evaluated" in summary:
                telemetry["total_rules_evaluated"] = summary["total_rules_evaluated"]

        return self.ingest_events([telemetry])


_axiom_client: AxiomTelemetryClient | None = None


def get_axiom_client() -> AxiomTelemetryClient:
    """Return the global singleton AxiomTelemetryClient instance."""
    global _axiom_client
    if _axiom_client is None:
        _axiom_client = AxiomTelemetryClient()
    return _axiom_client
