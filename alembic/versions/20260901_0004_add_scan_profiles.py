"""Alembic no-op migration: document addition of new scan profiles.

New profiles added to SUPPORTED_PROFILES and SAFE_PROFILES in application code:
  - network-portscan  (nmap -sV -T4)
  - fast-portscan     (masscan --rate=1000)
  - content-discovery (ffuf)
  - vuln-assessment   (nuclei)

No DDL changes are required. The scan_jobs.profile column is String(64) which
can store any of the new profile names. This migration exists purely for audit
and documentation purposes.
"""
revision = "20260901_0004"
down_revision = "20260901_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # No schema changes required. New profiles are enforced at the application layer.
    pass


def downgrade() -> None:
    pass
