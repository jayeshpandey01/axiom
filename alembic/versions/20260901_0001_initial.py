"""initial tables and audit events

Revision ID: 20260901_0001
Revises:
Create Date: 2026-09-01
"""
from alembic import op
import sqlalchemy as sa

revision = "20260901_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("targets", sa.Column("id", sa.Uuid(), nullable=False), sa.Column("value", sa.String(length=253), nullable=False), sa.Column("owner_reference", sa.String(length=200), nullable=False), sa.Column("authorization_reference", sa.String(length=200), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False), sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("value"))
    op.create_index("ix_targets_value", "targets", ["value"])
    op.create_table("scan_jobs", sa.Column("id", sa.Uuid(), nullable=False), sa.Column("target_id", sa.Uuid(), nullable=False), sa.Column("profile", sa.String(length=64), nullable=False), sa.Column("status", sa.Enum("queued", "dispatching", "running", "completed", "failed", "cancelled", name="scanstatus"), nullable=False), sa.Column("idempotency_key", sa.String(length=128), nullable=True), sa.Column("controller_job_id", sa.String(length=128), nullable=True), sa.Column("failure_reason", sa.Text(), nullable=True), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False), sa.ForeignKeyConstraint(["target_id"], ["targets.id"]), sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("idempotency_key"))
    op.create_index("ix_scan_jobs_status", "scan_jobs", ["status"])
    op.create_index("ix_scan_jobs_target_id", "scan_jobs", ["target_id"])
    op.create_table("audit_events", sa.Column("id", sa.Uuid(), nullable=False), sa.Column("actor_role", sa.String(length=32), nullable=False), sa.Column("action", sa.String(length=80), nullable=False), sa.Column("resource_type", sa.String(length=40), nullable=False), sa.Column("resource_id", sa.String(length=64), nullable=False), sa.Column("detail", sa.Text(), nullable=True), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False), sa.PrimaryKeyConstraint("id"))
    op.create_index("ix_audit_events_action", "audit_events", ["action"])
    op.create_index("ix_audit_events_actor_role", "audit_events", ["actor_role"])
    op.create_index("ix_audit_events_created_at", "audit_events", ["created_at"])


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("scan_jobs")
    op.drop_table("targets")
