"""scan results and retained artifact metadata

Revision ID: 20260901_0002
Revises: 20260901_0001
Create Date: 2026-09-01
"""
from alembic import op
import sqlalchemy as sa

revision = "20260901_0002"
down_revision = "20260901_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("scan_results", sa.Column("id", sa.Uuid(), nullable=False), sa.Column("scan_job_id", sa.Uuid(), nullable=False), sa.Column("summary", sa.JSON(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False), sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"]), sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("scan_job_id"))
    op.create_index("ix_scan_results_scan_job_id", "scan_results", ["scan_job_id"])
    op.create_table("result_artifacts", sa.Column("id", sa.Uuid(), nullable=False), sa.Column("result_id", sa.Uuid(), nullable=False), sa.Column("object_key", sa.String(length=512), nullable=False), sa.Column("sha256", sa.String(length=64), nullable=False), sa.Column("byte_count", sa.Integer(), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True), sa.ForeignKeyConstraint(["result_id"], ["scan_results.id"]), sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("object_key"), sa.UniqueConstraint("result_id"))
    op.create_index("ix_result_artifacts_expires_at", "result_artifacts", ["expires_at"])
    op.create_index("ix_result_artifacts_result_id", "result_artifacts", ["result_id"])


def downgrade() -> None:
    op.drop_table("result_artifacts")
    op.drop_table("scan_results")
