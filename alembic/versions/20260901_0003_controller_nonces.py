"""controller request nonces

Revision ID: 20260901_0003
Revises: 20260901_0002
Create Date: 2026-09-01
"""
from alembic import op
import sqlalchemy as sa

revision = "20260901_0003"
down_revision = "20260901_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("controller_nonces", sa.Column("nonce", sa.String(length=80), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.PrimaryKeyConstraint("nonce"))
    op.create_index("ix_controller_nonces_expires_at", "controller_nonces", ["expires_at"])


def downgrade() -> None:
    op.drop_table("controller_nonces")
