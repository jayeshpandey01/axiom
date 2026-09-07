"""align unique indices on targets, scan_results, and result_artifacts

Revision ID: 20260901_0005
Revises: 20260901_0004
Create Date: 2026-09-08
"""
from alembic import op

revision = "20260901_0005"
down_revision = "20260901_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("targets") as batch_op:
        batch_op.drop_index("ix_targets_value")
        batch_op.create_index("ix_targets_value", ["value"], unique=True)

    with op.batch_alter_table("scan_results") as batch_op:
        batch_op.drop_index("ix_scan_results_scan_job_id")
        batch_op.create_index("ix_scan_results_scan_job_id", ["scan_job_id"], unique=True)

    with op.batch_alter_table("result_artifacts") as batch_op:
        batch_op.drop_index("ix_result_artifacts_result_id")
        batch_op.create_index("ix_result_artifacts_result_id", ["result_id"], unique=True)


def downgrade() -> None:
    with op.batch_alter_table("result_artifacts") as batch_op:
        batch_op.drop_index("ix_result_artifacts_result_id")
        batch_op.create_index("ix_result_artifacts_result_id", ["result_id"], unique=False)

    with op.batch_alter_table("scan_results") as batch_op:
        batch_op.drop_index("ix_scan_results_scan_job_id")
        batch_op.create_index("ix_scan_results_scan_job_id", ["scan_job_id"], unique=False)

    with op.batch_alter_table("targets") as batch_op:
        batch_op.drop_index("ix_targets_value")
        batch_op.create_index("ix_targets_value", ["value"], unique=False)
