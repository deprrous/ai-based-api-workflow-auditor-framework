"""add planning runs

Revision ID: 20260320_0008
Revises: 20260320_0007
Create Date: 2026-03-20 01:10:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260320_0008"
down_revision = "20260320_0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "planning_runs",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("scan_id", sa.String(length=64), nullable=False),
        sa.Column("mode", sa.String(length=32), nullable=False),
        sa.Column("provider_key", sa.String(length=64), nullable=False),
        sa.Column("apply", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("candidate_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("suggested_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("emitted_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("skipped_existing_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("queued_job_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("request_json", sa.JSON(), nullable=False),
        sa.Column("candidates_json", sa.JSON(), nullable=False),
        sa.Column("proposals_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scan_runs.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_planning_runs_scan_id", "planning_runs", ["scan_id"])
    op.create_index("ix_planning_runs_mode", "planning_runs", ["mode"])
    op.create_index("ix_planning_runs_provider_key", "planning_runs", ["provider_key"])
    op.create_index("ix_planning_runs_created_at", "planning_runs", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_planning_runs_created_at", table_name="planning_runs")
    op.drop_index("ix_planning_runs_provider_key", table_name="planning_runs")
    op.drop_index("ix_planning_runs_mode", table_name="planning_runs")
    op.drop_index("ix_planning_runs_scan_id", table_name="planning_runs")
    op.drop_table("planning_runs")
