"""add verifier jobs

Revision ID: 20260320_0004
Revises: 20260320_0003
Create Date: 2026-03-20 00:30:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260320_0004"
down_revision = "20260320_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "verifier_jobs",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("scan_id", sa.String(length=64), nullable=False),
        sa.Column("source_path_id", sa.String(length=120), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("worker_id", sa.String(length=120), nullable=True),
        sa.Column("verifier_run_id", sa.String(length=120), nullable=True),
        sa.Column("finding_id", sa.String(length=64), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scan_runs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["verifier_run_id"], ["verifier_runs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_verifier_jobs_scan_id", "verifier_jobs", ["scan_id"])
    op.create_index("ix_verifier_jobs_source_path_id", "verifier_jobs", ["source_path_id"])
    op.create_index("ix_verifier_jobs_severity", "verifier_jobs", ["severity"])
    op.create_index("ix_verifier_jobs_status", "verifier_jobs", ["status"])
    op.create_index("ix_verifier_jobs_available_at", "verifier_jobs", ["available_at"])
    op.create_index("ix_verifier_jobs_verifier_run_id", "verifier_jobs", ["verifier_run_id"])
    op.create_index("ix_verifier_jobs_finding_id", "verifier_jobs", ["finding_id"])
    op.create_index("ix_verifier_jobs_created_at", "verifier_jobs", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_verifier_jobs_created_at", table_name="verifier_jobs")
    op.drop_index("ix_verifier_jobs_finding_id", table_name="verifier_jobs")
    op.drop_index("ix_verifier_jobs_verifier_run_id", table_name="verifier_jobs")
    op.drop_index("ix_verifier_jobs_available_at", table_name="verifier_jobs")
    op.drop_index("ix_verifier_jobs_status", table_name="verifier_jobs")
    op.drop_index("ix_verifier_jobs_severity", table_name="verifier_jobs")
    op.drop_index("ix_verifier_jobs_source_path_id", table_name="verifier_jobs")
    op.drop_index("ix_verifier_jobs_scan_id", table_name="verifier_jobs")
    op.drop_table("verifier_jobs")
