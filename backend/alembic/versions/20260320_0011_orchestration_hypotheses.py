"""add orchestration hypotheses

Revision ID: 20260320_0011
Revises: 20260320_0010
Create Date: 2026-03-20 01:40:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260320_0011"
down_revision = "20260320_0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "orchestration_hypotheses",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("scan_id", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.String(length=64), nullable=True),
        sa.Column("planning_run_id", sa.String(length=64), nullable=True),
        sa.Column("source_path_id", sa.String(length=120), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("vulnerability_class", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("matched_rule", sa.String(length=120), nullable=False),
        sa.Column("verifier_strategy", sa.String(length=64), nullable=False),
        sa.Column("matched_signals_json", sa.JSON(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("selected_payload_variant_id", sa.String(length=80), nullable=True),
        sa.Column("selected_verifier_strategy", sa.String(length=64), nullable=True),
        sa.Column("decision_source", sa.String(length=32), nullable=True),
        sa.Column("verifier_job_id", sa.String(length=64), nullable=True),
        sa.Column("finding_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scan_runs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["session_id"], ["orchestration_sessions.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["planning_run_id"], ["planning_runs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["verifier_job_id"], ["verifier_jobs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_orchestration_hypotheses_scan_id", "orchestration_hypotheses", ["scan_id"])
    op.create_index("ix_orchestration_hypotheses_session_id", "orchestration_hypotheses", ["session_id"])
    op.create_index("ix_orchestration_hypotheses_planning_run_id", "orchestration_hypotheses", ["planning_run_id"])
    op.create_index("ix_orchestration_hypotheses_source_path_id", "orchestration_hypotheses", ["source_path_id"])
    op.create_index("ix_orchestration_hypotheses_vulnerability_class", "orchestration_hypotheses", ["vulnerability_class"])
    op.create_index("ix_orchestration_hypotheses_severity", "orchestration_hypotheses", ["severity"])
    op.create_index("ix_orchestration_hypotheses_status", "orchestration_hypotheses", ["status"])
    op.create_index("ix_orchestration_hypotheses_verifier_job_id", "orchestration_hypotheses", ["verifier_job_id"])
    op.create_index("ix_orchestration_hypotheses_finding_id", "orchestration_hypotheses", ["finding_id"])
    op.create_index("ix_orchestration_hypotheses_created_at", "orchestration_hypotheses", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_orchestration_hypotheses_created_at", table_name="orchestration_hypotheses")
    op.drop_index("ix_orchestration_hypotheses_finding_id", table_name="orchestration_hypotheses")
    op.drop_index("ix_orchestration_hypotheses_verifier_job_id", table_name="orchestration_hypotheses")
    op.drop_index("ix_orchestration_hypotheses_status", table_name="orchestration_hypotheses")
    op.drop_index("ix_orchestration_hypotheses_severity", table_name="orchestration_hypotheses")
    op.drop_index("ix_orchestration_hypotheses_vulnerability_class", table_name="orchestration_hypotheses")
    op.drop_index("ix_orchestration_hypotheses_source_path_id", table_name="orchestration_hypotheses")
    op.drop_index("ix_orchestration_hypotheses_planning_run_id", table_name="orchestration_hypotheses")
    op.drop_index("ix_orchestration_hypotheses_session_id", table_name="orchestration_hypotheses")
    op.drop_index("ix_orchestration_hypotheses_scan_id", table_name="orchestration_hypotheses")
    op.drop_table("orchestration_hypotheses")
