"""add verifier runs and finding context references

Revision ID: 20260320_0003
Revises: 20260320_0002
Create Date: 2026-03-20 00:20:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260320_0003"
down_revision = "20260320_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("context_references_json", sa.JSON(), nullable=False, server_default="[]"),
    )

    op.create_table(
        "verifier_runs",
        sa.Column("id", sa.String(length=120), primary_key=True),
        sa.Column("scan_id", sa.String(length=64), nullable=False),
        sa.Column("finding_id", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("category", sa.String(length=80), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("endpoint", sa.String(length=200), nullable=True),
        sa.Column("actor", sa.String(length=120), nullable=True),
        sa.Column("request_fingerprint", sa.String(length=120), nullable=True),
        sa.Column("request_summary", sa.Text(), nullable=True),
        sa.Column("response_status_code", sa.Integer(), nullable=True),
        sa.Column("evidence_json", sa.JSON(), nullable=False),
        sa.Column("context_references_json", sa.JSON(), nullable=False),
        sa.Column("workflow_node_ids_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scan_runs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_verifier_runs_scan_id", "verifier_runs", ["scan_id"])
    op.create_index("ix_verifier_runs_finding_id", "verifier_runs", ["finding_id"])
    op.create_index("ix_verifier_runs_status", "verifier_runs", ["status"])
    op.create_index("ix_verifier_runs_category", "verifier_runs", ["category"])
    op.create_index("ix_verifier_runs_severity", "verifier_runs", ["severity"])
    op.create_index("ix_verifier_runs_request_fingerprint", "verifier_runs", ["request_fingerprint"])
    op.create_index("ix_verifier_runs_created_at", "verifier_runs", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_verifier_runs_created_at", table_name="verifier_runs")
    op.drop_index("ix_verifier_runs_request_fingerprint", table_name="verifier_runs")
    op.drop_index("ix_verifier_runs_severity", table_name="verifier_runs")
    op.drop_index("ix_verifier_runs_category", table_name="verifier_runs")
    op.drop_index("ix_verifier_runs_status", table_name="verifier_runs")
    op.drop_index("ix_verifier_runs_finding_id", table_name="verifier_runs")
    op.drop_index("ix_verifier_runs_scan_id", table_name="verifier_runs")
    op.drop_table("verifier_runs")

    op.drop_column("findings", "context_references_json")
