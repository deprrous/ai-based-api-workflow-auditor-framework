"""initial backend schema

Revision ID: 20260320_0001
Revises:
Create Date: 2026-03-20 00:00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260320_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_runs",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("target", sa.String(length=120), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("current_stage", sa.String(length=64), nullable=False),
        sa.Column("findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("flagged_paths", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("risk", sa.String(length=32), nullable=False),
        sa.Column("workflow_id", sa.String(length=64), nullable=False, unique=True),
        sa.Column("notes", sa.Text(), nullable=True),
    )
    op.create_index("ix_scan_runs_status", "scan_runs", ["status"])
    op.create_index("ix_scan_runs_created_at", "scan_runs", ["created_at"])

    op.create_table(
        "workflow_graphs",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("scan_id", sa.String(length=64), nullable=True),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("flagged_paths", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("nodes_json", sa.JSON(), nullable=False),
        sa.Column("edges_json", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scan_runs.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("scan_id"),
    )
    op.create_index("ix_workflow_graphs_kind", "workflow_graphs", ["kind"])

    op.create_table(
        "scan_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("scan_id", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("event_type", sa.String(length=80), nullable=False),
        sa.Column("stage", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scan_runs.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_scan_events_scan_id", "scan_events", ["scan_id"])
    op.create_index("ix_scan_events_created_at", "scan_events", ["created_at"])

    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("scan_id", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("category", sa.String(length=80), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("endpoint", sa.String(length=200), nullable=True),
        sa.Column("actor", sa.String(length=120), nullable=True),
        sa.Column("impact_summary", sa.Text(), nullable=False),
        sa.Column("remediation_summary", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("impact", sa.Text(), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column("evidence_json", sa.JSON(), nullable=False),
        sa.Column("workflow_node_ids_json", sa.JSON(), nullable=False),
        sa.Column("tags_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scan_runs.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_category", "findings", ["category"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_status", "findings", ["status"])
    op.create_index("ix_findings_created_at", "findings", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_findings_created_at", table_name="findings")
    op.drop_index("ix_findings_status", table_name="findings")
    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_index("ix_findings_category", table_name="findings")
    op.drop_index("ix_findings_scan_id", table_name="findings")
    op.drop_table("findings")

    op.drop_index("ix_scan_events_created_at", table_name="scan_events")
    op.drop_index("ix_scan_events_scan_id", table_name="scan_events")
    op.drop_table("scan_events")

    op.drop_index("ix_workflow_graphs_kind", table_name="workflow_graphs")
    op.drop_table("workflow_graphs")

    op.drop_index("ix_scan_runs_created_at", table_name="scan_runs")
    op.drop_index("ix_scan_runs_status", table_name="scan_runs")
    op.drop_table("scan_runs")
