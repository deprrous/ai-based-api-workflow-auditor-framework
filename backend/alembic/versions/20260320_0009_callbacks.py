"""add callback expectations and events

Revision ID: 20260320_0009
Revises: 20260320_0008
Create Date: 2026-03-20 01:20:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260320_0009"
down_revision = "20260320_0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "callback_expectations",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("scan_id", sa.String(length=64), nullable=False),
        sa.Column("verifier_job_id", sa.String(length=64), nullable=True),
        sa.Column("token", sa.String(length=64), nullable=False, unique=True),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("label", sa.String(length=120), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scan_runs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["verifier_job_id"], ["verifier_jobs.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_callback_expectations_scan_id", "callback_expectations", ["scan_id"])
    op.create_index("ix_callback_expectations_verifier_job_id", "callback_expectations", ["verifier_job_id"])
    op.create_index("ix_callback_expectations_token", "callback_expectations", ["token"])
    op.create_index("ix_callback_expectations_kind", "callback_expectations", ["kind"])
    op.create_index("ix_callback_expectations_status", "callback_expectations", ["status"])
    op.create_index("ix_callback_expectations_created_at", "callback_expectations", ["created_at"])
    op.create_index("ix_callback_expectations_expires_at", "callback_expectations", ["expires_at"])

    op.create_table(
        "callback_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("expectation_id", sa.String(length=64), nullable=False),
        sa.Column("method", sa.String(length=16), nullable=False),
        sa.Column("path", sa.String(length=400), nullable=False),
        sa.Column("query_string", sa.Text(), nullable=True),
        sa.Column("headers_json", sa.JSON(), nullable=False),
        sa.Column("body_excerpt", sa.Text(), nullable=True),
        sa.Column("source_ip", sa.String(length=120), nullable=True),
        sa.Column("user_agent", sa.String(length=300), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["expectation_id"], ["callback_expectations.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_callback_events_expectation_id", "callback_events", ["expectation_id"])
    op.create_index("ix_callback_events_created_at", "callback_events", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_callback_events_created_at", table_name="callback_events")
    op.drop_index("ix_callback_events_expectation_id", table_name="callback_events")
    op.drop_table("callback_events")

    op.drop_index("ix_callback_expectations_expires_at", table_name="callback_expectations")
    op.drop_index("ix_callback_expectations_created_at", table_name="callback_expectations")
    op.drop_index("ix_callback_expectations_status", table_name="callback_expectations")
    op.drop_index("ix_callback_expectations_kind", table_name="callback_expectations")
    op.drop_index("ix_callback_expectations_token", table_name="callback_expectations")
    op.drop_index("ix_callback_expectations_verifier_job_id", table_name="callback_expectations")
    op.drop_index("ix_callback_expectations_scan_id", table_name="callback_expectations")
    op.drop_table("callback_expectations")
