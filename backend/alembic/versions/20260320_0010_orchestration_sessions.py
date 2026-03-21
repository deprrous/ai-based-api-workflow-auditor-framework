"""add orchestration sessions

Revision ID: 20260320_0010
Revises: 20260320_0009
Create Date: 2026-03-20 01:30:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260320_0010"
down_revision = "20260320_0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "orchestration_sessions",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("scan_id", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("mode", sa.String(length=32), nullable=False),
        sa.Column("provider_key", sa.String(length=64), nullable=True),
        sa.Column("current_phase", sa.String(length=64), nullable=False),
        sa.Column("max_verifier_cycles", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("completed_verifier_cycles", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("request_json", sa.JSON(), nullable=False),
        sa.Column("memory_json", sa.JSON(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scan_runs.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_orchestration_sessions_scan_id", "orchestration_sessions", ["scan_id"])
    op.create_index("ix_orchestration_sessions_status", "orchestration_sessions", ["status"])
    op.create_index("ix_orchestration_sessions_mode", "orchestration_sessions", ["mode"])
    op.create_index("ix_orchestration_sessions_provider_key", "orchestration_sessions", ["provider_key"])
    op.create_index("ix_orchestration_sessions_started_at", "orchestration_sessions", ["started_at"])
    op.create_index("ix_orchestration_sessions_created_at", "orchestration_sessions", ["created_at"])

    op.create_table(
        "orchestration_steps",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("session_id", sa.String(length=64), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("memory_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["session_id"], ["orchestration_sessions.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_orchestration_steps_session_id", "orchestration_steps", ["session_id"])
    op.create_index("ix_orchestration_steps_kind", "orchestration_steps", ["kind"])
    op.create_index("ix_orchestration_steps_status", "orchestration_steps", ["status"])
    op.create_index("ix_orchestration_steps_created_at", "orchestration_steps", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_orchestration_steps_created_at", table_name="orchestration_steps")
    op.drop_index("ix_orchestration_steps_status", table_name="orchestration_steps")
    op.drop_index("ix_orchestration_steps_kind", table_name="orchestration_steps")
    op.drop_index("ix_orchestration_steps_session_id", table_name="orchestration_steps")
    op.drop_table("orchestration_steps")

    op.drop_index("ix_orchestration_sessions_created_at", table_name="orchestration_sessions")
    op.drop_index("ix_orchestration_sessions_started_at", table_name="orchestration_sessions")
    op.drop_index("ix_orchestration_sessions_provider_key", table_name="orchestration_sessions")
    op.drop_index("ix_orchestration_sessions_mode", table_name="orchestration_sessions")
    op.drop_index("ix_orchestration_sessions_status", table_name="orchestration_sessions")
    op.drop_index("ix_orchestration_sessions_scan_id", table_name="orchestration_sessions")
    op.drop_table("orchestration_sessions")
