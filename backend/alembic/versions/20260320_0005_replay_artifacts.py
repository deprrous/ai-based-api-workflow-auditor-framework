"""add replay artifacts

Revision ID: 20260320_0005
Revises: 20260320_0004
Create Date: 2026-03-20 00:40:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260320_0005"
down_revision = "20260320_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "replay_artifacts",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("scan_id", sa.String(length=64), nullable=False),
        sa.Column("request_fingerprint", sa.String(length=120), nullable=False),
        sa.Column("actor", sa.String(length=120), nullable=True),
        sa.Column("method", sa.String(length=16), nullable=False),
        sa.Column("host", sa.String(length=120), nullable=False),
        sa.Column("path", sa.String(length=400), nullable=False),
        sa.Column("request_headers_json", sa.JSON(), nullable=False),
        sa.Column("request_body_base64", sa.Text(), nullable=True),
        sa.Column("request_content_type", sa.String(length=160), nullable=True),
        sa.Column("response_status_code", sa.Integer(), nullable=True),
        sa.Column("response_headers_json", sa.JSON(), nullable=False),
        sa.Column("response_body_excerpt", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scan_runs.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_replay_artifacts_scan_id", "replay_artifacts", ["scan_id"])
    op.create_index("ix_replay_artifacts_request_fingerprint", "replay_artifacts", ["request_fingerprint"])
    op.create_index("ix_replay_artifacts_created_at", "replay_artifacts", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_replay_artifacts_created_at", table_name="replay_artifacts")
    op.drop_index("ix_replay_artifacts_request_fingerprint", table_name="replay_artifacts")
    op.drop_index("ix_replay_artifacts_scan_id", table_name="replay_artifacts")
    op.drop_table("replay_artifacts")
