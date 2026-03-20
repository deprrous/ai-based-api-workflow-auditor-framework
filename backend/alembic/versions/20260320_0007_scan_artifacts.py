"""add scan artifacts

Revision ID: 20260320_0007
Revises: 20260320_0006
Create Date: 2026-03-20 01:00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260320_0007"
down_revision = "20260320_0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_artifacts",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("scan_id", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("path", sa.String(length=300), nullable=True),
        sa.Column("language", sa.String(length=60), nullable=True),
        sa.Column("format", sa.String(length=40), nullable=True),
        sa.Column("checksum", sa.String(length=64), nullable=False),
        sa.Column("content_text", sa.Text(), nullable=False),
        sa.Column("content_excerpt", sa.Text(), nullable=False),
        sa.Column("parsed_summary_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scan_runs.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_scan_artifacts_scan_id", "scan_artifacts", ["scan_id"])
    op.create_index("ix_scan_artifacts_kind", "scan_artifacts", ["kind"])
    op.create_index("ix_scan_artifacts_checksum", "scan_artifacts", ["checksum"])
    op.create_index("ix_scan_artifacts_created_at", "scan_artifacts", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_scan_artifacts_created_at", table_name="scan_artifacts")
    op.drop_index("ix_scan_artifacts_checksum", table_name="scan_artifacts")
    op.drop_index("ix_scan_artifacts_kind", table_name="scan_artifacts")
    op.drop_index("ix_scan_artifacts_scan_id", table_name="scan_artifacts")
    op.drop_table("scan_artifacts")
