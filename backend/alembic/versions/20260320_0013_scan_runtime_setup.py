"""add scan runtime setup fields

Revision ID: 20260320_0013
Revises: 20260320_0012
Create Date: 2026-03-21 06:00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260320_0013"
down_revision = "20260320_0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("scan_runs") as batch_op:
        batch_op.add_column(sa.Column("target_base_url", sa.String(length=300), nullable=True))

    op.create_table(
        "scan_actor_profiles",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("scan_id", sa.String(length=64), nullable=False),
        sa.Column("actor_id", sa.String(length=120), nullable=False),
        sa.Column("label", sa.String(length=160), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("headers_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scan_runs.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_scan_actor_profiles_scan_id", "scan_actor_profiles", ["scan_id"])
    op.create_index("ix_scan_actor_profiles_actor_id", "scan_actor_profiles", ["actor_id"])


def downgrade() -> None:
    op.drop_index("ix_scan_actor_profiles_actor_id", table_name="scan_actor_profiles")
    op.drop_index("ix_scan_actor_profiles_scan_id", table_name="scan_actor_profiles")
    op.drop_table("scan_actor_profiles")

    with op.batch_alter_table("scan_runs") as batch_op:
        batch_op.drop_column("target_base_url")
