"""add hypothesis lifecycle fields

Revision ID: 20260320_0012
Revises: 20260320_0011
Create Date: 2026-03-21 05:25:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260320_0012"
down_revision = "20260320_0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("orchestration_hypotheses") as batch_op:
        batch_op.add_column(sa.Column("canonical_key", sa.String(length=240), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("merged_into_hypothesis_id", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"))
        batch_op.add_column(sa.Column("failure_count", sa.Integer(), nullable=False, server_default="0"))
        batch_op.add_column(sa.Column("reopen_count", sa.Integer(), nullable=False, server_default="0"))
        batch_op.add_column(sa.Column("stale_cycles", sa.Integer(), nullable=False, server_default="0"))
        batch_op.add_column(sa.Column("last_transition_reason", sa.Text(), nullable=True))
        batch_op.create_index("ix_orchestration_hypotheses_canonical_key", ["canonical_key"])
        batch_op.create_index("ix_orchestration_hypotheses_merged_into_hypothesis_id", ["merged_into_hypothesis_id"])
        batch_op.create_foreign_key(
            "fk_orchestration_hypotheses_merged_into_hypothesis_id",
            "orchestration_hypotheses",
            ["merged_into_hypothesis_id"],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    with op.batch_alter_table("orchestration_hypotheses") as batch_op:
        batch_op.drop_constraint(
            "fk_orchestration_hypotheses_merged_into_hypothesis_id",
            type_="foreignkey",
        )
        batch_op.drop_index("ix_orchestration_hypotheses_merged_into_hypothesis_id")
        batch_op.drop_index("ix_orchestration_hypotheses_canonical_key")
        batch_op.drop_column("last_transition_reason")
        batch_op.drop_column("stale_cycles")
        batch_op.drop_column("reopen_count")
        batch_op.drop_column("failure_count")
        batch_op.drop_column("attempt_count")
        batch_op.drop_column("merged_into_hypothesis_id")
        batch_op.drop_column("canonical_key")
