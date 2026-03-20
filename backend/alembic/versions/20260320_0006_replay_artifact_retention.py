"""add replay artifact retention fields

Revision ID: 20260320_0006
Revises: 20260320_0005
Create Date: 2026-03-20 00:50:00
"""

from __future__ import annotations

from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa


revision = "20260320_0006"
down_revision = "20260320_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "replay_artifacts",
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )
    op.add_column(
        "replay_artifacts",
        sa.Column("purged_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_replay_artifacts_expires_at", "replay_artifacts", ["expires_at"])
    op.create_index("ix_replay_artifacts_purged_at", "replay_artifacts", ["purged_at"])

    connection = op.get_bind()
    default_expiry = datetime.now(timezone.utc)
    connection.execute(sa.text("UPDATE replay_artifacts SET expires_at = :expires_at"), {"expires_at": default_expiry})


def downgrade() -> None:
    op.drop_index("ix_replay_artifacts_purged_at", table_name="replay_artifacts")
    op.drop_index("ix_replay_artifacts_expires_at", table_name="replay_artifacts")
    op.drop_column("replay_artifacts", "purged_at")
    op.drop_column("replay_artifacts", "expires_at")
