"""add service accounts

Revision ID: 20260320_0002
Revises: 20260320_0001
Create Date: 2026-03-20 00:10:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260320_0002"
down_revision = "20260320_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "service_accounts",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("name", sa.String(length=120), nullable=False, unique=True),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("scopes_json", sa.JSON(), nullable=False),
        sa.Column("token_hash", sa.String(length=128), nullable=False, unique=True),
        sa.Column("token_prefix", sa.String(length=24), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_service_accounts_kind", "service_accounts", ["kind"])
    op.create_index("ix_service_accounts_created_at", "service_accounts", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_service_accounts_created_at", table_name="service_accounts")
    op.drop_index("ix_service_accounts_kind", table_name="service_accounts")
    op.drop_table("service_accounts")
