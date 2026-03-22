"""add ai provider auth tables

Revision ID: 20260320_0014
Revises: 20260320_0013
Create Date: 2026-03-21 06:30:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260320_0014"
down_revision = "20260320_0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_provider_configs",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("provider_key", sa.String(length=80), nullable=False),
        sa.Column("provider_kind", sa.String(length=40), nullable=False),
        sa.Column("display_name", sa.String(length=160), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("is_default", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("default_model", sa.String(length=120), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_ai_provider_configs_provider_key", "ai_provider_configs", ["provider_key"])
    op.create_index("ix_ai_provider_configs_provider_kind", "ai_provider_configs", ["provider_kind"])
    op.create_index("ix_ai_provider_configs_created_at", "ai_provider_configs", ["created_at"])

    op.create_table(
        "ai_provider_auth_records",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("provider_config_id", sa.String(length=64), nullable=False),
        sa.Column("auth_method", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("encrypted_secret_json", sa.Text(), nullable=False),
        sa.Column("redacted_summary_json", sa.JSON(), nullable=False),
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["provider_config_id"], ["ai_provider_configs.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_ai_provider_auth_records_provider_config_id", "ai_provider_auth_records", ["provider_config_id"])
    op.create_index("ix_ai_provider_auth_records_auth_method", "ai_provider_auth_records", ["auth_method"])
    op.create_index("ix_ai_provider_auth_records_status", "ai_provider_auth_records", ["status"])
    op.create_index("ix_ai_provider_auth_records_created_at", "ai_provider_auth_records", ["created_at"])

    op.create_table(
        "ai_provider_oauth_states",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("provider_key", sa.String(length=80), nullable=False),
        sa.Column("provider_config_id", sa.String(length=64), nullable=True),
        sa.Column("state_token", sa.String(length=120), nullable=False, unique=True),
        sa.Column("pkce_verifier", sa.String(length=200), nullable=False),
        sa.Column("redirect_uri", sa.String(length=300), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["provider_config_id"], ["ai_provider_configs.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_ai_provider_oauth_states_provider_key", "ai_provider_oauth_states", ["provider_key"])
    op.create_index("ix_ai_provider_oauth_states_provider_config_id", "ai_provider_oauth_states", ["provider_config_id"])
    op.create_index("ix_ai_provider_oauth_states_state_token", "ai_provider_oauth_states", ["state_token"])
    op.create_index("ix_ai_provider_oauth_states_expires_at", "ai_provider_oauth_states", ["expires_at"])
    op.create_index("ix_ai_provider_oauth_states_created_at", "ai_provider_oauth_states", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_ai_provider_oauth_states_created_at", table_name="ai_provider_oauth_states")
    op.drop_index("ix_ai_provider_oauth_states_expires_at", table_name="ai_provider_oauth_states")
    op.drop_index("ix_ai_provider_oauth_states_state_token", table_name="ai_provider_oauth_states")
    op.drop_index("ix_ai_provider_oauth_states_provider_config_id", table_name="ai_provider_oauth_states")
    op.drop_index("ix_ai_provider_oauth_states_provider_key", table_name="ai_provider_oauth_states")
    op.drop_table("ai_provider_oauth_states")

    op.drop_index("ix_ai_provider_auth_records_created_at", table_name="ai_provider_auth_records")
    op.drop_index("ix_ai_provider_auth_records_status", table_name="ai_provider_auth_records")
    op.drop_index("ix_ai_provider_auth_records_auth_method", table_name="ai_provider_auth_records")
    op.drop_index("ix_ai_provider_auth_records_provider_config_id", table_name="ai_provider_auth_records")
    op.drop_table("ai_provider_auth_records")

    op.drop_index("ix_ai_provider_configs_created_at", table_name="ai_provider_configs")
    op.drop_index("ix_ai_provider_configs_provider_kind", table_name="ai_provider_configs")
    op.drop_index("ix_ai_provider_configs_provider_key", table_name="ai_provider_configs")
    op.drop_table("ai_provider_configs")
