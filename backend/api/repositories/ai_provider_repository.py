from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.db_models import AiProviderAuthRecord, AiProviderConfigRecord, AiProviderOAuthStateRecord


class AiProviderRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def list_configs(self) -> list[AiProviderConfigRecord]:
        return self.session.scalars(
            select(AiProviderConfigRecord).order_by(AiProviderConfigRecord.created_at.desc(), AiProviderConfigRecord.id.asc())
        ).all()

    def get_config(self, config_id: str) -> AiProviderConfigRecord | None:
        return self.session.get(AiProviderConfigRecord, config_id)

    def get_default_config(self) -> AiProviderConfigRecord | None:
        return self.session.scalar(select(AiProviderConfigRecord).where(AiProviderConfigRecord.is_default.is_(True)))

    def add_config(self, record: AiProviderConfigRecord) -> None:
        self.session.add(record)

    def get_config_by_provider_key(self, provider_key: str) -> AiProviderConfigRecord | None:
        return self.session.scalar(
            select(AiProviderConfigRecord)
            .where(AiProviderConfigRecord.provider_key == provider_key)
            .order_by(AiProviderConfigRecord.created_at.desc(), AiProviderConfigRecord.id.asc())
        )

    def list_auth_records(self, config_id: str) -> list[AiProviderAuthRecord]:
        return self.session.scalars(
            select(AiProviderAuthRecord)
            .where(AiProviderAuthRecord.provider_config_id == config_id)
            .order_by(AiProviderAuthRecord.created_at.desc(), AiProviderAuthRecord.id.asc())
        ).all()

    def get_auth_record(self, config_id: str, auth_method: str) -> AiProviderAuthRecord | None:
        return self.session.scalar(
            select(AiProviderAuthRecord)
            .where(AiProviderAuthRecord.provider_config_id == config_id)
            .where(AiProviderAuthRecord.auth_method == auth_method)
        )

    def add_auth_record(self, record: AiProviderAuthRecord) -> None:
        self.session.add(record)

    def add_oauth_state(self, record: AiProviderOAuthStateRecord) -> None:
        self.session.add(record)

    def get_oauth_state(self, state_token: str) -> AiProviderOAuthStateRecord | None:
        return self.session.scalar(select(AiProviderOAuthStateRecord).where(AiProviderOAuthStateRecord.state_token == state_token))

    def list_expired_oauth_states(self, *, now: datetime) -> list[AiProviderOAuthStateRecord]:
        return self.session.scalars(
            select(AiProviderOAuthStateRecord)
            .where(AiProviderOAuthStateRecord.expires_at <= now)
            .where(AiProviderOAuthStateRecord.used_at.is_(None))
        ).all()
