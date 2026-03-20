from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.db_models import ServiceAccountRecord


class ServiceAccountRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def list(self) -> list[ServiceAccountRecord]:
        return self.session.scalars(
            select(ServiceAccountRecord).order_by(ServiceAccountRecord.created_at.desc(), ServiceAccountRecord.name.asc())
        ).all()

    def get(self, service_account_id: str) -> ServiceAccountRecord | None:
        return self.session.get(ServiceAccountRecord, service_account_id)

    def get_by_name(self, name: str) -> ServiceAccountRecord | None:
        return self.session.scalar(select(ServiceAccountRecord).where(ServiceAccountRecord.name == name))

    def get_by_token_hash(self, token_hash: str) -> ServiceAccountRecord | None:
        return self.session.scalar(select(ServiceAccountRecord).where(ServiceAccountRecord.token_hash == token_hash))

    def add(self, record: ServiceAccountRecord) -> None:
        self.session.add(record)
