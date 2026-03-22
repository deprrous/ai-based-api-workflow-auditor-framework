from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.db_models import ScanActorProfileRecord


class ScanActorProfileRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def list_for_scan(self, scan_id: str) -> list[ScanActorProfileRecord]:
        return self.session.scalars(
            select(ScanActorProfileRecord)
            .where(ScanActorProfileRecord.scan_id == scan_id)
            .order_by(ScanActorProfileRecord.created_at.asc(), ScanActorProfileRecord.id.asc())
        ).all()

    def get_by_scan_and_actor_id(self, scan_id: str, actor_id: str) -> ScanActorProfileRecord | None:
        return self.session.scalar(
            select(ScanActorProfileRecord)
            .where(ScanActorProfileRecord.scan_id == scan_id)
            .where(ScanActorProfileRecord.actor_id == actor_id)
        )

    def add(self, record: ScanActorProfileRecord) -> None:
        self.session.add(record)
