from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.db_models import ScanRunRecord


class ScanRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def list(self) -> list[ScanRunRecord]:
        return self.session.scalars(select(ScanRunRecord).order_by(ScanRunRecord.created_at.desc())).all()

    def get(self, scan_id: str) -> ScanRunRecord | None:
        return self.session.get(ScanRunRecord, scan_id)

    def exists_any(self) -> bool:
        return self.session.scalar(select(ScanRunRecord.id).limit(1)) is not None

    def add(self, record: ScanRunRecord) -> None:
        self.session.add(record)
