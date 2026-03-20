from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.db_models import ScanEventRecord


class EventRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def list_for_scan(self, scan_id: str, *, after_id: int | None = None, limit: int = 40) -> list[ScanEventRecord]:
        query = select(ScanEventRecord).where(ScanEventRecord.scan_id == scan_id)
        if after_id is not None:
            query = query.where(ScanEventRecord.id > after_id)

        return self.session.scalars(query.order_by(ScanEventRecord.id.asc()).limit(limit)).all()

    def list_recent_for_scan(self, scan_id: str, *, limit: int = 25) -> list[ScanEventRecord]:
        return self.session.scalars(
            select(ScanEventRecord)
            .where(ScanEventRecord.scan_id == scan_id)
            .order_by(ScanEventRecord.id.desc())
            .limit(limit)
        ).all()

    def add(self, record: ScanEventRecord) -> None:
        self.session.add(record)
