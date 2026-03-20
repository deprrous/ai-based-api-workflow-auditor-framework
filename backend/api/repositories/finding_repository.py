from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.db_models import FindingRecord


class FindingRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def list(
        self,
        *,
        scan_id: str | None = None,
        severity: str | None = None,
        status: str | None = None,
    ) -> list[FindingRecord]:
        query = select(FindingRecord)

        if scan_id is not None:
            query = query.where(FindingRecord.scan_id == scan_id)
        if severity is not None:
            query = query.where(FindingRecord.severity == severity)
        if status is not None:
            query = query.where(FindingRecord.status == status)

        return self.session.scalars(query.order_by(FindingRecord.created_at.desc(), FindingRecord.id.asc())).all()

    def list_for_scan(self, scan_id: str) -> list[FindingRecord]:
        return self.session.scalars(
            select(FindingRecord)
            .where(FindingRecord.scan_id == scan_id)
            .order_by(FindingRecord.created_at.desc(), FindingRecord.id.asc())
        ).all()

    def get(self, finding_id: str) -> FindingRecord | None:
        return self.session.get(FindingRecord, finding_id)

    def exists_any(self) -> bool:
        return self.session.scalar(select(FindingRecord.id).limit(1)) is not None

    def add(self, record: FindingRecord) -> None:
        self.session.add(record)
