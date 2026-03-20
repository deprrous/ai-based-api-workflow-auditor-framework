from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.db_models import VerifierRunRecord


class VerifierRunRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def list_for_scan(self, scan_id: str) -> list[VerifierRunRecord]:
        return self.session.scalars(
            select(VerifierRunRecord)
            .where(VerifierRunRecord.scan_id == scan_id)
            .order_by(VerifierRunRecord.created_at.desc(), VerifierRunRecord.id.asc())
        ).all()

    def get(self, verifier_run_id: str) -> VerifierRunRecord | None:
        return self.session.get(VerifierRunRecord, verifier_run_id)

    def add(self, record: VerifierRunRecord) -> None:
        self.session.add(record)
