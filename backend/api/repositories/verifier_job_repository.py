from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.db_models import VerifierJobRecord


class VerifierJobRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def list_for_scan(self, scan_id: str) -> list[VerifierJobRecord]:
        return self.session.scalars(
            select(VerifierJobRecord)
            .where(VerifierJobRecord.scan_id == scan_id)
            .order_by(VerifierJobRecord.created_at.desc(), VerifierJobRecord.id.asc())
        ).all()

    def get(self, verifier_job_id: str) -> VerifierJobRecord | None:
        return self.session.get(VerifierJobRecord, verifier_job_id)

    def get_active_by_path(self, scan_id: str, path_id: str) -> VerifierJobRecord | None:
        return self.session.scalar(
            select(VerifierJobRecord)
            .where(VerifierJobRecord.scan_id == scan_id)
            .where(VerifierJobRecord.source_path_id == path_id)
            .where(VerifierJobRecord.status.in_(("queued", "running")))
        )

    def list_claimable(self, *, now: datetime, scan_id: str | None = None) -> list[VerifierJobRecord]:
        query = (
            select(VerifierJobRecord)
            .where(VerifierJobRecord.status == "queued")
            .where(VerifierJobRecord.available_at <= now)
        )
        if scan_id is not None:
            query = query.where(VerifierJobRecord.scan_id == scan_id)

        return self.session.scalars(
            query.order_by(VerifierJobRecord.available_at.asc(), VerifierJobRecord.created_at.asc(), VerifierJobRecord.id.asc())
        ).all()

    def add(self, record: VerifierJobRecord) -> None:
        self.session.add(record)
