from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.db_models import PlanningRunRecord


class PlanningRunRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def list_for_scan(self, scan_id: str) -> list[PlanningRunRecord]:
        return self.session.scalars(
            select(PlanningRunRecord)
            .where(PlanningRunRecord.scan_id == scan_id)
            .order_by(PlanningRunRecord.created_at.desc(), PlanningRunRecord.id.asc())
        ).all()

    def get(self, planning_run_id: str) -> PlanningRunRecord | None:
        return self.session.get(PlanningRunRecord, planning_run_id)

    def add(self, record: PlanningRunRecord) -> None:
        self.session.add(record)
