from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.db_models import OrchestrationSessionRecord, OrchestrationStepRecord


class OrchestrationRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def add_session(self, record: OrchestrationSessionRecord) -> None:
        self.session.add(record)

    def add_step(self, record: OrchestrationStepRecord) -> None:
        self.session.add(record)

    def get_session(self, session_id: str) -> OrchestrationSessionRecord | None:
        return self.session.get(OrchestrationSessionRecord, session_id)

    def list_sessions_for_scan(self, scan_id: str) -> list[OrchestrationSessionRecord]:
        return self.session.scalars(
            select(OrchestrationSessionRecord)
            .where(OrchestrationSessionRecord.scan_id == scan_id)
            .order_by(OrchestrationSessionRecord.created_at.desc(), OrchestrationSessionRecord.id.asc())
        ).all()

    def list_steps_for_session(self, session_id: str) -> list[OrchestrationStepRecord]:
        return self.session.scalars(
            select(OrchestrationStepRecord)
            .where(OrchestrationStepRecord.session_id == session_id)
            .order_by(OrchestrationStepRecord.sequence.asc(), OrchestrationStepRecord.id.asc())
        ).all()
