from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.db_models import WorkflowGraphRecord


class WorkflowRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def get_by_scan_id(self, scan_id: str) -> WorkflowGraphRecord | None:
        return self.session.scalar(select(WorkflowGraphRecord).where(WorkflowGraphRecord.scan_id == scan_id))

    def get_framework_principle(self) -> WorkflowGraphRecord | None:
        return self.session.scalar(
            select(WorkflowGraphRecord).where(WorkflowGraphRecord.kind == "framework_principle")
        )

    def add(self, record: WorkflowGraphRecord) -> None:
        self.session.add(record)
