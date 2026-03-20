from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.db_models import ReplayArtifactRecord


class ReplayArtifactRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def get(self, artifact_id: str) -> ReplayArtifactRecord | None:
        return self.session.get(ReplayArtifactRecord, artifact_id)

    def add(self, record: ReplayArtifactRecord) -> None:
        self.session.add(record)

    def list_for_scan(self, scan_id: str) -> list[ReplayArtifactRecord]:
        return self.session.scalars(
            select(ReplayArtifactRecord)
            .where(ReplayArtifactRecord.scan_id == scan_id)
            .order_by(ReplayArtifactRecord.created_at.desc(), ReplayArtifactRecord.id.asc())
        ).all()
