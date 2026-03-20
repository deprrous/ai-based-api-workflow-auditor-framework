from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.db_models import ScanArtifactRecord


class ArtifactRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def list_for_scan(self, scan_id: str, *, kind: str | None = None) -> list[ScanArtifactRecord]:
        query = select(ScanArtifactRecord).where(ScanArtifactRecord.scan_id == scan_id)
        if kind is not None:
            query = query.where(ScanArtifactRecord.kind == kind)

        return self.session.scalars(
            query.order_by(ScanArtifactRecord.created_at.desc(), ScanArtifactRecord.id.asc())
        ).all()

    def get(self, artifact_id: str) -> ScanArtifactRecord | None:
        return self.session.get(ScanArtifactRecord, artifact_id)

    def add(self, record: ScanArtifactRecord) -> None:
        self.session.add(record)
