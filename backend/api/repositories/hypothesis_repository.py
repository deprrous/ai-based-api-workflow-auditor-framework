from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.db_models import OrchestrationHypothesisRecord


class HypothesisRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def add(self, record: OrchestrationHypothesisRecord) -> None:
        self.session.add(record)

    def get(self, hypothesis_id: str) -> OrchestrationHypothesisRecord | None:
        return self.session.get(OrchestrationHypothesisRecord, hypothesis_id)

    def get_by_scan_and_path(self, scan_id: str, path_id: str) -> OrchestrationHypothesisRecord | None:
        return self.session.scalar(
            select(OrchestrationHypothesisRecord)
            .where(OrchestrationHypothesisRecord.scan_id == scan_id)
            .where(OrchestrationHypothesisRecord.source_path_id == path_id)
        )

    def get_by_scan_and_canonical_key(self, scan_id: str, canonical_key: str) -> OrchestrationHypothesisRecord | None:
        return self.session.scalar(
            select(OrchestrationHypothesisRecord)
            .where(OrchestrationHypothesisRecord.scan_id == scan_id)
            .where(OrchestrationHypothesisRecord.canonical_key == canonical_key)
            .order_by(OrchestrationHypothesisRecord.created_at.asc(), OrchestrationHypothesisRecord.id.asc())
        )

    def list_for_scan(self, scan_id: str) -> list[OrchestrationHypothesisRecord]:
        return self.session.scalars(
            select(OrchestrationHypothesisRecord)
            .where(OrchestrationHypothesisRecord.scan_id == scan_id)
            .order_by(OrchestrationHypothesisRecord.created_at.desc(), OrchestrationHypothesisRecord.id.asc())
        ).all()

    def list_for_scan_by_canonical_key(self, scan_id: str, canonical_key: str) -> list[OrchestrationHypothesisRecord]:
        return self.session.scalars(
            select(OrchestrationHypothesisRecord)
            .where(OrchestrationHypothesisRecord.scan_id == scan_id)
            .where(OrchestrationHypothesisRecord.canonical_key == canonical_key)
            .order_by(OrchestrationHypothesisRecord.created_at.asc(), OrchestrationHypothesisRecord.id.asc())
        ).all()
