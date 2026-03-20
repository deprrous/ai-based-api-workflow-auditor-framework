from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.db_models import CallbackEventRecord, CallbackExpectationRecord


class CallbackRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def get_expectation(self, expectation_id: str) -> CallbackExpectationRecord | None:
        return self.session.get(CallbackExpectationRecord, expectation_id)

    def get_expectation_by_token(self, token: str) -> CallbackExpectationRecord | None:
        return self.session.scalar(select(CallbackExpectationRecord).where(CallbackExpectationRecord.token == token))

    def list_expectations_for_scan(self, scan_id: str) -> list[CallbackExpectationRecord]:
        return self.session.scalars(
            select(CallbackExpectationRecord)
            .where(CallbackExpectationRecord.scan_id == scan_id)
            .order_by(CallbackExpectationRecord.created_at.desc(), CallbackExpectationRecord.id.asc())
        ).all()

    def list_events_for_expectation(self, expectation_id: str) -> list[CallbackEventRecord]:
        return self.session.scalars(
            select(CallbackEventRecord)
            .where(CallbackEventRecord.expectation_id == expectation_id)
            .order_by(CallbackEventRecord.created_at.asc(), CallbackEventRecord.id.asc())
        ).all()

    def add_expectation(self, record: CallbackExpectationRecord) -> None:
        self.session.add(record)

    def add_event(self, record: CallbackEventRecord) -> None:
        self.session.add(record)

    def list_expired_pending_expectations(self, *, now: datetime) -> list[CallbackExpectationRecord]:
        return self.session.scalars(
            select(CallbackExpectationRecord)
            .where(CallbackExpectationRecord.expires_at <= now)
            .where(CallbackExpectationRecord.status == "pending")
            .order_by(CallbackExpectationRecord.expires_at.asc(), CallbackExpectationRecord.id.asc())
        ).all()
