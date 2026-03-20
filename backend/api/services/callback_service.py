from __future__ import annotations

from dataclasses import dataclass

from api.app.config import get_settings
from api.schemas.callbacks import CallbackExpectationDetail, CallbackExpectationStatus, CallbackExpectationSummary, CallbackKind
from api.services.store import audit_store
from tools.verifier.callback_analysis import analyze_callback_event


class CallbackService:
    def create_expectation(
        self,
        *,
        scan_id: str,
        verifier_job_id: str | None,
        kind: CallbackKind,
        label: str,
    ) -> CallbackExpectationDetail | None:
        settings = get_settings()
        return audit_store.create_callback_expectation(
            scan_id=scan_id,
            verifier_job_id=verifier_job_id,
            kind=kind,
            label=label,
            ttl_seconds=settings.callback_expectation_ttl_seconds,
        )

    def get_expectation_by_token(self, token: str) -> CallbackExpectationDetail | None:
        self.expire_expectations()
        return audit_store.get_callback_expectation_by_token(token)

    def list_expectations(self, scan_id: str) -> list[CallbackExpectationSummary]:
        self.expire_expectations()
        return audit_store.list_callback_expectations(scan_id)

    def record_event(
        self,
        *,
        token: str,
        method: str,
        path: str,
        query_string: str | None,
        headers: dict[str, str],
        body_excerpt: str | None,
        source_ip: str | None,
        user_agent: str | None,
    ) -> CallbackExpectationDetail | None:
        return audit_store.record_callback_event(
            token=token,
            method=method,
            path=path,
            query_string=query_string,
            headers=headers,
            body_excerpt=body_excerpt,
            source_ip=source_ip,
            user_agent=user_agent,
        )

    def expire_expectations(self) -> int:
        return audit_store.expire_callback_expectations()

    def callback_received(self, token: str) -> bool:
        expectation = self.get_expectation_by_token(token)
        return expectation is not None and expectation.status == CallbackExpectationStatus.RECEIVED

    @staticmethod
    def analyze_event(
        *,
        method: str,
        path: str,
        query_string: str | None,
        headers: dict[str, str],
        body_excerpt: str | None,
        source_ip: str | None,
        user_agent: str | None,
    ):
        return analyze_callback_event(
            method=method,
            path=path,
            query_string=query_string,
            headers=headers,
            body_excerpt=body_excerpt,
            source_ip=source_ip,
            user_agent=user_agent,
        )


@dataclass(slots=True)
class CallbackRetentionService:
    def run_once(self) -> int:
        return callback_service.expire_expectations()


callback_service = CallbackService()
