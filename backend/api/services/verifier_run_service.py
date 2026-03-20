from __future__ import annotations

from api.schemas.verifier_runs import VerifierRunDetail, VerifierRunSummary
from api.services.store import audit_store


class VerifierRunService:
    def list_verifier_runs(self, scan_id: str) -> list[VerifierRunSummary]:
        return audit_store.list_verifier_runs(scan_id)

    def get_verifier_run(self, verifier_run_id: str) -> VerifierRunDetail | None:
        return audit_store.get_verifier_run(verifier_run_id)


verifier_run_service = VerifierRunService()
