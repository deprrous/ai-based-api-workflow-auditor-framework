from __future__ import annotations

from api.schemas.verifier_jobs import (
    ClaimVerifierJobRequest,
    CompleteVerifierJobRequest,
    FailVerifierJobRequest,
    VerifierJobDetail,
    VerifierJobSummary,
)
from api.services.store import audit_store


class VerifierJobService:
    def list_verifier_jobs(self, scan_id: str) -> list[VerifierJobSummary]:
        return audit_store.list_verifier_jobs(scan_id)

    def get_verifier_job(self, verifier_job_id: str) -> VerifierJobDetail | None:
        return audit_store.get_verifier_job(verifier_job_id)

    def claim_verifier_job(self, payload: ClaimVerifierJobRequest) -> VerifierJobDetail | None:
        return audit_store.claim_verifier_job(payload)

    def complete_verifier_job(self, verifier_job_id: str, payload: CompleteVerifierJobRequest) -> VerifierJobDetail | None:
        return audit_store.complete_verifier_job(verifier_job_id, payload)

    def fail_verifier_job(self, verifier_job_id: str, payload: FailVerifierJobRequest) -> VerifierJobDetail | None:
        return audit_store.fail_verifier_job(verifier_job_id, payload)


verifier_job_service = VerifierJobService()
