from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
from typing import Protocol

from api.schemas.events import EventSeverity, EventSource, RecordScanEventRequest
from api.schemas.findings import FindingEvidence, FindingSeverity
from api.schemas.verifier_jobs import ClaimVerifierJobRequest, CompleteVerifierJobRequest, FailVerifierJobRequest, VerifierJobDetail
from api.services.event_service import event_service
from api.services.verifier_job_service import verifier_job_service
from tools.verifier.worker import VerifierReplayResult, build_ingest_request


def _stable_suffix(value: str, *, length: int = 12) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest()[:length]


def _category_from_job(job: VerifierJobDetail) -> str:
    lowered = f"{job.title} {job.rationale}".lower()
    if "delete" in lowered or "admin" in lowered or "role" in lowered:
        return "bfla"
    if "key" in lowered or "secret" in lowered or "tenant" in lowered:
        return "tenant_isolation"
    return "business_logic"


def _endpoint_from_job(job: VerifierJobDetail) -> str | None:
    for node in reversed(job.payload.workflow_nodes):
        if node.type in {"endpoint", "action"}:
            return node.label
    return None


class VerifierJobExecutor(Protocol):
    def execute(self, job: VerifierJobDetail) -> VerifierReplayResult: ...


@dataclass(frozen=True, slots=True)
class DeterministicDevVerifierExecutor:
    def execute(self, job: VerifierJobDetail) -> VerifierReplayResult:
        endpoint = _endpoint_from_job(job)
        status_code = 204 if endpoint and endpoint.startswith("DELETE ") else 200
        return VerifierReplayResult(
            verifier_run_id=f"verify-{job.id}",
            scan_id=job.scan_id,
            finding_id=f"finding-{job.id}",
            title=job.title,
            category=_category_from_job(job),
            severity=job.severity,
            confidence=92 if job.severity == FindingSeverity.CRITICAL else 84,
            endpoint=endpoint,
            actor=job.payload.workflow_nodes[0].label if job.payload.workflow_nodes else None,
            request_fingerprint=f"auto-{_stable_suffix(job.source_path_id)}",
            request_summary=f"Deterministic dev executor processed queued path {job.source_path_id}.",
            response_status_code=status_code,
            message=f"Automatic verifier worker confirmed queued job {job.id}.",
            impact_summary=f"Auto-run verifier marked the queued path '{job.title}' as confirmed for development workflow testing.",
            remediation_summary="Replace the deterministic development executor with a real replay executor before production usage.",
            description=(
                "The deterministic development executor converted a queued verifier job into a confirmed replay result. "
                "This is intended to exercise the backend orchestration pipeline, not to represent a production-grade exploit engine."
            ),
            impact="The queued path remains high-risk and should be re-verified by a real replay executor before being trusted in production.",
            remediation="Attach a real replay backend and keep deterministic development execution disabled outside local testing.",
            workflow_node_ids=list(job.payload.workflow_node_ids),
            evidence=[
                FindingEvidence(
                    label="Deterministic executor output",
                    detail=(
                        f"The backend auto-runner processed verifier job {job.id} for path {job.source_path_id} "
                        f"and produced a development confirmation artifact."
                    ),
                    source="verifier",
                )
            ],
            tags=["dev-autorun", job.severity.value, *{node.phase for node in job.payload.workflow_nodes}],
        )


@dataclass(slots=True)
class VerifierRuntimeService:
    executor: VerifierJobExecutor
    worker_id: str
    poll_interval_seconds: float = 2.0
    _stop_event: asyncio.Event | None = None

    def run_once(self) -> bool:
        job = verifier_job_service.claim_verifier_job(
            ClaimVerifierJobRequest(
                worker_id=self.worker_id,
            )
        )
        if job is None:
            return False

        try:
            result = self.executor.execute(job)
            envelope = event_service.ingest_scan_event(job.scan_id, build_ingest_request(result))
            if envelope is None:
                raise RuntimeError("Failed to ingest verifier finding into the backend runtime store.")

            finding_id = envelope.event.payload.get("finding_id") if envelope.event.payload else None
            verifier_job_service.complete_verifier_job(
                job.id,
                CompleteVerifierJobRequest(
                    verifier_run_id=result.verifier_run_id,
                    finding_id=str(finding_id) if finding_id is not None else result.finding_id,
                    note="Automatic verifier runtime completed the queued job.",
                ),
            )
            event_service.record_scan_event(
                job.scan_id,
                RecordScanEventRequest(
                    source=EventSource.SYSTEM,
                    event_type="verifier_runtime.completed",
                    stage="reporting",
                    severity=EventSeverity.INFO,
                    message=f"Automatic verifier runtime completed job {job.id}.",
                    payload={"job_id": job.id, "verifier_run_id": result.verifier_run_id},
                ),
            )
            return True
        except Exception as exc:
            verifier_job_service.fail_verifier_job(
                job.id,
                FailVerifierJobRequest(
                    error_message=str(exc),
                    retryable=True,
                    retry_delay_seconds=0,
                ),
            )
            event_service.record_scan_event(
                job.scan_id,
                RecordScanEventRequest(
                    source=EventSource.SYSTEM,
                    event_type="verifier_runtime.failed",
                    stage="verification",
                    severity=EventSeverity.WARNING,
                    message=f"Automatic verifier runtime failed job {job.id}.",
                    payload={"job_id": job.id, "error": str(exc)},
                ),
            )
            return False

    async def run_forever(self) -> None:
        if self._stop_event is None:
            self._stop_event = asyncio.Event()

        while not self._stop_event.is_set():
            processed = self.run_once()
            if not processed:
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=self.poll_interval_seconds)
                except TimeoutError:
                    continue

    def stop(self) -> None:
        if self._stop_event is not None:
            self._stop_event.set()


def build_runtime_service(*, mode: str, worker_id: str, poll_interval_seconds: float) -> VerifierRuntimeService | None:
    normalized_mode = mode.strip().lower()
    if normalized_mode in {"", "disabled", "manual"}:
        return None
    if normalized_mode == "deterministic-dev":
        return VerifierRuntimeService(
            executor=DeterministicDevVerifierExecutor(),
            worker_id=worker_id,
            poll_interval_seconds=poll_interval_seconds,
        )

    raise ValueError(f"Unsupported verifier autorun mode: {mode}")
