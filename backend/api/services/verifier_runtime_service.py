from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
from typing import Callable, Protocol

import httpx

from api.app.config import Settings
from api.schemas.events import EventSeverity, EventSource, RecordScanEventRequest
from api.schemas.findings import FindingEvidence, FindingSeverity
from api.schemas.verifier_jobs import ReplayPlan, ReplayRequestSpec
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
    def execute(self, job: VerifierJobDetail) -> VerifierExecutionOutcome: ...


@dataclass(frozen=True, slots=True)
class VerifierExecutionOutcome:
    confirmed: bool
    replay_result: VerifierReplayResult | None
    note: str


@dataclass(frozen=True, slots=True)
class ReplayHttpResult:
    request: ReplayRequestSpec
    url: str
    status_code: int
    body_excerpt: str


@dataclass(frozen=True, slots=True)
class DeterministicDevVerifierExecutor:
    def execute(self, job: VerifierJobDetail) -> VerifierExecutionOutcome:
        endpoint = _endpoint_from_job(job)
        status_code = 204 if endpoint and endpoint.startswith("DELETE ") else 200
        result = VerifierReplayResult(
            verifier_run_id=f"verify-{job.id}",
            scan_id=job.scan_id,
            finding_id=f"finding-{job.id}",
            title=job.title,
            category=_category_from_job(job),
            severity=job.severity,
            confidence=92 if job.severity == FindingSeverity.CRITICAL else 84,
            endpoint=endpoint,
            actor=(job.payload.replay_plan.actor if job.payload.replay_plan else None) or (job.payload.workflow_nodes[0].label if job.payload.workflow_nodes else None),
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
        return VerifierExecutionOutcome(
            confirmed=True,
            replay_result=result,
            note="Deterministic development executor confirmed the queued verifier job.",
        )


def _response_excerpt(text: str, *, limit: int = 240) -> str:
    compact = " ".join(text.split())
    return compact[:limit]


def _request_url(base_url: str | None, request_spec: ReplayRequestSpec) -> str:
    if request_spec.path.startswith("http://") or request_spec.path.startswith("https://"):
        return request_spec.path
    if base_url:
        return f"{base_url.rstrip('/')}{request_spec.path}"
    return f"https://{request_spec.host}{request_spec.path}"


def _default_http_transport(
    request_spec: ReplayRequestSpec,
    *,
    base_url: str | None,
    timeout_seconds: float,
    verify_tls: bool,
    headers: dict[str, str],
) -> ReplayHttpResult:
    url = _request_url(base_url, request_spec)
    response = httpx.request(
        request_spec.method.upper(),
        url,
        headers=headers,
        timeout=timeout_seconds,
        verify=verify_tls,
        follow_redirects=True,
    )
    return ReplayHttpResult(
        request=request_spec,
        url=str(response.url),
        status_code=response.status_code,
        body_excerpt=_response_excerpt(response.text),
    )


@dataclass(frozen=True, slots=True)
class HttpReplayVerifierExecutor:
    base_url: str | None
    actor_headers: dict[str, dict[str, str]]
    timeout_seconds: float = 5.0
    verify_tls: bool = True
    transport: Callable[..., ReplayHttpResult] = _default_http_transport

    def execute(self, job: VerifierJobDetail) -> VerifierExecutionOutcome:
        replay_plan = job.payload.replay_plan
        if replay_plan is None or not replay_plan.requests:
            return VerifierExecutionOutcome(
                confirmed=False,
                replay_result=None,
                note="No replay plan is attached to the verifier job.",
            )

        actor_key = replay_plan.actor or (replay_plan.requests[-1].actor if replay_plan.requests else None)
        actor_headers = self.actor_headers.get(actor_key or "", {})
        response_results = [
            self.transport(
                request_spec,
                base_url=self.base_url,
                timeout_seconds=self.timeout_seconds,
                verify_tls=self.verify_tls,
                headers=actor_headers,
            )
            for request_spec in replay_plan.requests
        ]
        final_result = response_results[-1]
        if final_result.status_code not in replay_plan.success_status_codes:
            return VerifierExecutionOutcome(
                confirmed=False,
                replay_result=None,
                note=(
                    f"Replay executor did not confirm the path because the final request returned "
                    f"HTTP {final_result.status_code} instead of one of {replay_plan.success_status_codes}."
                ),
            )

        evidence = [
            FindingEvidence(
                label=f"Replay {result.request.method.upper()} {result.request.path}",
                detail=f"{result.url} returned HTTP {result.status_code}. Response excerpt: {result.body_excerpt or '<empty>'}",
                source="verifier",
            )
            for result in response_results
        ]
        replay_result = VerifierReplayResult(
            verifier_run_id=f"verify-{job.id}",
            scan_id=job.scan_id,
            finding_id=f"finding-{job.id}",
            title=job.title,
            category=_category_from_job(job),
            severity=job.severity,
            confidence=95 if job.severity == FindingSeverity.CRITICAL else 87,
            endpoint=f"{final_result.request.method.upper()} {final_result.request.path}",
            actor=actor_key,
            request_fingerprint=final_result.request.request_fingerprint,
            request_summary=(
                f"Replayed {len(response_results)} requests for path {job.source_path_id}; "
                f"final response was HTTP {final_result.status_code}."
            ),
            response_status_code=final_result.status_code,
            message=f"HTTP replay verifier confirmed queued job {job.id}.",
            impact_summary=f"HTTP replay reproduced the risky path '{job.title}' with the provided actor credentials.",
            remediation_summary="Tighten authorization around the replayed path and add regression tests for the affected actor permissions.",
            description=(
                "The HTTP replay executor issued real requests against the configured target using the supplied actor headers "
                "and confirmed that the risky path remains reachable."
            ),
            impact="A low-privilege or externally scoped actor can execute the replayed path successfully against the live target.",
            remediation="Review the authorization checks for each replayed step and block the actor from reaching the final high-risk endpoint.",
            workflow_node_ids=list(job.payload.workflow_node_ids),
            evidence=evidence,
            tags=["http-replay", job.severity.value, *{node.phase for node in job.payload.workflow_nodes}],
        )
        return VerifierExecutionOutcome(
            confirmed=True,
            replay_result=replay_result,
            note="HTTP replay executor confirmed the queued verifier job.",
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
            outcome = self.executor.execute(job)
            if outcome.confirmed:
                result = outcome.replay_result
                if result is None:
                    raise RuntimeError("Executor reported confirmation without a replay result.")

                envelope = event_service.ingest_scan_event(job.scan_id, build_ingest_request(result))
                if envelope is None:
                    raise RuntimeError("Failed to ingest verifier finding into the backend runtime store.")

                finding_id = envelope.event.payload.get("finding_id") if envelope.event.payload else None
                verifier_job_service.complete_verifier_job(
                    job.id,
                    CompleteVerifierJobRequest(
                        verifier_run_id=result.verifier_run_id,
                        finding_id=str(finding_id) if finding_id is not None else result.finding_id,
                        note=outcome.note,
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
            else:
                verifier_job_service.complete_verifier_job(
                    job.id,
                    CompleteVerifierJobRequest(note=outcome.note),
                )
                event_service.record_scan_event(
                    job.scan_id,
                    RecordScanEventRequest(
                        source=EventSource.SYSTEM,
                        event_type="verifier_runtime.unconfirmed",
                        stage="verification",
                        severity=EventSeverity.INFO,
                        message=f"Automatic verifier runtime completed job {job.id} without confirmation.",
                        payload={"job_id": job.id, "note": outcome.note},
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


def build_runtime_service(*, settings: Settings) -> VerifierRuntimeService | None:
    mode = settings.verifier_autorun_mode
    worker_id = settings.verifier_autorun_worker_id
    poll_interval_seconds = settings.verifier_autorun_poll_interval
    normalized_mode = mode.strip().lower()
    if normalized_mode in {"", "disabled", "manual"}:
        return None
    if normalized_mode == "deterministic-dev":
        return VerifierRuntimeService(
            executor=DeterministicDevVerifierExecutor(),
            worker_id=worker_id,
            poll_interval_seconds=poll_interval_seconds,
        )
    if normalized_mode == "http-replay":
        if settings.verifier_replay_base_url is None:
            raise ValueError("AUDITOR_VERIFIER_REPLAY_BASE_URL must be configured for http-replay mode.")
        return VerifierRuntimeService(
            executor=HttpReplayVerifierExecutor(
                base_url=settings.verifier_replay_base_url,
                actor_headers=settings.verifier_replay_actor_headers,
                timeout_seconds=settings.verifier_replay_timeout,
                verify_tls=settings.verifier_replay_verify_tls,
            ),
            worker_id=worker_id,
            poll_interval_seconds=poll_interval_seconds,
        )

    raise ValueError(f"Unsupported verifier autorun mode: {mode}")
