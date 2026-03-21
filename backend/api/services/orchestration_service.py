from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from uuid import uuid4

from api.app.database import session_scope
from api.app.db_models import OrchestrationSessionRecord, OrchestrationStepRecord
from api.repositories.orchestration_repository import OrchestrationRepository
from api.schemas.ai import AiPlanningRunRequest
from api.schemas.orchestration import (
    OrchestrationMode,
    OrchestrationSessionDetail,
    OrchestrationSessionSummary,
    OrchestrationStatus,
    OrchestrationStep,
    OrchestrationStepKind,
    OrchestrationStepStatus,
    StartOrchestrationRequest,
)
from api.services.planner_service import planner_service
from api.services.scan_service import scan_service
from api.services.verifier_job_service import verifier_job_service
from api.services.verifier_runtime_service import DeterministicDevVerifierExecutor, VerifierRuntimeService, build_runtime_service
from api.app.config import get_settings


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _session_record_to_summary(record: OrchestrationSessionRecord) -> OrchestrationSessionSummary:
    return OrchestrationSessionSummary(
        id=record.id,
        scan_id=record.scan_id,
        status=OrchestrationStatus(record.status),
        mode=OrchestrationMode(record.mode),
        provider_key=record.provider_key,
        current_phase=record.current_phase,
        max_verifier_cycles=record.max_verifier_cycles,
        completed_verifier_cycles=record.completed_verifier_cycles,
        started_at=record.started_at,
        completed_at=record.completed_at,
        last_error=record.last_error,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


def _step_record_to_model(record: OrchestrationStepRecord) -> OrchestrationStep:
    return OrchestrationStep(
        id=record.id,
        sequence=record.sequence,
        kind=OrchestrationStepKind(record.kind),
        status=OrchestrationStepStatus(record.status),
        title=record.title,
        detail=record.detail,
        payload=dict(record.payload_json),
        memory=dict(record.memory_json),
        created_at=record.created_at,
    )


@dataclass(slots=True)
class SessionRecorder:
    session_id: str
    scan_id: str
    provider_key: str | None
    request_payload: dict[str, object]
    max_verifier_cycles: int
    sequence: int = 0

    def create(self) -> None:
        now = _utc_now()
        with session_scope() as session:
            repository = OrchestrationRepository(session)
            repository.add_session(
                OrchestrationSessionRecord(
                    id=self.session_id,
                    scan_id=self.scan_id,
                    status=OrchestrationStatus.RUNNING.value,
                    mode=OrchestrationMode.AUTONOMOUS.value,
                    provider_key=self.provider_key,
                    current_phase=OrchestrationStepKind.PREPARE.value,
                    max_verifier_cycles=self.max_verifier_cycles,
                    completed_verifier_cycles=0,
                    request_json=self.request_payload,
                    memory_json={"planning_runs": [], "verifier_cycles": [], "notes": []},
                    started_at=now,
                    completed_at=None,
                    last_error=None,
                    created_at=now,
                    updated_at=now,
                )
            )

    def append_step(
        self,
        *,
        kind: OrchestrationStepKind,
        status: OrchestrationStepStatus,
        title: str,
        detail: str,
        payload: dict[str, object],
        memory_updates: dict[str, object] | None = None,
        current_phase: str | None = None,
        completed_verifier_cycles: int | None = None,
    ) -> None:
        self.sequence += 1
        now = _utc_now()
        with session_scope() as session:
            repository = OrchestrationRepository(session)
            session_record = repository.get_session(self.session_id)
            if session_record is None:
                raise RuntimeError("Orchestration session disappeared while recording steps.")

            memory = dict(session_record.memory_json)
            if memory_updates:
                for key, value in memory_updates.items():
                    if isinstance(value, list) and isinstance(memory.get(key), list):
                        memory[key] = [*memory.get(key, []), *value]
                    else:
                        memory[key] = value
            session_record.memory_json = memory
            session_record.current_phase = current_phase or kind.value
            if completed_verifier_cycles is not None:
                session_record.completed_verifier_cycles = completed_verifier_cycles
            session_record.updated_at = now

            repository.add_step(
                OrchestrationStepRecord(
                    session_id=self.session_id,
                    sequence=self.sequence,
                    kind=kind.value,
                    status=status.value,
                    title=title,
                    detail=detail,
                    payload_json=payload,
                    memory_json=memory,
                    created_at=now,
                )
            )

    def finalize(self, *, status: OrchestrationStatus, last_error: str | None = None) -> None:
        now = _utc_now()
        with session_scope() as session:
            repository = OrchestrationRepository(session)
            session_record = repository.get_session(self.session_id)
            if session_record is None:
                return
            session_record.status = status.value
            session_record.last_error = last_error
            session_record.completed_at = now
            session_record.updated_at = now


class OrchestrationService:
    def _build_runtime(self) -> VerifierRuntimeService:
        settings = get_settings()
        runtime = build_runtime_service(settings=settings)
        if runtime is not None:
            return runtime

        return VerifierRuntimeService(
            executor=DeterministicDevVerifierExecutor(),
            worker_id="orchestrator-fallback-runtime",
            poll_interval_seconds=0.1,
        )

    def list_sessions(self, scan_id: str) -> list[OrchestrationSessionSummary]:
        with session_scope() as session:
            records = OrchestrationRepository(session).list_sessions_for_scan(scan_id)
            return [_session_record_to_summary(record) for record in records]

    def get_session(self, session_id: str) -> OrchestrationSessionDetail | None:
        with session_scope() as session:
            repository = OrchestrationRepository(session)
            record = repository.get_session(session_id)
            if record is None:
                return None
            steps = repository.list_steps_for_session(session_id)
            return OrchestrationSessionDetail(
                **_session_record_to_summary(record).model_dump(),
                request=dict(record.request_json),
                memory=dict(record.memory_json),
                steps=[_step_record_to_model(step) for step in steps],
            )

    def start_session(self, scan_id: str, payload: StartOrchestrationRequest) -> OrchestrationSessionDetail | None:
        scan = scan_service.get_scan(scan_id)
        if scan is None:
            return None

        provider_key = payload.ai_provider_key or get_settings().ai_default_provider if payload.use_ai_planner else None
        session_id = f"orch-{uuid4().hex[:12]}"
        recorder = SessionRecorder(
            session_id=session_id,
            scan_id=scan_id,
            provider_key=provider_key,
            request_payload=payload.model_dump(mode="json"),
            max_verifier_cycles=payload.max_verifier_cycles,
        )
        recorder.create()

        try:
            recorder.append_step(
                kind=OrchestrationStepKind.PREPARE,
                status=OrchestrationStepStatus.COMPLETED,
                title="Prepare autonomous session",
                detail="Initialized autonomous pentest session state and selected orchestration settings.",
                payload={"scan_id": scan_id, "provider_key": provider_key},
            )

            deterministic_result = planner_service.run_workflow_planner(scan_id)
            if deterministic_result is not None:
                recorder.append_step(
                    kind=OrchestrationStepKind.DETERMINISTIC_PLANNER,
                    status=OrchestrationStepStatus.COMPLETED,
                    title="Run deterministic planner",
                    detail=f"Deterministic planner emitted {deterministic_result.emitted_count} paths from {deterministic_result.candidate_count} candidates.",
                    payload=deterministic_result.model_dump(mode="json"),
                    memory_updates={"planning_runs": [deterministic_result.planning_run_id]},
                )

            if payload.use_ai_planner:
                ai_result = planner_service.run_ai_workflow_planner(
                    scan_id,
                    AiPlanningRunRequest(
                        provider_key=payload.ai_provider_key,
                        apply=True,
                        candidate_limit=payload.ai_candidate_limit,
                        min_priority_score=payload.ai_min_priority_score,
                    ),
                )
                if ai_result is not None:
                    recorder.append_step(
                        kind=OrchestrationStepKind.AI_PLANNER,
                        status=OrchestrationStepStatus.COMPLETED,
                        title="Run AI-assisted planner",
                        detail=f"AI planner suggested {ai_result.suggested_count} paths and emitted {ai_result.emitted_count} paths.",
                        payload=ai_result.model_dump(mode="json"),
                        memory_updates={"planning_runs": [ai_result.planning_run_id]},
                    )
            else:
                recorder.append_step(
                    kind=OrchestrationStepKind.AI_PLANNER,
                    status=OrchestrationStepStatus.SKIPPED,
                    title="Skip AI-assisted planner",
                    detail="Autonomous session skipped AI planning because it was disabled in the request.",
                    payload={"use_ai_planner": False},
                )

            runtime = self._build_runtime()
            completed_cycles = 0
            for cycle_index in range(1, payload.max_verifier_cycles + 1):
                processed = runtime.run_once(scan_id=scan_id)
                if not processed:
                    recorder.append_step(
                        kind=OrchestrationStepKind.VERIFIER_CYCLE,
                        status=OrchestrationStepStatus.SKIPPED,
                        title=f"Verifier cycle {cycle_index}",
                        detail="No queued verifier jobs remained for this scan.",
                        payload={"cycle": cycle_index, "processed": False},
                        completed_verifier_cycles=completed_cycles,
                    )
                    break

                completed_cycles += 1
                recorder.append_step(
                    kind=OrchestrationStepKind.VERIFIER_CYCLE,
                    status=OrchestrationStepStatus.COMPLETED,
                    title=f"Verifier cycle {cycle_index}",
                    detail="Processed one queued verifier job in the autonomous loop.",
                    payload={"cycle": cycle_index, "processed": True},
                    memory_updates={"verifier_cycles": [cycle_index]},
                    completed_verifier_cycles=completed_cycles,
                )

            planning_run_count = len(planner_service.list_planning_runs(scan_id))
            queued_jobs_remaining = sum(
                1 for job in verifier_job_service.list_verifier_jobs(scan_id) if job.status in {"queued", "running"}
            )
            recorder.append_step(
                kind=OrchestrationStepKind.SUMMARY,
                status=OrchestrationStepStatus.COMPLETED,
                title="Finalize autonomous session",
                detail="Autonomous pentest session completed planning and verifier replay loops.",
                payload={
                    "planning_run_count": planning_run_count,
                    "completed_verifier_cycles": completed_cycles,
                    "queued_jobs_remaining": queued_jobs_remaining,
                },
                current_phase=OrchestrationStepKind.SUMMARY.value,
                completed_verifier_cycles=completed_cycles,
            )
            recorder.finalize(status=OrchestrationStatus.COMPLETED)
        except Exception as exc:
            recorder.append_step(
                kind=OrchestrationStepKind.SUMMARY,
                status=OrchestrationStepStatus.FAILED,
                title="Autonomous session failed",
                detail=str(exc),
                payload={"error": str(exc)},
            )
            recorder.finalize(status=OrchestrationStatus.FAILED, last_error=str(exc))

        return self.get_session(session_id)


orchestration_service = OrchestrationService()
