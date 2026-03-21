from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from uuid import uuid4

from api.app.database import session_scope
from api.app.db_models import OrchestrationSessionRecord, OrchestrationStepRecord
from api.repositories.orchestration_repository import OrchestrationRepository
from api.schemas.ai import AiNextAction, AiNextActionRequest, AiOrchestrationMemory, AiPlanningRunRequest
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
from api.services.ai_provider_service import ai_provider_service
from api.services.event_service import event_service
from api.services.finding_service import finding_service
from api.services.planner_service import planner_service
from api.services.scan_service import scan_service
from api.services.verifier_job_service import verifier_job_service
from api.services.verifier_runtime_service import DeterministicDevVerifierExecutor, VerifierRuntimeService, build_runtime_service
from api.app.config import get_settings


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _memory_int(memory: dict[str, object], key: str) -> int:
    value = memory.get(key, 0)
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return 0


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
    initial_memory: dict[str, object]
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
                    memory_json=self.initial_memory,
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
    def _initial_memory(self) -> dict[str, object]:
        return {
            "planning_runs": [],
            "verifier_cycles": [],
            "notes": [],
            "decisions": [],
            "proxy_event_count": 0,
            "finding_count": 0,
            "pending_verifier_jobs": 0,
            "candidate_backlog": [],
            "unresolved_hypotheses": [],
            "verifier_outcomes": [],
            "deterministic_planning_runs": 0,
            "ai_planning_runs": 0,
            "last_deterministic_event_count": 0,
            "last_deterministic_candidate_count": 0,
            "last_ai_candidate_count": 0,
            "last_step_kind": None,
            "last_decision_source": None,
        }

    def _refresh_memory(self, scan_id: str, memory: dict[str, object]) -> dict[str, object]:
        refreshed = dict(memory)
        events = event_service.list_scan_events(scan_id, limit=1000)
        refreshed["proxy_event_count"] = sum(1 for event in events if event.event_type == "proxy.http_observed")
        refreshed["finding_count"] = len(finding_service.list_findings(scan_id=scan_id))
        job_summaries = verifier_job_service.list_verifier_jobs(scan_id)
        refreshed["pending_verifier_jobs"] = sum(1 for job in job_summaries if job.status.value in {"queued", "running"})
        refreshed["candidate_backlog"] = [
            {
                "path_id": detail.source_path_id,
                "title": detail.title,
                "vulnerability_class": detail.payload.vulnerability_class,
                "severity": detail.severity.value,
                "confidence": detail.payload.confidence,
                "verifier_strategy": detail.payload.verifier_strategy,
                "status": detail.status.value,
            }
            for job in job_summaries
            if job.status.value in {"queued", "running"}
            if (detail := verifier_job_service.get_verifier_job(job.id)) is not None
        ]
        refreshed["unresolved_hypotheses"] = list(refreshed["candidate_backlog"])
        refreshed["verifier_outcomes"] = [
            {
                "job_id": job.id,
                "status": job.status.value,
                "finding_id": job.finding_id,
                "verifier_run_id": job.verifier_run_id,
                "note": job.last_error,
            }
            for job in job_summaries
            if job.status.value in {"succeeded", "failed", "cancelled"}
        ]
        return refreshed

    def _deterministic_next_action(self, memory: dict[str, object], payload: StartOrchestrationRequest) -> tuple[OrchestrationStepKind, str]:
        proxy_event_count = _memory_int(memory, "proxy_event_count")
        last_deterministic_event_count = _memory_int(memory, "last_deterministic_event_count")
        deterministic_planning_runs = _memory_int(memory, "deterministic_planning_runs")
        ai_planning_runs = _memory_int(memory, "ai_planning_runs")
        last_deterministic_candidate_count = _memory_int(memory, "last_deterministic_candidate_count")
        last_ai_candidate_count = _memory_int(memory, "last_ai_candidate_count")
        pending_verifier_jobs = _memory_int(memory, "pending_verifier_jobs")
        completed_verifier_cycles = _memory_int(memory, "completed_verifier_cycles")

        if proxy_event_count > last_deterministic_event_count and deterministic_planning_runs < payload.max_planning_passes:
            return OrchestrationStepKind.DETERMINISTIC_PLANNER, "New proxy observations are available and have not yet been re-planned."

        if (
            payload.use_ai_planner
            and last_deterministic_candidate_count > last_ai_candidate_count
            and ai_planning_runs < payload.max_ai_planning_passes
        ):
            return OrchestrationStepKind.AI_PLANNER, "New deterministic candidates are available for AI prioritization."

        if pending_verifier_jobs > 0 and completed_verifier_cycles < payload.max_verifier_cycles:
            return OrchestrationStepKind.VERIFIER_CYCLE, "Queued verifier jobs remain and the cycle budget allows another replay iteration."

        return OrchestrationStepKind.SUMMARY, "No higher-priority autonomous action remains for the current memory state."

    def _ai_memory(self, memory: dict[str, object]) -> AiOrchestrationMemory:
        return AiOrchestrationMemory.model_validate(memory)

    def _choose_next_action(
        self,
        *,
        provider_key: str | None,
        memory: dict[str, object],
        payload: StartOrchestrationRequest,
    ) -> tuple[OrchestrationStepKind, dict[str, object]]:
        fallback_kind, fallback_reason = self._deterministic_next_action(memory, payload)
        if not payload.use_ai_decision:
            return fallback_kind, {
                "source": "deterministic",
                "provider_key": None,
                "confidence": 100,
                "rationale": fallback_reason,
                "supporting_observations": [],
            }

        try:
            decision_provider_key, decision = ai_provider_service.decide_next_action(
                AiNextActionRequest(
                    scan_id=memory.get("scan_id", "") or provider_key or "",
                    use_ai_planner=payload.use_ai_planner,
                    max_planning_passes=payload.max_planning_passes,
                    max_ai_planning_passes=payload.max_ai_planning_passes,
                    max_verifier_cycles=payload.max_verifier_cycles,
                    memory=self._ai_memory(memory),
                ),
                provider_key=provider_key,
            )
            mapping = {
                AiNextAction.DETERMINISTIC_PLANNER: OrchestrationStepKind.DETERMINISTIC_PLANNER,
                AiNextAction.AI_PLANNER: OrchestrationStepKind.AI_PLANNER,
                AiNextAction.VERIFIER_CYCLE: OrchestrationStepKind.VERIFIER_CYCLE,
                AiNextAction.SUMMARY: OrchestrationStepKind.SUMMARY,
            }
            return mapping[decision.next_action], {
                "source": "ai",
                "provider_key": decision_provider_key,
                "confidence": decision.confidence,
                "rationale": decision.rationale,
                "supporting_observations": list(decision.supporting_observations),
            }
        except Exception as exc:
            return fallback_kind, {
                "source": "deterministic-fallback",
                "provider_key": provider_key,
                "confidence": 100,
                "rationale": fallback_reason,
                "supporting_observations": [f"ai_decision_error: {exc}"],
            }

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
        memory = self._refresh_memory(scan_id, {**self._initial_memory(), "scan_id": scan_id})
        recorder = SessionRecorder(
            session_id=session_id,
            scan_id=scan_id,
            provider_key=provider_key,
            request_payload=payload.model_dump(mode="json"),
            max_verifier_cycles=payload.max_verifier_cycles,
            initial_memory=memory,
        )
        recorder.create()

        try:
            recorder.append_step(
                kind=OrchestrationStepKind.PREPARE,
                status=OrchestrationStepStatus.COMPLETED,
                title="Prepare autonomous session",
                detail="Initialized autonomous pentest session state and selected orchestration settings.",
                payload={"scan_id": scan_id, "provider_key": provider_key},
                memory_updates=memory,
            )

            runtime = self._build_runtime()
            max_total_actions = payload.max_verifier_cycles + payload.max_planning_passes + payload.max_ai_planning_passes + 8
            completed_cycles = 0
            for _ in range(max_total_actions):
                memory = self._refresh_memory(scan_id, memory)
                memory["completed_verifier_cycles"] = completed_cycles
                next_kind, decision_meta = self._choose_next_action(
                    provider_key=provider_key,
                    memory=memory,
                    payload=payload,
                )
                recorder.append_step(
                    kind=OrchestrationStepKind.DECISION,
                    status=OrchestrationStepStatus.COMPLETED,
                    title=f"Choose next action: {next_kind.value}",
                    detail=str(decision_meta["rationale"]),
                    payload={"next_action": next_kind.value, **decision_meta},
                    memory_updates={
                        "decisions": [{"next_action": next_kind.value, **decision_meta}],
                        "last_step_kind": next_kind.value,
                        "last_decision_source": decision_meta["source"],
                    },
                )

                if next_kind == OrchestrationStepKind.DETERMINISTIC_PLANNER:
                    deterministic_result = planner_service.run_workflow_planner(scan_id)
                    if deterministic_result is None:
                        raise RuntimeError("Deterministic planner could not run for this scan.")
                    memory = self._refresh_memory(scan_id, memory)
                    memory["deterministic_planning_runs"] = _memory_int(memory, "deterministic_planning_runs") + 1
                    memory["last_deterministic_event_count"] = _memory_int(memory, "proxy_event_count")
                    memory["last_deterministic_candidate_count"] = deterministic_result.candidate_count
                    recorder.append_step(
                        kind=OrchestrationStepKind.DETERMINISTIC_PLANNER,
                        status=OrchestrationStepStatus.COMPLETED,
                        title="Run deterministic planner",
                        detail=f"Deterministic planner emitted {deterministic_result.emitted_count} paths from {deterministic_result.candidate_count} candidates.",
                        payload=deterministic_result.model_dump(mode="json"),
                        memory_updates={
                            "planning_runs": [deterministic_result.planning_run_id],
                            "deterministic_planning_runs": memory["deterministic_planning_runs"],
                            "last_deterministic_event_count": memory["last_deterministic_event_count"],
                            "last_deterministic_candidate_count": memory["last_deterministic_candidate_count"],
                        },
                    )
                    continue

                if next_kind == OrchestrationStepKind.AI_PLANNER:
                    ai_result = planner_service.run_ai_workflow_planner(
                        scan_id,
                        AiPlanningRunRequest(
                            provider_key=payload.ai_provider_key,
                            apply=True,
                            candidate_limit=payload.ai_candidate_limit,
                            min_priority_score=payload.ai_min_priority_score,
                        ),
                    )
                    if ai_result is None:
                        raise RuntimeError("AI-assisted planner could not run for this scan.")
                    memory = self._refresh_memory(scan_id, memory)
                    memory["ai_planning_runs"] = _memory_int(memory, "ai_planning_runs") + 1
                    memory["last_ai_candidate_count"] = ai_result.candidate_count
                    recorder.append_step(
                        kind=OrchestrationStepKind.AI_PLANNER,
                        status=OrchestrationStepStatus.COMPLETED,
                        title="Run AI-assisted planner",
                        detail=f"AI planner suggested {ai_result.suggested_count} paths and emitted {ai_result.emitted_count} paths.",
                        payload=ai_result.model_dump(mode="json"),
                        memory_updates={
                            "planning_runs": [ai_result.planning_run_id],
                            "ai_planning_runs": memory["ai_planning_runs"],
                            "last_ai_candidate_count": memory["last_ai_candidate_count"],
                        },
                    )
                    continue

                if next_kind == OrchestrationStepKind.VERIFIER_CYCLE:
                    processed = runtime.run_once(scan_id=scan_id)
                    if not processed:
                        recorder.append_step(
                            kind=OrchestrationStepKind.VERIFIER_CYCLE,
                            status=OrchestrationStepStatus.SKIPPED,
                            title=f"Verifier cycle {completed_cycles + 1}",
                            detail="Verifier runtime had no processable job despite pending work metadata.",
                            payload={"cycle": completed_cycles + 1, "processed": False},
                            completed_verifier_cycles=completed_cycles,
                        )
                        continue

                    completed_cycles += 1
                    memory = self._refresh_memory(scan_id, memory)
                    recorder.append_step(
                        kind=OrchestrationStepKind.VERIFIER_CYCLE,
                        status=OrchestrationStepStatus.COMPLETED,
                        title=f"Verifier cycle {completed_cycles}",
                        detail="Processed one queued verifier job in the autonomous loop.",
                        payload={"cycle": completed_cycles, "processed": True},
                        memory_updates={"verifier_cycles": [completed_cycles]},
                        completed_verifier_cycles=completed_cycles,
                    )
                    continue

                break

            planning_run_count = len(planner_service.list_planning_runs(scan_id))
            queued_jobs_remaining = sum(
                1 for job in verifier_job_service.list_verifier_jobs(scan_id) if job.status.value in {"queued", "running"}
            )
            recorder.append_step(
                kind=OrchestrationStepKind.SUMMARY,
                status=OrchestrationStepStatus.COMPLETED,
                title="Finalize autonomous session",
                detail="Autonomous pentest session completed its dynamic planning and verifier loop.",
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
