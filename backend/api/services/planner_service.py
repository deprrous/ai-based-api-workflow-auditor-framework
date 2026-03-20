from __future__ import annotations

from dataclasses import dataclass

from api.schemas.ai import AiPlanningCandidate, AiPlanningProposal, AiPlanningRunRequest, AiPlanningRunResponse
from api.schemas.events import EventSeverity, RecordScanEventRequest
from api.schemas.planner import PlannerCandidateSummary, PlannerRunResponse
from api.schemas.planning_runs import PlanningMode, PlanningRunDetail, PlanningRunSummary
from api.services.ai_provider_service import ai_provider_service
from api.services.artifact_service import artifact_service
from api.services.event_service import event_service
from api.services.scan_service import scan_service
from api.services.store import audit_store
from api.services.verifier_job_service import verifier_job_service
from orchestrator.planners.workflow_path_planner import build_candidates_from_proxy_events
from tools.workflow.worker import WorkflowPathFindingCandidate, build_ingest_request


@dataclass(frozen=True, slots=True)
class PreparedPlannerCandidates:
    candidates: list[WorkflowPathFindingCandidate]
    existing_path_ids: set[str]


class PlannerService:
    def _prepare_candidates(self, scan_id: str) -> PreparedPlannerCandidates | None:
        scan = scan_service.get_scan(scan_id)
        if scan is None:
            return None

        events = event_service.list_scan_events(scan_id, limit=1000)
        candidates = build_candidates_from_proxy_events(scan_id, events)
        for candidate in candidates:
            final_step = candidate.steps[-1]
            if final_step.method is None or final_step.path is None:
                continue
            matches = artifact_service.match_artifacts(scan_id, method=final_step.method, path=final_step.path)
            if not matches:
                continue
            artifact_names = ", ".join(sorted({match.artifact_name for match in matches}))
            candidate.rationale = f"{candidate.rationale} Matched artifact context in: {artifact_names}."

        existing_path_ids = {
            str(event.payload.get("path_id"))
            for event in events
            if event.event_type == "workflow_mapper.path_flagged" and event.payload and event.payload.get("path_id")
        }
        existing_path_ids.update(job.source_path_id for job in verifier_job_service.list_verifier_jobs(scan_id))

        return PreparedPlannerCandidates(candidates=candidates, existing_path_ids=existing_path_ids)

    def _emit_candidates(
        self,
        scan_id: str,
        candidates: list[WorkflowPathFindingCandidate],
        *,
        existing_path_ids: set[str],
    ) -> tuple[int, int]:
        emitted_count = 0
        skipped_existing_count = 0

        for candidate in candidates:
            path_id = candidate.path_id or ""
            if path_id in existing_path_ids:
                skipped_existing_count += 1
                continue

            envelope = event_service.ingest_scan_event(scan_id, build_ingest_request(candidate))
            if envelope is not None:
                emitted_count += 1
                existing_path_ids.add(path_id)

        return emitted_count, skipped_existing_count

    def _candidate_summaries(self, candidates: list[WorkflowPathFindingCandidate]) -> list[PlannerCandidateSummary]:
        return [
            PlannerCandidateSummary(
                path_id=candidate.path_id or "",
                title=candidate.title,
                severity=candidate.severity,
                step_count=len(candidate.steps),
                workflow_node_ids=[step.node_id for step in candidate.steps],
            )
            for candidate in candidates
        ]

    def list_planning_runs(self, scan_id: str) -> list[PlanningRunSummary]:
        return audit_store.list_planning_runs(scan_id)

    def get_planning_run(self, planning_run_id: str) -> PlanningRunDetail | None:
        return audit_store.get_planning_run(planning_run_id)

    def run_workflow_planner(self, scan_id: str) -> PlannerRunResponse | None:
        prepared = self._prepare_candidates(scan_id)
        if prepared is None:
            return None

        queued_job_count_before = len(verifier_job_service.list_verifier_jobs(scan_id))
        emitted_count, skipped_existing_count = self._emit_candidates(
            scan_id,
            prepared.candidates,
            existing_path_ids=set(prepared.existing_path_ids),
        )
        queued_job_count_after = len(verifier_job_service.list_verifier_jobs(scan_id))
        candidate_summaries = self._candidate_summaries(prepared.candidates)
        event_service.record_scan_event(
            scan_id,
            RecordScanEventRequest(
                source="orchestrator",
                event_type="orchestrator.workflow_planner.completed",
                stage="reasoning",
                severity=EventSeverity.INFO if emitted_count == 0 else EventSeverity.WARNING,
                message=f"Workflow planner processed {len(prepared.candidates)} candidates and emitted {emitted_count} new flagged paths.",
                payload={
                    "candidate_count": len(prepared.candidates),
                    "emitted_count": emitted_count,
                    "skipped_existing_count": skipped_existing_count,
                },
            ),
        )

        planning_run = audit_store.create_planning_run(
            scan_id=scan_id,
            mode=PlanningMode.DETERMINISTIC,
            provider_key="deterministic",
            apply=True,
            candidate_count=len(prepared.candidates),
            suggested_count=len(prepared.candidates),
            emitted_count=emitted_count,
            skipped_existing_count=skipped_existing_count,
            queued_job_count=max(0, queued_job_count_after - queued_job_count_before),
            request_payload={"mode": "deterministic", "apply": True},
            candidates=candidate_summaries,
            proposals=[],
        )
        planning_run_id = planning_run.id if planning_run is not None else f"deterministic-{scan_id}"

        return PlannerRunResponse(
            planning_run_id=planning_run_id,
            scan_id=scan_id,
            candidate_count=len(prepared.candidates),
            emitted_count=emitted_count,
            skipped_existing_count=skipped_existing_count,
            queued_job_count=max(0, queued_job_count_after - queued_job_count_before),
            candidates=candidate_summaries,
        )

    def run_ai_workflow_planner(self, scan_id: str, payload: AiPlanningRunRequest) -> AiPlanningRunResponse | None:
        prepared = self._prepare_candidates(scan_id)
        if prepared is None:
            return None

        limited_candidates = prepared.candidates[: payload.candidate_limit]
        ai_candidates = [
            AiPlanningCandidate(
                path_id=candidate.path_id or "",
                title=candidate.title,
                severity=candidate.severity.value,
                rationale=candidate.rationale,
                step_count=len(candidate.steps),
                workflow_node_ids=[step.node_id for step in candidate.steps],
            )
            for candidate in limited_candidates
        ]
        provider_key, proposals = ai_provider_service.plan_candidates(
            ai_candidates,
            provider_key=payload.provider_key,
            min_priority_score=payload.min_priority_score,
        )

        proposals_by_path = {proposal.path_id: proposal for proposal in proposals}
        selected_candidates: list[WorkflowPathFindingCandidate] = []
        for candidate in limited_candidates:
            path_id = candidate.path_id or ""
            proposal = proposals_by_path.get(path_id)
            if proposal is None or not proposal.include_in_plan:
                continue

            candidate.rationale = f"{proposal.suggested_rationale} AI note: {proposal.explanation}"
            selected_candidates.append(candidate)

        queued_job_count_before = len(verifier_job_service.list_verifier_jobs(scan_id))
        emitted_count = 0
        skipped_existing_count = 0
        if payload.apply:
            emitted_count, skipped_existing_count = self._emit_candidates(
                scan_id,
                selected_candidates,
                existing_path_ids=set(prepared.existing_path_ids),
            )

        queued_job_count_after = len(verifier_job_service.list_verifier_jobs(scan_id))
        event_service.record_scan_event(
            scan_id,
            RecordScanEventRequest(
                source="orchestrator",
                event_type="orchestrator.ai_planner.completed",
                stage="reasoning",
                severity=EventSeverity.INFO if emitted_count == 0 else EventSeverity.WARNING,
                message=(
                    f"AI planner using provider {provider_key} processed {len(ai_candidates)} candidates and selected "
                    f"{len(selected_candidates)} paths."
                ),
                payload={
                    "provider_key": provider_key,
                    "candidate_count": len(ai_candidates),
                    "selected_count": len(selected_candidates),
                    "emitted_count": emitted_count,
                },
            ),
        )

        planning_run = audit_store.create_planning_run(
            scan_id=scan_id,
            mode=PlanningMode.AI_ASSISTED,
            provider_key=provider_key,
            apply=payload.apply,
            candidate_count=len(ai_candidates),
            suggested_count=len(selected_candidates),
            emitted_count=emitted_count,
            skipped_existing_count=skipped_existing_count,
            queued_job_count=max(0, queued_job_count_after - queued_job_count_before),
            request_payload=payload.model_dump(mode="json"),
            candidates=self._candidate_summaries(limited_candidates),
            proposals=proposals,
        )
        planning_run_id = planning_run.id if planning_run is not None else f"ai-{scan_id}"

        return AiPlanningRunResponse(
            planning_run_id=planning_run_id,
            scan_id=scan_id,
            provider_key=provider_key,
            candidate_count=len(ai_candidates),
            suggested_count=len(selected_candidates),
            emitted_count=emitted_count,
            skipped_existing_count=skipped_existing_count,
            apply=payload.apply,
            proposals=proposals,
        )


planner_service = PlannerService()
