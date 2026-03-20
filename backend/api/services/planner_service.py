from __future__ import annotations

from api.schemas.events import EventSeverity, RecordScanEventRequest
from api.schemas.planner import PlannerCandidateSummary, PlannerRunResponse
from api.services.artifact_service import artifact_service
from api.services.event_service import event_service
from api.services.scan_service import scan_service
from api.services.verifier_job_service import verifier_job_service
from orchestrator.planners.workflow_path_planner import build_candidates_from_proxy_events
from tools.workflow.worker import build_ingest_request


class PlannerService:
    def run_workflow_planner(self, scan_id: str) -> PlannerRunResponse | None:
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

        emitted_count = 0
        queued_job_count_before = len(verifier_job_service.list_verifier_jobs(scan_id))
        candidate_summaries = [
            PlannerCandidateSummary(
                path_id=candidate.path_id or "",
                title=candidate.title,
                severity=candidate.severity,
                step_count=len(candidate.steps),
                workflow_node_ids=[step.node_id for step in candidate.steps],
            )
            for candidate in candidates
        ]

        for candidate in candidates:
            path_id = candidate.path_id or ""
            if path_id in existing_path_ids:
                continue

            envelope = event_service.ingest_scan_event(scan_id, build_ingest_request(candidate))
            if envelope is not None:
                emitted_count += 1
                existing_path_ids.add(path_id)

        queued_job_count_after = len(verifier_job_service.list_verifier_jobs(scan_id))
        event_service.record_scan_event(
            scan_id,
            RecordScanEventRequest(
                source="orchestrator",
                event_type="orchestrator.workflow_planner.completed",
                stage="reasoning",
                severity=EventSeverity.INFO if emitted_count == 0 else EventSeverity.WARNING,
                message=f"Workflow planner processed {len(candidates)} candidates and emitted {emitted_count} new flagged paths.",
                payload={
                    "candidate_count": len(candidates),
                    "emitted_count": emitted_count,
                    "skipped_existing_count": len(candidates) - emitted_count,
                },
            ),
        )

        return PlannerRunResponse(
            scan_id=scan_id,
            candidate_count=len(candidates),
            emitted_count=emitted_count,
            skipped_existing_count=len(candidates) - emitted_count,
            queued_job_count=max(0, queued_job_count_after - queued_job_count_before),
            candidates=candidate_summaries,
        )


planner_service = PlannerService()
