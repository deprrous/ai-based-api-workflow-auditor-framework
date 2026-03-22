from __future__ import annotations

from api.schemas.scan_setup import ScanSetupRequest, ScanSetupResponse
from api.schemas.orchestration import StartOrchestrationRequest
from api.services.artifact_service import artifact_service
from api.services.orchestration_service import orchestration_service
from api.services.scan_service import scan_service


class ScanSetupService:
    def setup_scan(self, payload: ScanSetupRequest) -> ScanSetupResponse:
        scan = scan_service.start_scan(payload.scan)
        actor_profiles = scan_service.upsert_scan_actor_profiles(scan.id, payload.actors)

        source_artifact_ids: list[str] = []
        for artifact in payload.source_artifacts:
            created = artifact_service.ingest_source_artifact(scan.id, artifact)
            if created is not None:
                source_artifact_ids.append(created.id)

        api_spec_artifact_ids: list[str] = []
        for artifact in payload.api_spec_artifacts:
            created = artifact_service.ingest_api_spec_artifact(scan.id, artifact)
            if created is not None:
                api_spec_artifact_ids.append(created.id)

        orchestration_session = None
        if payload.start_orchestration:
            orchestration_session = orchestration_service.start_session(
                scan.id,
                payload.orchestration
                or StartOrchestrationRequest(
                    use_ai_planner=True,
                    use_ai_decision=True,
                    use_ai_hypothesis_selection=True,
                    max_planning_passes=2,
                    max_ai_planning_passes=1,
                    max_verifier_cycles=10,
                    ai_candidate_limit=8,
                    ai_min_priority_score=50,
                ),
            )

        updated_scan = scan_service.get_scan(scan.id) or scan
        return ScanSetupResponse(
            scan=updated_scan,
            actor_profiles=actor_profiles,
            source_artifact_ids=source_artifact_ids,
            api_spec_artifact_ids=api_spec_artifact_ids,
            orchestration_session=orchestration_session,
        )


scan_setup_service = ScanSetupService()
