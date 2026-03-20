from __future__ import annotations

from api.schemas.replay_artifacts import ReplayArtifactDetail
from api.services.store import audit_store


class ReplayArtifactService:
    def get_replay_artifact(self, artifact_id: str) -> ReplayArtifactDetail | None:
        return audit_store.get_replay_artifact(artifact_id)

    def list_replay_artifacts(self, scan_id: str) -> list[ReplayArtifactDetail]:
        return audit_store.list_replay_artifacts(scan_id)


replay_artifact_service = ReplayArtifactService()
