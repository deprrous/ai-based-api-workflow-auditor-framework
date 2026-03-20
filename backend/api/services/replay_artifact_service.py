from __future__ import annotations

import asyncio
from dataclasses import dataclass

from api.app.config import Settings, get_settings
from api.schemas.replay_artifacts import ReplayArtifactDetail, ReplayArtifactMaterial
from api.services.replay_artifact_policy import build_body_preview, redact_headers, redact_response_excerpt
from api.services.store import audit_store


def _to_public_detail(material: ReplayArtifactMaterial, settings: Settings) -> ReplayArtifactDetail:
    return ReplayArtifactDetail(
        id=material.id,
        scan_id=material.scan_id,
        request_fingerprint=material.request_fingerprint,
        actor=material.actor,
        method=material.method,
        host=material.host,
        path=material.path,
        request_headers=redact_headers(material.request_headers, settings.replay_artifact_redact_headers),
        request_body_preview=build_body_preview(
            material.request_body_base64,
            content_type=material.request_content_type,
            sensitive_body_keys=settings.replay_artifact_redact_body_keys,
        ),
        request_content_type=material.request_content_type,
        response_status_code=material.response_status_code,
        response_headers=redact_headers(material.response_headers, settings.replay_artifact_redact_headers),
        response_body_excerpt=redact_response_excerpt(
            material.response_body_excerpt,
            sensitive_body_keys=settings.replay_artifact_redact_body_keys,
        ),
        replayable=material.replayable,
        expires_at=material.expires_at,
        purged_at=material.purged_at,
        created_at=material.created_at,
    )


class ReplayArtifactService:
    def get_replay_artifact(self, artifact_id: str) -> ReplayArtifactDetail | None:
        material = audit_store.get_replay_artifact_material(artifact_id)
        if material is None:
            return None
        return _to_public_detail(material, get_settings())

    def get_replay_artifact_material(self, artifact_id: str) -> ReplayArtifactMaterial | None:
        return audit_store.get_replay_artifact_material(artifact_id)

    def list_replay_artifacts(self, scan_id: str) -> list[ReplayArtifactDetail]:
        settings = get_settings()
        return [_to_public_detail(material, settings) for material in audit_store.list_replay_artifact_materials(scan_id)]

    def purge_expired_replay_artifacts(self) -> int:
        return audit_store.purge_expired_replay_artifacts()


@dataclass(slots=True)
class ReplayArtifactRetentionService:
    poll_interval_seconds: float
    _stop_event: asyncio.Event | None = None

    def run_once(self) -> int:
        return replay_artifact_service.purge_expired_replay_artifacts()

    async def run_forever(self) -> None:
        if self._stop_event is None:
            self._stop_event = asyncio.Event()

        while not self._stop_event.is_set():
            purged = self.run_once()
            if purged == 0:
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=self.poll_interval_seconds)
                except TimeoutError:
                    continue

    def stop(self) -> None:
        if self._stop_event is not None:
            self._stop_event.set()


def build_retention_service(*, settings: Settings) -> ReplayArtifactRetentionService | None:
    if not settings.replay_artifact_retention_autorun_enabled:
        return None

    return ReplayArtifactRetentionService(
        poll_interval_seconds=settings.replay_artifact_retention_poll_interval,
    )


replay_artifact_service = ReplayArtifactService()
