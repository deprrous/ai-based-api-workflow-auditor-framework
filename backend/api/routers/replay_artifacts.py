from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from api.app.security import require_verifier_job_token
from api.schemas.replay_artifacts import ReplayArtifactDetail
from api.services.replay_artifact_service import replay_artifact_service
from api.services.scan_service import scan_service

router = APIRouter(prefix="/replay-artifacts", tags=["replay-artifacts"])


@router.get("/{artifact_id}", response_model=ReplayArtifactDetail, summary="Read replay artifact detail")
async def get_replay_artifact(artifact_id: str, _: None = Depends(require_verifier_job_token)) -> ReplayArtifactDetail:
    artifact = replay_artifact_service.get_replay_artifact(artifact_id)
    if artifact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Replay artifact not found.")

    return artifact


@router.get("/scan/{scan_id}", response_model=list[ReplayArtifactDetail], summary="List replay artifacts for a scan")
async def list_replay_artifacts(scan_id: str, _: None = Depends(require_verifier_job_token)) -> list[ReplayArtifactDetail]:
    scan = scan_service.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan run not found.")

    return replay_artifact_service.list_replay_artifacts(scan_id)
