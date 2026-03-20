from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from api.schemas.artifacts import ApiSpecArtifactIngestRequest, ArtifactDetail, ArtifactKind, ArtifactSummary, SourceArtifactIngestRequest
from api.services.artifact_service import artifact_service
from api.services.scan_service import scan_service

router = APIRouter(prefix="/artifacts", tags=["artifacts"])


@router.get("/scan/{scan_id}", response_model=list[ArtifactSummary], summary="List ingested artifacts for a scan")
async def list_artifacts(
    scan_id: str,
    kind: ArtifactKind | None = Query(default=None, description="Optional artifact kind filter."),
) -> list[ArtifactSummary]:
    scan = scan_service.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan run not found.")

    return artifact_service.list_artifacts(scan_id, kind=kind)


@router.get("/{artifact_id}", response_model=ArtifactDetail, summary="Read artifact detail")
async def get_artifact(artifact_id: str) -> ArtifactDetail:
    artifact = artifact_service.get_artifact(artifact_id)
    if artifact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found.")

    return artifact


@router.post("/scan/{scan_id}/source", response_model=ArtifactDetail, status_code=status.HTTP_201_CREATED, summary="Ingest source artifact")
async def ingest_source_artifact(scan_id: str, payload: SourceArtifactIngestRequest) -> ArtifactDetail:
    artifact = artifact_service.ingest_source_artifact(scan_id, payload)
    if artifact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan run not found.")

    return artifact


@router.post("/scan/{scan_id}/api-spec", response_model=ArtifactDetail, status_code=status.HTTP_201_CREATED, summary="Ingest API spec artifact")
async def ingest_api_spec_artifact(scan_id: str, payload: ApiSpecArtifactIngestRequest) -> ArtifactDetail:
    artifact = artifact_service.ingest_api_spec_artifact(scan_id, payload)
    if artifact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan run not found.")

    return artifact
