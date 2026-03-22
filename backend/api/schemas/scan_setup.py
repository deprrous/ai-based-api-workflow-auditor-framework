from __future__ import annotations

from pydantic import BaseModel, Field

from api.schemas.artifacts import ApiSpecArtifactIngestRequest, SourceArtifactIngestRequest
from api.schemas.orchestration import OrchestrationSessionDetail, StartOrchestrationRequest
from api.schemas.scans import ScanRunSummary, StartScanRequest


class ScanActorProfileInput(BaseModel):
    actor_id: str = Field(min_length=3, max_length=120)
    label: str = Field(min_length=3, max_length=160)
    description: str | None = Field(default=None, max_length=500)
    headers: dict[str, str] = Field(default_factory=dict)


class ScanActorProfileDetail(BaseModel):
    id: str
    scan_id: str
    actor_id: str
    label: str
    description: str | None = None
    headers: dict[str, str]


class ScanSetupRequest(BaseModel):
    scan: StartScanRequest
    actors: list[ScanActorProfileInput] = Field(default_factory=list)
    source_artifacts: list[SourceArtifactIngestRequest] = Field(default_factory=list)
    api_spec_artifacts: list[ApiSpecArtifactIngestRequest] = Field(default_factory=list)
    start_orchestration: bool = True
    orchestration: StartOrchestrationRequest | None = None


class ScanSetupResponse(BaseModel):
    scan: ScanRunSummary
    actor_profiles: list[ScanActorProfileDetail]
    source_artifact_ids: list[str] = Field(default_factory=list)
    api_spec_artifact_ids: list[str] = Field(default_factory=list)
    orchestration_session: OrchestrationSessionDetail | None = None
