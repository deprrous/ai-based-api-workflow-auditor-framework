from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class ArtifactKind(StrEnum):
    SOURCE_CODE = "source_code"
    API_SPEC = "api_spec"


class ArtifactRiskCategory(StrEnum):
    SQLI = "sqli"
    SSRF = "ssrf"
    STORED_XSS = "stored_xss"
    REFLECTED_XSS = "reflected_xss"


class ArtifactRiskIndicatorSummary(BaseModel):
    category: ArtifactRiskCategory
    summary: str
    location: str
    confidence: int = Field(ge=0, le=100)
    route_method: str | None = Field(default=None, max_length=16)
    route_path: str | None = Field(default=None, max_length=400)
    tags: list[str] = Field(default_factory=list)


class ArtifactTaintFlowSummary(BaseModel):
    category: ArtifactRiskCategory
    source_summary: str
    source_location: str
    sink_summary: str
    sink_location: str
    route_method: str | None = Field(default=None, max_length=16)
    route_path: str | None = Field(default=None, max_length=400)
    confidence: int = Field(ge=0, le=100)
    rationale: str
    tags: list[str] = Field(default_factory=list)


class ArtifactRouteSummary(BaseModel):
    method: str = Field(min_length=2, max_length=16)
    path: str = Field(min_length=1, max_length=400)
    source: str = Field(min_length=3, max_length=200)


class ArtifactSummary(BaseModel):
    id: str
    scan_id: str
    kind: ArtifactKind
    name: str
    path: str | None = None
    language: str | None = None
    format: str | None = None
    checksum: str
    route_count: int
    auth_scheme_count: int
    risk_indicator_count: int
    taint_flow_count: int
    created_at: datetime
    updated_at: datetime


class ArtifactDetail(ArtifactSummary):
    content_excerpt: str
    parsed_summary: dict[str, object]
    risk_indicators: list[ArtifactRiskIndicatorSummary]
    taint_flows: list[ArtifactTaintFlowSummary]


class SourceArtifactIngestRequest(BaseModel):
    name: str = Field(min_length=3, max_length=200)
    path: str | None = Field(default=None, max_length=300)
    language: str = Field(min_length=2, max_length=60)
    content: str = Field(min_length=3, max_length=200000)


class ApiSpecArtifactIngestRequest(BaseModel):
    name: str = Field(min_length=3, max_length=200)
    path: str | None = Field(default=None, max_length=300)
    format: str = Field(min_length=2, max_length=40)
    content: str = Field(min_length=3, max_length=400000)


class ArtifactMatchReference(BaseModel):
    kind: ArtifactKind
    artifact_id: str
    artifact_name: str
    route: ArtifactRouteSummary | None = None
    rationale: str
    risk_indicators: list[ArtifactRiskIndicatorSummary] = Field(default_factory=list)
    taint_flows: list[ArtifactTaintFlowSummary] = Field(default_factory=list)
