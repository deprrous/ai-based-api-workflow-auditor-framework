from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class FindingSeverity(StrEnum):
    REVIEW = "review"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    RESOLVED = "resolved"


class ContextReferenceKind(StrEnum):
    SOURCE_CODE = "source_code"
    API_SPEC = "api_spec"


class ContextReference(BaseModel):
    id: str = Field(min_length=3, max_length=120)
    kind: ContextReferenceKind
    label: str = Field(min_length=3, max_length=200)
    location: str = Field(min_length=1, max_length=300)
    excerpt: str = Field(min_length=3, max_length=2000)
    rationale: str = Field(min_length=3, max_length=800)


class FindingEvidence(BaseModel):
    label: str = Field(min_length=2, max_length=120)
    detail: str = Field(min_length=3, max_length=2000)
    source: str | None = Field(default=None, max_length=80)
    uri: str | None = Field(default=None, max_length=300)


class FindingSummary(BaseModel):
    id: str = Field(description="Stable finding identifier.")
    scan_id: str = Field(description="Owning scan identifier.")
    title: str = Field(description="Short human-readable finding title.")
    category: str = Field(description="Finding category such as bola or tenant_isolation.")
    severity: FindingSeverity = Field(description="Business-facing severity for the finding.")
    status: FindingStatus = Field(description="Current lifecycle status of the finding.")
    confidence: int = Field(ge=0, le=100, description="Confidence score for the finding.")
    endpoint: str | None = Field(default=None, description="Most relevant endpoint for the finding.")
    actor: str | None = Field(default=None, description="Actor or session involved in the finding.")
    impact_summary: str = Field(description="Short impact summary for list views.")
    remediation_summary: str = Field(description="Short remediation summary for list views.")
    evidence_count: int = Field(description="Number of evidence entries attached to the finding.")
    context_reference_count: int = Field(description="Number of source or spec context references attached to the finding.")
    created_at: datetime = Field(description="UTC timestamp when the finding was created.")
    updated_at: datetime = Field(description="UTC timestamp when the finding was last updated.")


class FindingDetail(FindingSummary):
    description: str = Field(description="Detailed description of the issue and exploit path.")
    impact: str = Field(description="Detailed impact explanation in developer-friendly language.")
    remediation: str = Field(description="Detailed remediation guidance or patch direction.")
    evidence: list[FindingEvidence] = Field(description="Evidence items supporting the finding.")
    context_references: list[ContextReference] = Field(description="Relevant source-code or API-spec references tied to the finding.")
    workflow_node_ids: list[str] = Field(description="Workflow nodes directly tied to this finding.")
    tags: list[str] = Field(description="Search and grouping tags attached to the finding.")


class FindingUpsert(BaseModel):
    id: str | None = Field(default=None, description="Optional identifier used when updating an existing finding.")
    title: str = Field(min_length=3, max_length=200)
    category: str = Field(min_length=2, max_length=80)
    severity: FindingSeverity
    status: FindingStatus = FindingStatus.CANDIDATE
    confidence: int = Field(ge=0, le=100)
    endpoint: str | None = Field(default=None, max_length=200)
    actor: str | None = Field(default=None, max_length=120)
    impact_summary: str = Field(min_length=3, max_length=280)
    remediation_summary: str = Field(min_length=3, max_length=280)
    description: str = Field(min_length=3, max_length=4000)
    impact: str = Field(min_length=3, max_length=4000)
    remediation: str = Field(min_length=3, max_length=4000)
    evidence: list[FindingEvidence] = Field(default_factory=list)
    context_references: list[ContextReference] = Field(default_factory=list)
    workflow_node_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
