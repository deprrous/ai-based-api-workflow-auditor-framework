from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from api.schemas.findings import ContextReference, FindingEvidence, FindingSeverity


class VerifierRunStatus(StrEnum):
    CONFIRMED = "confirmed"


class VerifierRunSummary(BaseModel):
    id: str
    scan_id: str
    finding_id: str | None = None
    status: VerifierRunStatus
    category: str
    severity: FindingSeverity
    confidence: int = Field(ge=0, le=100)
    title: str
    endpoint: str | None = None
    actor: str | None = None
    request_fingerprint: str | None = None
    response_status_code: int | None = None
    evidence_count: int
    context_reference_count: int
    created_at: datetime
    updated_at: datetime


class VerifierRunDetail(VerifierRunSummary):
    request_summary: str | None = None
    evidence: list[FindingEvidence]
    context_references: list[ContextReference]
    workflow_node_ids: list[str]
