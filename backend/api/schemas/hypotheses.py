from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from api.schemas.planner import VerifierStrategy, VulnerabilityClass


class HypothesisStatus(StrEnum):
    NEW = "new"
    PRIORITIZED = "prioritized"
    DOWNGRADED = "downgraded"
    VERIFYING = "verifying"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    ABANDONED = "abandoned"
    MERGED = "merged"


class HypothesisSummary(BaseModel):
    id: str
    scan_id: str
    session_id: str | None = None
    planning_run_id: str | None = None
    source_path_id: str
    title: str
    vulnerability_class: VulnerabilityClass
    severity: str
    confidence: int = Field(ge=0, le=100)
    matched_rule: str
    verifier_strategy: VerifierStrategy
    status: HypothesisStatus
    canonical_key: str
    selected_payload_variant_id: str | None = None
    selected_verifier_strategy: VerifierStrategy | None = None
    decision_source: str | None = None
    verifier_job_id: str | None = None
    finding_id: str | None = None
    merged_into_hypothesis_id: str | None = None
    attempt_count: int = 0
    failure_count: int = 0
    reopen_count: int = 0
    stale_cycles: int = 0
    last_transition_reason: str | None = None
    created_at: datetime
    updated_at: datetime


class HypothesisDetail(HypothesisSummary):
    rationale: str
    matched_signals: list[str] = Field(default_factory=list)
