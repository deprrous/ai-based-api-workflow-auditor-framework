from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from api.schemas.findings import FindingSeverity


class VulnerabilityClass(StrEnum):
    BOLA_IDOR = "bola_idor"
    BFLA = "bfla"
    TENANT_ISOLATION = "tenant_isolation"
    MASS_ASSIGNMENT = "mass_assignment"
    EXCESSIVE_DATA_EXPOSURE = "excessive_data_exposure"
    UNSAFE_DESTRUCTIVE_ACTION = "unsafe_destructive_action"


class VerifierStrategy(StrEnum):
    DIRECT_OBJECT_REPLAY = "direct_object_replay"
    PRIVILEGE_TRANSITION_REPLAY = "privilege_transition_replay"
    TENANT_BOUNDARY_REPLAY = "tenant_boundary_replay"
    BODY_MUTATION_REPLAY = "body_mutation_replay"
    SENSITIVE_READ_REPLAY = "sensitive_read_replay"
    DESTRUCTIVE_ACTION_REPLAY = "destructive_action_replay"


class PlannerCandidateSummary(BaseModel):
    path_id: str
    title: str
    severity: FindingSeverity
    vulnerability_class: VulnerabilityClass
    confidence: int = Field(ge=0, le=100)
    matched_rule: str
    verifier_strategy: VerifierStrategy
    match_explanation: str
    matched_signals: list[str] = Field(default_factory=list)
    step_count: int = Field(ge=2)
    workflow_node_ids: list[str] = Field(default_factory=list)


class PlannerRunResponse(BaseModel):
    planning_run_id: str
    scan_id: str
    candidate_count: int
    emitted_count: int
    skipped_existing_count: int
    queued_job_count: int
    candidates: list[PlannerCandidateSummary]
