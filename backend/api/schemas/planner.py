from __future__ import annotations

from pydantic import BaseModel, Field

from api.schemas.findings import FindingSeverity


class PlannerCandidateSummary(BaseModel):
    path_id: str
    title: str
    severity: FindingSeverity
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
