from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from api.schemas.ai import AiPlanningProposal, AiPlanningRunRequest
from api.schemas.planner import PlannerCandidateSummary


class PlanningMode(StrEnum):
    DETERMINISTIC = "deterministic"
    AI_ASSISTED = "ai_assisted"


class PlanningRunSummary(BaseModel):
    id: str
    scan_id: str
    mode: PlanningMode
    provider_key: str
    apply: bool
    candidate_count: int
    suggested_count: int
    emitted_count: int
    skipped_existing_count: int
    queued_job_count: int
    created_at: datetime
    updated_at: datetime


class PlanningRunDetail(PlanningRunSummary):
    request: dict[str, object]
    candidates: list[PlannerCandidateSummary]
    proposals: list[AiPlanningProposal]


class DeterministicPlanningRequest(BaseModel):
    apply: bool = True


class DeterministicPlanningRunResponse(BaseModel):
    planning_run_id: str
    scan_id: str
    candidate_count: int
    emitted_count: int
    skipped_existing_count: int
    queued_job_count: int
    apply: bool
    candidates: list[PlannerCandidateSummary]


class AiPlanningHistoryRequest(AiPlanningRunRequest):
    pass
