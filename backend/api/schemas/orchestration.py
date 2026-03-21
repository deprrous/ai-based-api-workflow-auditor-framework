from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class OrchestrationMode(StrEnum):
    AUTONOMOUS = "autonomous"


class OrchestrationStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class OrchestrationStepStatus(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


class OrchestrationStepKind(StrEnum):
    PREPARE = "prepare"
    DECISION = "decision"
    DETERMINISTIC_PLANNER = "deterministic_planner"
    AI_PLANNER = "ai_planner"
    HYPOTHESIS_SELECTION = "hypothesis_selection"
    VERIFIER_CYCLE = "verifier_cycle"
    SUMMARY = "summary"


class StartOrchestrationRequest(BaseModel):
    use_ai_planner: bool = True
    use_ai_decision: bool = True
    use_ai_hypothesis_selection: bool = True
    ai_provider_key: str | None = None
    max_planning_passes: int = Field(default=2, ge=1, le=10)
    max_ai_planning_passes: int = Field(default=1, ge=0, le=10)
    max_verifier_cycles: int = Field(default=10, ge=1, le=100)
    ai_candidate_limit: int = Field(default=8, ge=1, le=50)
    ai_min_priority_score: int = Field(default=50, ge=0, le=100)


class OrchestrationStep(BaseModel):
    id: int
    sequence: int
    kind: OrchestrationStepKind
    status: OrchestrationStepStatus
    title: str
    detail: str
    payload: dict[str, object]
    memory: dict[str, object]
    created_at: datetime


class OrchestrationSessionSummary(BaseModel):
    id: str
    scan_id: str
    status: OrchestrationStatus
    mode: OrchestrationMode
    provider_key: str | None = None
    current_phase: str
    max_verifier_cycles: int
    completed_verifier_cycles: int
    started_at: datetime
    completed_at: datetime | None = None
    last_error: str | None = None
    created_at: datetime
    updated_at: datetime


class OrchestrationSessionDetail(OrchestrationSessionSummary):
    request: dict[str, object]
    memory: dict[str, object]
    steps: list[OrchestrationStep]
