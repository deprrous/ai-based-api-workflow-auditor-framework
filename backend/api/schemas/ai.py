from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class AiProviderKind(StrEnum):
    MOCK = "mock"
    OPENAI_COMPATIBLE = "openai_compatible"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    LOCAL = "local"


class AiCapability(StrEnum):
    CHAT = "chat"
    TOOL_CALLING = "tool_calling"
    JSON_OUTPUT = "json_output"
    EMBEDDINGS = "embeddings"


class AiProviderDescriptor(BaseModel):
    key: str
    kind: AiProviderKind
    display_name: str
    description: str
    capabilities: list[AiCapability]
    config_fields: list[str] = Field(default_factory=list)


class AiProviderCatalog(BaseModel):
    version: str
    providers: list[AiProviderDescriptor]


class AiPlanningCandidate(BaseModel):
    path_id: str
    title: str
    severity: str
    rationale: str
    step_count: int = Field(ge=2)
    workflow_node_ids: list[str] = Field(default_factory=list)


class AiPlanningProposal(BaseModel):
    path_id: str
    include_in_plan: bool = True
    priority_score: int = Field(ge=0, le=100)
    recommended_severity: str
    suggested_rationale: str
    explanation: str
    tags: list[str] = Field(default_factory=list)


class AiPlanningRunRequest(BaseModel):
    provider_key: str | None = None
    apply: bool = True
    candidate_limit: int = Field(default=8, ge=1, le=50)
    min_priority_score: int = Field(default=50, ge=0, le=100)


class AiPlanningRunResponse(BaseModel):
    planning_run_id: str
    scan_id: str
    provider_key: str
    candidate_count: int
    suggested_count: int
    emitted_count: int
    skipped_existing_count: int
    apply: bool
    proposals: list[AiPlanningProposal]
