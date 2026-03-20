from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from api.schemas.findings import FindingSeverity
from api.schemas.workflows import WorkflowEdge, WorkflowNode


class VerifierJobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ReplayRequestSpec(BaseModel):
    request_fingerprint: str = Field(min_length=3, max_length=120)
    method: str = Field(min_length=2, max_length=16)
    host: str = Field(min_length=3, max_length=120)
    path: str = Field(min_length=1, max_length=400)
    actor: str | None = Field(default=None, max_length=120)


class ReplayPlan(BaseModel):
    actor: str | None = Field(default=None, max_length=120)
    requests: list[ReplayRequestSpec] = Field(default_factory=list)
    success_status_codes: list[int] = Field(default_factory=lambda: [200])


class VerifierJobPayload(BaseModel):
    path_id: str = Field(min_length=3, max_length=120)
    title: str = Field(min_length=3, max_length=200)
    rationale: str = Field(min_length=3, max_length=1500)
    workflow_node_ids: list[str] = Field(default_factory=list)
    workflow_nodes: list[WorkflowNode] = Field(default_factory=list)
    workflow_edges: list[WorkflowEdge] = Field(default_factory=list)
    replay_plan: ReplayPlan | None = None


class VerifierJobSummary(BaseModel):
    id: str
    scan_id: str
    source_path_id: str
    title: str
    severity: FindingSeverity
    status: VerifierJobStatus
    attempt_count: int
    max_attempts: int
    available_at: datetime
    claimed_at: datetime | None = None
    completed_at: datetime | None = None
    worker_id: str | None = None
    verifier_run_id: str | None = None
    finding_id: str | None = None
    last_error: str | None = None
    created_at: datetime
    updated_at: datetime


class VerifierJobDetail(VerifierJobSummary):
    rationale: str
    payload: VerifierJobPayload


class ClaimVerifierJobRequest(BaseModel):
    scan_id: str | None = Field(default=None, max_length=64)
    worker_id: str | None = Field(default=None, max_length=120)


class ClaimVerifierJobResponse(BaseModel):
    job: VerifierJobDetail | None = None


class CompleteVerifierJobRequest(BaseModel):
    verifier_run_id: str | None = Field(default=None, max_length=120)
    finding_id: str | None = Field(default=None, max_length=64)
    note: str | None = Field(default=None, max_length=500)


class FailVerifierJobRequest(BaseModel):
    error_message: str = Field(min_length=3, max_length=1000)
    retryable: bool = True
    retry_delay_seconds: int = Field(default=0, ge=0, le=3600)
