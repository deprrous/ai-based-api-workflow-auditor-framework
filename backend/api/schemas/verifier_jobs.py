from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from api.schemas.callbacks import CallbackSourceClass
from api.schemas.findings import FindingSeverity
from api.schemas.planner import VerifierStrategy, VulnerabilityClass
from api.schemas.workflows import WorkflowEdge, WorkflowNode


class VerifierJobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ReplayRequestSpec(BaseModel):
    artifact_id: str | None = Field(default=None, max_length=64)
    request_fingerprint: str = Field(min_length=3, max_length=120)
    method: str = Field(min_length=2, max_length=16)
    host: str = Field(min_length=3, max_length=120)
    path: str = Field(min_length=1, max_length=400)
    actor: str | None = Field(default=None, max_length=120)


class ReplayMutationType(StrEnum):
    PATH_REPLACE = "path_replace"
    QUERY_SET = "query_set"
    BODY_JSON_SET = "body_json_set"
    HEADER_SET = "header_set"
    ACTOR_SWITCH = "actor_switch"


class ReplayAssertionType(StrEnum):
    BODY_CONTAINS = "body_contains"
    BODY_REGEX = "body_regex"
    HEADER_CONTAINS = "header_contains"
    STATUS_IN = "status_in"
    DURATION_MS_GTE = "duration_ms_gte"
    STATUS_DIFFERS_FROM_BASELINE = "status_differs_from_baseline"
    BODY_DIFFERS_FROM_BASELINE = "body_differs_from_baseline"
    CALLBACK_RECEIVED = "callback_received"
    CALLBACK_METADATA_SCORE_GTE = "callback_metadata_score_gte"
    CALLBACK_SOURCE_CLASS_IN = "callback_source_class_in"


class ReplayMutationSpec(BaseModel):
    type: ReplayMutationType
    target_request_fingerprint: str | None = Field(default=None, max_length=120)
    from_value: str | None = Field(default=None, max_length=200)
    to_value: str | None = Field(default=None, max_length=200)
    body_field: str | None = Field(default=None, max_length=120)
    header_name: str | None = Field(default=None, max_length=120)
    query_param: str | None = Field(default=None, max_length=120)
    actor: str | None = Field(default=None, max_length=120)
    value: Any | None = None


class ReplayAssertionSpec(BaseModel):
    type: ReplayAssertionType
    target_request_fingerprint: str | None = Field(default=None, max_length=120)
    description: str = Field(min_length=3, max_length=500)
    expected_text: str | None = Field(default=None, max_length=500)
    regex_pattern: str | None = Field(default=None, max_length=500)
    header_name: str | None = Field(default=None, max_length=120)
    status_codes: list[int] = Field(default_factory=list)
    source_classes: list[CallbackSourceClass] = Field(default_factory=list)
    threshold_ms: int | None = Field(default=None, ge=0)
    callback_label: str | None = Field(default=None, max_length=120)
    wait_seconds: int = Field(default=0, ge=0, le=30)


class BrowserVisitSpec(BaseModel):
    path: str = Field(min_length=1, max_length=400)
    actor: str | None = Field(default=None, max_length=120)
    wait_seconds: int = Field(default=2, ge=0, le=30)
    callback_labels: list[str] = Field(default_factory=list)


class BrowserPlan(BaseModel):
    visits: list[BrowserVisitSpec] = Field(default_factory=list)


class ReplayPayloadVariant(BaseModel):
    id: str = Field(min_length=3, max_length=80)
    label: str = Field(min_length=3, max_length=160)
    description: str = Field(min_length=3, max_length=500)
    mutations: list[ReplayMutationSpec] = Field(default_factory=list)
    assertions: list[ReplayAssertionSpec] = Field(default_factory=list)
    browser_plan: BrowserPlan | None = None


class ReplayRefreshRequestSpec(BaseModel):
    method: str = Field(min_length=2, max_length=16)
    host: str = Field(min_length=3, max_length=120)
    path: str = Field(min_length=1, max_length=400)
    actor: str | None = Field(default=None, max_length=120)
    headers: dict[str, str] = Field(default_factory=dict)
    body_base64: str | None = None
    content_type: str | None = Field(default=None, max_length=160)


class ReplayPlan(BaseModel):
    actor: str | None = Field(default=None, max_length=120)
    requests: list[ReplayRequestSpec] = Field(default_factory=list)
    success_status_codes: list[int] = Field(default_factory=lambda: [200])
    mutations: list[ReplayMutationSpec] = Field(default_factory=list)
    assertions: list[ReplayAssertionSpec] = Field(default_factory=list)
    browser_plan: BrowserPlan | None = None
    variants: list[ReplayPayloadVariant] = Field(default_factory=list)
    refresh_requests: list[ReplayRefreshRequestSpec] = Field(default_factory=list)
    refresh_on_status_codes: list[int] = Field(default_factory=lambda: [401, 419, 440])
    retry_after_refresh: bool = True


class VerifierJobPayload(BaseModel):
    path_id: str = Field(min_length=3, max_length=120)
    title: str = Field(min_length=3, max_length=200)
    rationale: str = Field(min_length=3, max_length=1500)
    vulnerability_class: VulnerabilityClass
    confidence: int = Field(ge=0, le=100)
    matched_rule: str = Field(min_length=3, max_length=120)
    verifier_strategy: VerifierStrategy
    matched_signals: list[str] = Field(default_factory=list)
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
