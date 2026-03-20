from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, Field

from api.schemas.findings import FindingSeverity, FindingUpsert
from api.schemas.replay_artifacts import ReplayArtifactInput
from api.schemas.verifier_jobs import ReplayPlan
from api.schemas.workflows import WorkflowEdge, WorkflowNode


class ProxyHttpObservedContract(BaseModel):
    kind: Literal["proxy.http_observed"] = "proxy.http_observed"
    request_id: str = Field(min_length=3, max_length=120)
    request_fingerprint: str = Field(min_length=3, max_length=120)
    method: str = Field(min_length=2, max_length=16)
    host: str = Field(min_length=3, max_length=120)
    path: str = Field(min_length=1, max_length=240)
    status_code: int | None = Field(default=None, ge=100, le=599)
    actor: str | None = Field(default=None, max_length=120)
    node: WorkflowNode
    edge: WorkflowEdge | None = None
    replay_artifact: ReplayArtifactInput | None = None


class OrchestratorHypothesisCreatedContract(BaseModel):
    kind: Literal["orchestrator.hypothesis_created"] = "orchestrator.hypothesis_created"
    hypothesis_id: str = Field(min_length=3, max_length=120)
    category: str = Field(min_length=2, max_length=80)
    title: str = Field(min_length=3, max_length=200)
    confidence: int = Field(ge=0, le=100)
    rationale: str = Field(min_length=3, max_length=1500)
    node: WorkflowNode
    edges: list[WorkflowEdge] = Field(default_factory=list)


class WorkflowMapperPathFlaggedContract(BaseModel):
    kind: Literal["workflow_mapper.path_flagged"] = "workflow_mapper.path_flagged"
    path_id: str = Field(min_length=3, max_length=120)
    title: str = Field(min_length=3, max_length=200)
    severity: FindingSeverity
    rationale: str = Field(min_length=3, max_length=1500)
    nodes: list[WorkflowNode] = Field(default_factory=list)
    edges: list[WorkflowEdge] = Field(default_factory=list)
    flagged_paths_increment: int = Field(default=1, ge=0)
    replay_plan: ReplayPlan | None = None


class VerifierFindingConfirmedContract(BaseModel):
    kind: Literal["verifier.finding_confirmed"] = "verifier.finding_confirmed"
    verifier_run_id: str = Field(min_length=3, max_length=120)
    request_fingerprint: str | None = Field(default=None, max_length=120)
    request_summary: str | None = Field(default=None, max_length=800)
    response_status_code: int | None = Field(default=None, ge=100, le=599)
    finding: FindingUpsert
    finding_node: WorkflowNode | None = None
    edges: list[WorkflowEdge] = Field(default_factory=list)


ProducerContractPayload = Annotated[
    ProxyHttpObservedContract
    | OrchestratorHypothesisCreatedContract
    | WorkflowMapperPathFlaggedContract
    | VerifierFindingConfirmedContract,
    Field(discriminator="kind"),
]


class ProducerContractDefinition(BaseModel):
    kind: str
    source: str
    summary: str
    required_event_type: str


class ProducerContractCatalog(BaseModel):
    version: str
    definitions: list[ProducerContractDefinition]
