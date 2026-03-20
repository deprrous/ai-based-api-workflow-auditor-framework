from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Callable
from urllib import error, request

from pydantic import BaseModel, Field, model_validator

from api.schemas.events import EventSeverity, EventSource, IngestScanEventRequest
from api.schemas.findings import ContextReference, FindingEvidence, FindingSeverity, FindingStatus, FindingUpsert
from api.schemas.verifier_jobs import ClaimVerifierJobRequest, ClaimVerifierJobResponse, CompleteVerifierJobRequest, FailVerifierJobRequest, VerifierJobDetail
from api.schemas.producer_contracts import VerifierFindingConfirmedContract
from api.schemas.workflows import WorkflowEdge, WorkflowNode, WorkflowNodeStatus, WorkflowNodeType
from tools.analyzer.correlation import CorrelationCandidate, CorrelationInput, build_context_references


def _status_from_severity(severity: FindingSeverity) -> WorkflowNodeStatus:
    if severity == FindingSeverity.CRITICAL:
        return WorkflowNodeStatus.CRITICAL
    if severity == FindingSeverity.HIGH:
        return WorkflowNodeStatus.HIGH
    return WorkflowNodeStatus.REVIEW


def _event_severity_from_finding(severity: FindingSeverity) -> EventSeverity:
    if severity == FindingSeverity.CRITICAL:
        return EventSeverity.CRITICAL
    if severity == FindingSeverity.HIGH:
        return EventSeverity.HIGH
    return EventSeverity.WARNING


def _stable_suffix(value: str, *, length: int = 12) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest()[:length]


def _stable_y(value: str) -> float:
    digest = int(hashlib.sha1(value.encode("utf-8")).hexdigest()[:6], 16)
    return float(160 + ((digest % 7) * 96))


class VerifierReplayResult(BaseModel):
    verifier_run_id: str = Field(min_length=3, max_length=120)
    scan_id: str = Field(min_length=3, max_length=64)
    finding_id: str | None = Field(default=None, max_length=64)
    title: str = Field(min_length=3, max_length=200)
    category: str = Field(min_length=2, max_length=80)
    severity: FindingSeverity
    confidence: int = Field(ge=0, le=100)
    endpoint: str | None = Field(default=None, max_length=200)
    actor: str | None = Field(default=None, max_length=120)
    request_fingerprint: str | None = Field(default=None, max_length=120)
    request_summary: str | None = Field(default=None, max_length=800)
    response_status_code: int | None = Field(default=None, ge=100, le=599)
    message: str = Field(min_length=3, max_length=500)
    impact_summary: str = Field(min_length=3, max_length=280)
    remediation_summary: str = Field(min_length=3, max_length=280)
    description: str = Field(min_length=3, max_length=4000)
    impact: str = Field(min_length=3, max_length=4000)
    remediation: str = Field(min_length=3, max_length=4000)
    workflow_node_ids: list[str] = Field(min_length=1)
    evidence: list[FindingEvidence] = Field(min_length=1)
    tags: list[str] = Field(default_factory=list)
    source_candidates: list[CorrelationCandidate] = Field(default_factory=list)
    spec_candidates: list[CorrelationCandidate] = Field(default_factory=list)
    finding_node_id: str | None = Field(default=None, max_length=64)
    finding_node_label: str | None = Field(default=None, max_length=200)
    finding_node_x: float | None = None
    finding_node_y: float | None = None

    @model_validator(mode="after")
    def validate_accuracy_constraints(self) -> VerifierReplayResult:
        if not self.workflow_node_ids:
            raise ValueError("Confirmed verifier findings must attach at least one workflow node.")
        if not self.evidence:
            raise ValueError("Confirmed verifier findings must include evidence.")
        return self


def build_context_for_result(result: VerifierReplayResult) -> list[ContextReference]:
    correlation_input = CorrelationInput(
        endpoint=result.endpoint,
        title=result.title,
        category=result.category,
        tags=result.tags,
        source_candidates=result.source_candidates,
        spec_candidates=result.spec_candidates,
    )
    return build_context_references(correlation_input)


def build_finding_node(result: VerifierReplayResult) -> WorkflowNode:
    node_id = result.finding_node_id or f"finding-node-{_stable_suffix(result.finding_id or result.title)}"
    label = result.finding_node_label or f"Finding: {result.title}"

    return WorkflowNode(
        id=node_id,
        label=label,
        type=WorkflowNodeType.FINDING,
        phase="reporting",
        detail=result.impact_summary,
        status=_status_from_severity(result.severity),
        x=result.finding_node_x if result.finding_node_x is not None else 2040.0,
        y=result.finding_node_y if result.finding_node_y is not None else _stable_y(result.finding_id or result.title),
    )


def build_contract_edges(result: VerifierReplayResult, finding_node_id: str) -> list[WorkflowEdge]:
    return [
        WorkflowEdge(
            source=node_id,
            target=finding_node_id,
            label="confirmed by verifier",
            style="dashed",
            animated=True,
        )
        for node_id in result.workflow_node_ids
    ]


def build_finding_upsert(result: VerifierReplayResult) -> FindingUpsert:
    context_references = build_context_for_result(result)
    return FindingUpsert(
        id=result.finding_id or f"finding-{_stable_suffix(result.verifier_run_id, length=14)}",
        title=result.title,
        category=result.category,
        severity=result.severity,
        status=FindingStatus.CONFIRMED,
        confidence=result.confidence,
        endpoint=result.endpoint,
        actor=result.actor,
        impact_summary=result.impact_summary,
        remediation_summary=result.remediation_summary,
        description=result.description,
        impact=result.impact,
        remediation=result.remediation,
        evidence=result.evidence,
        context_references=context_references,
        workflow_node_ids=list(result.workflow_node_ids),
        tags=list(result.tags),
    )


def build_verifier_contract(result: VerifierReplayResult) -> VerifierFindingConfirmedContract:
    finding_node = build_finding_node(result)
    return VerifierFindingConfirmedContract(
        verifier_run_id=result.verifier_run_id,
        request_fingerprint=result.request_fingerprint,
        request_summary=result.request_summary,
        response_status_code=result.response_status_code,
        finding=build_finding_upsert(result),
        finding_node=finding_node,
        edges=build_contract_edges(result, finding_node.id),
    )


def build_ingest_request(result: VerifierReplayResult) -> IngestScanEventRequest:
    contract = build_verifier_contract(result)
    return IngestScanEventRequest(
        contract_version="v1",
        source=EventSource.VERIFIER,
        event_type=contract.kind,
        stage="reporting",
        severity=_event_severity_from_finding(result.severity),
        message=result.message,
        producer_contract=contract,
    )


@dataclass(frozen=True, slots=True)
class VerifierPublishOptions:
    backend_url: str
    ingest_token: str
    timeout_seconds: float = 3.0


def post_verified_finding(options: VerifierPublishOptions, scan_id: str, payload: dict[str, Any]) -> int:
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


def request_verifier_job(options: VerifierPublishOptions, payload: dict[str, Any]) -> dict[str, Any] | None:
    endpoint = f"{options.backend_url.rstrip('/')}/verifier-jobs/claim"
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
            return json.loads(response.read().decode("utf-8"))
    except error.HTTPError:
        return None


def update_verifier_job(options: VerifierPublishOptions, job_id: str, action: str, payload: dict[str, Any]) -> int:
    endpoint = f"{options.backend_url.rstrip('/')}/verifier-jobs/{job_id}/{action}"
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
class VerifierWorker:
    options: VerifierPublishOptions
    sender: Callable[[VerifierPublishOptions, str, dict[str, Any]], int] = post_verified_finding
    claim_sender: Callable[[VerifierPublishOptions, dict[str, Any]], dict[str, Any] | None] = request_verifier_job
    job_sender: Callable[[VerifierPublishOptions, str, str, dict[str, Any]], int] = update_verifier_job

    def publish_verified_finding(self, result: VerifierReplayResult) -> bool:
        payload = build_ingest_request(result).model_dump(mode="json")
        status_code = self.sender(self.options, result.scan_id, payload)
        return 200 <= status_code < 300

    def claim_job(self, *, scan_id: str | None = None, worker_id: str | None = None) -> VerifierJobDetail | None:
        payload = ClaimVerifierJobRequest(scan_id=scan_id, worker_id=worker_id).model_dump(mode="json")
        response_payload = self.claim_sender(self.options, payload)
        if response_payload is None:
            return None

        response = ClaimVerifierJobResponse.model_validate(response_payload)
        return response.job

    def complete_job(self, job_id: str, *, verifier_run_id: str | None = None, finding_id: str | None = None, note: str | None = None) -> bool:
        payload = CompleteVerifierJobRequest(verifier_run_id=verifier_run_id, finding_id=finding_id, note=note).model_dump(mode="json")
        status_code = self.job_sender(self.options, job_id, "complete", payload)
        return 200 <= status_code < 300

    def fail_job(self, job_id: str, *, error_message: str, retryable: bool = True, retry_delay_seconds: int = 0) -> bool:
        payload = FailVerifierJobRequest(
            error_message=error_message,
            retryable=retryable,
            retry_delay_seconds=retry_delay_seconds,
        ).model_dump(mode="json")
        status_code = self.job_sender(self.options, job_id, "fail", payload)
        return 200 <= status_code < 300
