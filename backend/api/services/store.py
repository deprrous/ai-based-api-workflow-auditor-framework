from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import cast
from uuid import uuid4

from sqlalchemy.orm import Session

from api.app.config import get_settings
from api.app.database import session_scope
from api.app.db_models import FindingRecord, ReplayArtifactRecord, ScanEventRecord, ScanRunRecord, VerifierJobRecord, VerifierRunRecord, WorkflowGraphRecord
from api.repositories.event_repository import EventRepository
from api.repositories.finding_repository import FindingRepository
from api.repositories.replay_artifact_repository import ReplayArtifactRepository
from api.repositories.scan_repository import ScanRepository
from api.repositories.verifier_job_repository import VerifierJobRepository
from api.repositories.verifier_run_repository import VerifierRunRepository
from api.repositories.workflow_repository import WorkflowRepository
from api.schemas.events import (
    EventSeverity,
    EventSource,
    IngestScanEventRequest,
    RecordScanEventRequest,
    ScanEvent,
    ScanEventEnvelope,
    ScanStreamSnapshot,
    WorkflowEdgeReference,
    WorkflowGraphUpdate,
)
from api.schemas.findings import ContextReference, FindingDetail, FindingEvidence, FindingSeverity, FindingStatus, FindingSummary, FindingUpsert
from api.schemas.producer_contracts import ProxyHttpObservedContract, VerifierFindingConfirmedContract, WorkflowMapperPathFlaggedContract
from api.schemas.replay_artifacts import ReplayArtifactDetail, ReplayArtifactMaterial
from api.services.replay_artifact_policy import redact_headers, redact_response_excerpt
from api.schemas.scans import ScanRisk, ScanRunSummary, ScanStatus, StartScanRequest
from api.schemas.verifier_jobs import (
    ClaimVerifierJobRequest,
    CompleteVerifierJobRequest,
    FailVerifierJobRequest,
    VerifierJobDetail,
    VerifierJobPayload,
    VerifierJobStatus,
    VerifierJobSummary,
)
from api.schemas.verifier_runs import VerifierRunDetail, VerifierRunStatus, VerifierRunSummary
from api.schemas.workflows import (
    WorkflowEdge,
    WorkflowGraph,
    WorkflowGraphKind,
    WorkflowGraphStats,
    WorkflowNode,
    WorkflowNodeStatus,
    WorkflowNodeType,
)

RISK_ORDER = {
    ScanRisk.SAFE: 0,
    ScanRisk.REVIEW: 1,
    ScanRisk.HIGH: 2,
    ScanRisk.CRITICAL: 3,
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _build_graph_stats(nodes: list[WorkflowNode], edges: list[WorkflowEdge], flagged_paths: int) -> WorkflowGraphStats:
    critical_nodes = sum(1 for node in nodes if node.status == WorkflowNodeStatus.CRITICAL)
    return WorkflowGraphStats(
        node_count=len(nodes),
        edge_count=len(edges),
        critical_nodes=critical_nodes,
        flagged_paths=flagged_paths,
    )


def _risk_from_severity(severity: EventSeverity) -> ScanRisk:
    if severity == EventSeverity.CRITICAL:
        return ScanRisk.CRITICAL
    if severity == EventSeverity.HIGH:
        return ScanRisk.HIGH
    if severity == EventSeverity.WARNING:
        return ScanRisk.REVIEW
    return ScanRisk.SAFE


def _risk_from_finding_severity(severity: FindingSeverity) -> ScanRisk:
    if severity == FindingSeverity.CRITICAL:
        return ScanRisk.CRITICAL
    if severity == FindingSeverity.HIGH:
        return ScanRisk.HIGH
    return ScanRisk.REVIEW


def _merge_risk(current: ScanRisk, candidate: ScanRisk | None) -> ScanRisk:
    if candidate is None:
        return current

    return candidate if RISK_ORDER[candidate] > RISK_ORDER[current] else current


def _edge_key(edge: WorkflowEdge | WorkflowEdgeReference) -> tuple[str, str, str]:
    return (edge.source, edge.target, edge.label or "")


def _serialize_nodes(nodes: list[WorkflowNode]) -> list[dict[str, object]]:
    return [node.model_dump(mode="json") for node in nodes]


def _serialize_edges(edges: list[WorkflowEdge]) -> list[dict[str, object]]:
    return [edge.model_dump(mode="json") for edge in edges]


def _deserialize_nodes(raw_nodes: list[dict[str, object]]) -> list[WorkflowNode]:
    return [WorkflowNode.model_validate(node) for node in raw_nodes]


def _deserialize_edges(raw_edges: list[dict[str, object]]) -> list[WorkflowEdge]:
    return [WorkflowEdge.model_validate(edge) for edge in raw_edges]


def _scan_record_to_model(record: ScanRunRecord) -> ScanRunSummary:
    return ScanRunSummary(
        id=record.id,
        name=record.name,
        status=ScanStatus(record.status),
        target=record.target,
        created_at=record.created_at,
        current_stage=record.current_stage,
        findings_count=record.findings_count,
        flagged_paths=record.flagged_paths,
        risk=ScanRisk(record.risk),
        workflow_id=record.workflow_id,
    )


def _graph_record_to_model(record: WorkflowGraphRecord) -> WorkflowGraph:
    nodes = _deserialize_nodes(record.nodes_json)
    edges = _deserialize_edges(record.edges_json)

    return WorkflowGraph(
        id=record.id,
        kind=WorkflowGraphKind(record.kind),
        scan_id=record.scan_id,
        title=record.title,
        description=record.description,
        updated_at=record.updated_at,
        stats=_build_graph_stats(nodes, edges, flagged_paths=record.flagged_paths),
        nodes=nodes,
        edges=edges,
    )


def _event_record_to_model(record: ScanEventRecord) -> ScanEvent:
    return ScanEvent(
        id=record.id,
        scan_id=record.scan_id,
        source=EventSource(record.source),
        event_type=record.event_type,
        stage=record.stage,
        severity=EventSeverity(record.severity),
        message=record.message,
        payload=record.payload_json,
        created_at=record.created_at,
    )


def _replay_artifact_record_to_material(record: ReplayArtifactRecord) -> ReplayArtifactMaterial:
    return ReplayArtifactMaterial(
        id=record.id,
        scan_id=record.scan_id,
        request_fingerprint=record.request_fingerprint,
        actor=record.actor,
        method=record.method,
        host=record.host,
        path=record.path,
        request_headers=dict(record.request_headers_json),
        request_body_base64=record.request_body_base64,
        request_content_type=record.request_content_type,
        response_status_code=record.response_status_code,
        response_headers=dict(record.response_headers_json),
        response_body_excerpt=record.response_body_excerpt,
        replayable=record.purged_at is None,
        expires_at=record.expires_at,
        purged_at=record.purged_at,
        created_at=record.created_at,
    )


def _finding_record_to_summary(record: FindingRecord) -> FindingSummary:
    evidence = [FindingEvidence.model_validate(item) for item in record.evidence_json]
    context_references = [ContextReference.model_validate(item) for item in record.context_references_json]
    return FindingSummary(
        id=record.id,
        scan_id=record.scan_id,
        title=record.title,
        category=record.category,
        severity=FindingSeverity(record.severity),
        status=FindingStatus(record.status),
        confidence=record.confidence,
        endpoint=record.endpoint,
        actor=record.actor,
        impact_summary=record.impact_summary,
        remediation_summary=record.remediation_summary,
        evidence_count=len(evidence),
        context_reference_count=len(context_references),
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


def _finding_record_to_detail(record: FindingRecord) -> FindingDetail:
    evidence = [FindingEvidence.model_validate(item) for item in record.evidence_json]
    context_references = [ContextReference.model_validate(item) for item in record.context_references_json]
    summary = _finding_record_to_summary(record)
    return FindingDetail(
        **summary.model_dump(),
        description=record.description,
        impact=record.impact,
        remediation=record.remediation,
        evidence=evidence,
        context_references=context_references,
        workflow_node_ids=list(record.workflow_node_ids_json),
        tags=list(record.tags_json),
    )


def _verifier_run_record_to_summary(record: VerifierRunRecord) -> VerifierRunSummary:
    evidence = [FindingEvidence.model_validate(item) for item in record.evidence_json]
    context_references = [ContextReference.model_validate(item) for item in record.context_references_json]
    return VerifierRunSummary(
        id=record.id,
        scan_id=record.scan_id,
        finding_id=record.finding_id,
        status=VerifierRunStatus(record.status),
        category=record.category,
        severity=FindingSeverity(record.severity),
        confidence=record.confidence,
        title=record.title,
        endpoint=record.endpoint,
        actor=record.actor,
        request_fingerprint=record.request_fingerprint,
        response_status_code=record.response_status_code,
        evidence_count=len(evidence),
        context_reference_count=len(context_references),
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


def _verifier_run_record_to_detail(record: VerifierRunRecord) -> VerifierRunDetail:
    evidence = [FindingEvidence.model_validate(item) for item in record.evidence_json]
    context_references = [ContextReference.model_validate(item) for item in record.context_references_json]
    summary = _verifier_run_record_to_summary(record)
    return VerifierRunDetail(
        **summary.model_dump(),
        request_summary=record.request_summary,
        evidence=evidence,
        context_references=context_references,
        workflow_node_ids=list(record.workflow_node_ids_json),
    )


def _verifier_job_record_to_summary(record: VerifierJobRecord) -> VerifierJobSummary:
    return VerifierJobSummary(
        id=record.id,
        scan_id=record.scan_id,
        source_path_id=record.source_path_id,
        title=record.title,
        severity=FindingSeverity(record.severity),
        status=VerifierJobStatus(record.status),
        attempt_count=record.attempt_count,
        max_attempts=record.max_attempts,
        available_at=record.available_at,
        claimed_at=record.claimed_at,
        completed_at=record.completed_at,
        worker_id=record.worker_id,
        verifier_run_id=record.verifier_run_id,
        finding_id=record.finding_id,
        last_error=record.last_error,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


def _verifier_job_record_to_detail(record: VerifierJobRecord) -> VerifierJobDetail:
    summary = _verifier_job_record_to_summary(record)
    payload = VerifierJobPayload.model_validate(record.payload_json)
    return VerifierJobDetail(**summary.model_dump(), rationale=record.rationale, payload=payload)


def _severity_priority(severity: str) -> int:
    order = {
        FindingSeverity.CRITICAL.value: 0,
        FindingSeverity.HIGH.value: 1,
        FindingSeverity.REVIEW.value: 2,
    }
    return order.get(severity, 99)


def _upsert_replay_artifact(
    session: Session,
    scan_id: str,
    *,
    request_fingerprint: str,
    actor: str | None,
    method: str,
    host: str,
    path: str,
    artifact_input,
    now: datetime,
) -> ReplayArtifactRecord:
    repository = ReplayArtifactRepository(session)
    artifact_id = f"artifact-{uuid4().hex[:12]}"
    retention_hours = max(0.0, get_settings().replay_artifact_retention_hours)
    record = ReplayArtifactRecord(
        id=artifact_id,
        scan_id=scan_id,
        request_fingerprint=request_fingerprint,
        actor=actor,
        method=method,
        host=host,
        path=path,
        request_headers_json=dict(artifact_input.request_headers),
        request_body_base64=artifact_input.request_body_base64,
        request_content_type=artifact_input.request_content_type,
        response_status_code=artifact_input.response_status_code,
        response_headers_json=dict(artifact_input.response_headers),
        response_body_excerpt=artifact_input.response_body_excerpt,
        expires_at=now + timedelta(hours=retention_hours),
        purged_at=None,
        created_at=now,
    )
    repository.add(record)
    return record


def _framework_nodes() -> list[WorkflowNode]:
    return [
        WorkflowNode(id="api-spec", label="API Spec", type=WorkflowNodeType.INPUT, phase="inputs", detail="Swagger or OpenAPI definitions.", status=WorkflowNodeStatus.SAFE, x=0, y=20),
        WorkflowNode(id="source-code", label="Source Code", type=WorkflowNodeType.INPUT, phase="inputs", detail="White-box implementation context.", status=WorkflowNodeStatus.SAFE, x=0, y=160),
        WorkflowNode(id="live-traffic", label="Live Traffic", type=WorkflowNodeType.INPUT, phase="inputs", detail="Captured requests and responses from the proxy.", status=WorkflowNodeStatus.ACTIVE, x=0, y=300),
        WorkflowNode(id="knowledge-base", label="Knowledge Base", type=WorkflowNodeType.INPUT, phase="inputs", detail="OWASP API guidance, rules, and heuristics.", status=WorkflowNodeStatus.SAFE, x=0, y=440),
        WorkflowNode(id="auth-profile", label="Auth Profile", type=WorkflowNodeType.INGESTION, phase="ingestion", detail="Sessions, identities, roles, and token patterns.", status=WorkflowNodeStatus.ACTIVE, x=260, y=230),
        WorkflowNode(id="normalization", label="Normalization", type=WorkflowNodeType.INGESTION, phase="ingestion", detail="Redact, normalize, and link incoming artifacts.", status=WorkflowNodeStatus.ACTIVE, x=530, y=230),
        WorkflowNode(id="context-graph", label="Context Graph", type=WorkflowNodeType.RESOURCE, phase="ingestion", detail="Shared run context for the orchestrator and tools.", status=WorkflowNodeStatus.ACTIVE, x=800, y=230),
        WorkflowNode(id="llm-brain", label="LLM Brain", type=WorkflowNodeType.CORE, phase="orchestration", detail="Interprets meaning across fused context.", status=WorkflowNodeStatus.ACTIVE, x=1090, y=140),
        WorkflowNode(id="react-loop", label="ReAct Loop", type=WorkflowNodeType.CORE, phase="orchestration", detail="Reason, act, observe, and refine hypotheses.", status=WorkflowNodeStatus.ACTIVE, x=1090, y=320),
        WorkflowNode(id="guardrails", label="Guardrails", type=WorkflowNodeType.CONTROL, phase="orchestration", detail="Policy limits before tool execution.", status=WorkflowNodeStatus.SAFE, x=1360, y=320),
        WorkflowNode(id="hypothesis", label="Logic Hypothesis", type=WorkflowNodeType.ACTION, phase="reasoning", detail="Propose a business-logic or auth-bypass test.", status=WorkflowNodeStatus.REVIEW, x=1610, y=320),
        WorkflowNode(id="tool-router", label="Tool Router", type=WorkflowNodeType.TOOL, phase="reasoning", detail="Dispatch the best tool set for the hypothesis.", status=WorkflowNodeStatus.ACTIVE, x=1860, y=320),
        WorkflowNode(id="semantic-analyzer", label="Semantic Analyzer", type=WorkflowNodeType.TOOL, phase="tools", detail="Interpret endpoint meaning and parameter intent.", status=WorkflowNodeStatus.REVIEW, x=2130, y=90),
        WorkflowNode(id="workflow-mapper", label="Workflow Mapper", type=WorkflowNodeType.TOOL, phase="tools", detail="Build workflow nodes, edges, and actor relationships.", status=WorkflowNodeStatus.ACTIVE, x=2130, y=280),
        WorkflowNode(id="verifier", label="Automated Verifier", type=WorkflowNodeType.TOOL, phase="tools", detail="Run replay and PoC checks against the target flow.", status=WorkflowNodeStatus.HIGH, x=2130, y=470),
        WorkflowNode(id="evidence-store", label="Evidence Store", type=WorkflowNodeType.OBSERVATION, phase="observation", detail="Capture transcripts, proof, and replay artifacts.", status=WorkflowNodeStatus.ACTIVE, x=2410, y=470),
        WorkflowNode(id="reflection", label="Observation and Reflection", type=WorkflowNodeType.OBSERVATION, phase="observation", detail="Score outcomes and decide whether to continue.", status=WorkflowNodeStatus.ACTIVE, x=2680, y=280),
        WorkflowNode(id="report", label="Finding and Auto-Patch", type=WorkflowNodeType.FINDING, phase="reporting", detail="Plain-English report, impact, and remediation output.", status=WorkflowNodeStatus.CRITICAL, x=2950, y=170),
        WorkflowNode(id="dashboard", label="Dashboard and Logs", type=WorkflowNodeType.OUTPUT, phase="reporting", detail="Workflow graph, risk state, and live scan status.", status=WorkflowNodeStatus.ACTIVE, x=2950, y=370),
        WorkflowNode(id="audit-complete", label="Audit Complete", type=WorkflowNodeType.SUCCESS, phase="completion", detail="All current attack vectors are exhausted or confirmed safe.", status=WorkflowNodeStatus.SAFE, x=2950, y=560),
    ]


def _framework_edges() -> list[WorkflowEdge]:
    return [
        WorkflowEdge(source="api-spec", target="normalization"),
        WorkflowEdge(source="source-code", target="normalization"),
        WorkflowEdge(source="live-traffic", target="auth-profile"),
        WorkflowEdge(source="knowledge-base", target="context-graph"),
        WorkflowEdge(source="auth-profile", target="normalization"),
        WorkflowEdge(source="normalization", target="context-graph", label="fuse artifacts"),
        WorkflowEdge(source="context-graph", target="llm-brain"),
        WorkflowEdge(source="llm-brain", target="react-loop", animated=True),
        WorkflowEdge(source="react-loop", target="llm-brain", animated=True),
        WorkflowEdge(source="react-loop", target="guardrails", label="check policy"),
        WorkflowEdge(source="guardrails", target="hypothesis", label="approved"),
        WorkflowEdge(source="hypothesis", target="tool-router", label="select tools"),
        WorkflowEdge(source="tool-router", target="semantic-analyzer", label="tool 1"),
        WorkflowEdge(source="tool-router", target="workflow-mapper", label="tool 2"),
        WorkflowEdge(source="tool-router", target="verifier", label="tool 3", animated=True),
        WorkflowEdge(source="semantic-analyzer", target="reflection"),
        WorkflowEdge(source="workflow-mapper", target="reflection"),
        WorkflowEdge(source="verifier", target="evidence-store"),
        WorkflowEdge(source="evidence-store", target="reflection", label="attach evidence"),
        WorkflowEdge(source="reflection", target="react-loop", label="try another vector", style="dashed", animated=True),
        WorkflowEdge(source="reflection", target="report", label="issue confirmed", style="dashed"),
        WorkflowEdge(source="report", target="dashboard", label="publish results"),
        WorkflowEdge(source="reflection", target="dashboard", label="stream logs"),
        WorkflowEdge(source="reflection", target="audit-complete", label="run finished", style="dashed"),
    ]


def _build_framework_principle_graph() -> WorkflowGraph:
    nodes = _framework_nodes()
    edges = _framework_edges()
    return WorkflowGraph(
        id="framework-principle",
        kind=WorkflowGraphKind.FRAMEWORK_PRINCIPLE,
        scan_id=None,
        title="Agentic AI Framework Principle",
        description=(
            "How the framework fuses inputs, reasons through the ReAct loop, invokes tools, "
            "observes evidence, and publishes findings to the dashboard."
        ),
        updated_at=_utc_now(),
        stats=_build_graph_stats(nodes, edges, flagged_paths=3),
        nodes=nodes,
        edges=edges,
    )


def _build_billing_scan_graph(scan_id: str) -> WorkflowGraph:
    nodes = [
        WorkflowNode(id="actor-owner", label="Owner Session", type=WorkflowNodeType.ACTOR, phase="auth", detail="Baseline owner account used for happy-path capture.", status=WorkflowNodeStatus.SAFE, x=0, y=170),
        WorkflowNode(id="login", label="POST /auth/login", type=WorkflowNodeType.ENDPOINT, phase="auth", detail="Establishes authenticated session.", status=WorkflowNodeStatus.SAFE, x=250, y=170),
        WorkflowNode(id="profile", label="GET /v1/me", type=WorkflowNodeType.ENDPOINT, phase="auth", detail="Resolves tenant and role context.", status=WorkflowNodeStatus.SAFE, x=500, y=170),
        WorkflowNode(id="invoice-list", label="GET /v1/invoices", type=WorkflowNodeType.ENDPOINT, phase="read", detail="Lists owner-visible invoices.", status=WorkflowNodeStatus.SAFE, x=780, y=80),
        WorkflowNode(id="invoice-detail", label="GET /v1/invoices/{invoiceId}", type=WorkflowNodeType.ENDPOINT, phase="read", detail="Returns a single invoice by direct object id.", status=WorkflowNodeStatus.CRITICAL, x=1080, y=80),
        WorkflowNode(id="invoice-download", label="GET /v1/invoices/{invoiceId}/pdf", type=WorkflowNodeType.ENDPOINT, phase="read", detail="Downloads invoice documents with weak object checks.", status=WorkflowNodeStatus.HIGH, x=1380, y=80),
        WorkflowNode(id="invoice-share", label="POST /v1/invoices/{invoiceId}/send", type=WorkflowNodeType.ENDPOINT, phase="action", detail="Triggers outbound email to invoice recipients.", status=WorkflowNodeStatus.REVIEW, x=1380, y=260),
        WorkflowNode(id="analyst-replay", label="Verifier Replay", type=WorkflowNodeType.TOOL, phase="verification", detail="Replays the owner flow as a second tenant user.", status=WorkflowNodeStatus.ACTIVE, x=1080, y=320),
        WorkflowNode(id="evidence", label="Cross-Tenant Proof", type=WorkflowNodeType.RESOURCE, phase="observation", detail="Response body returns another tenant's invoice metadata.", status=WorkflowNodeStatus.CRITICAL, x=1650, y=170),
        WorkflowNode(id="finding", label="Finding: Broken Object Ownership", type=WorkflowNodeType.FINDING, phase="reporting", detail="Invoice ids can be enumerated across tenants without ownership enforcement.", status=WorkflowNodeStatus.CRITICAL, x=1940, y=80),
        WorkflowNode(id="remediation", label="Patch: Enforce Tenant Ownership", type=WorkflowNodeType.REMEDIATION, phase="reporting", detail="Add tenant-scoped authorization before invoice read and download paths.", status=WorkflowNodeStatus.REVIEW, x=1940, y=280),
    ]
    edges = [
        WorkflowEdge(source="actor-owner", target="login"),
        WorkflowEdge(source="login", target="profile"),
        WorkflowEdge(source="profile", target="invoice-list"),
        WorkflowEdge(source="invoice-list", target="invoice-detail", label="capture invoice ids"),
        WorkflowEdge(source="invoice-detail", target="invoice-download", label="follow-up document fetch", animated=True),
        WorkflowEdge(source="invoice-detail", target="analyst-replay", label="switch tenant", animated=True),
        WorkflowEdge(source="analyst-replay", target="evidence", label="unauthorized read confirmed", style="dashed", animated=True),
        WorkflowEdge(source="invoice-download", target="evidence", label="document exposed", style="dashed"),
        WorkflowEdge(source="invoice-share", target="evidence", label="unsafe side effect", style="dashed"),
        WorkflowEdge(source="evidence", target="finding"),
        WorkflowEdge(source="finding", target="remediation", label="suggest patch"),
    ]
    return WorkflowGraph(
        id=f"workflow-{scan_id}",
        kind=WorkflowGraphKind.SCAN_RUN,
        scan_id=scan_id,
        title="Tenant Billing Workflow Audit",
        description="Persisted workflow graph for a completed tenant-isolation scan run.",
        updated_at=_utc_now(),
        stats=_build_graph_stats(nodes, edges, flagged_paths=2),
        nodes=nodes,
        edges=edges,
    )


def _build_partner_scan_graph(scan_id: str) -> WorkflowGraph:
    nodes = [
        WorkflowNode(id="partner-login", label="POST /partner/session", type=WorkflowNodeType.ENDPOINT, phase="auth", detail="Partner portal session creation.", status=WorkflowNodeStatus.SAFE, x=0, y=160),
        WorkflowNode(id="projects", label="GET /v1/projects", type=WorkflowNodeType.ENDPOINT, phase="read", detail="Returns partner-visible projects.", status=WorkflowNodeStatus.SAFE, x=260, y=160),
        WorkflowNode(id="members", label="POST /v1/projects/{projectId}/members", type=WorkflowNodeType.ENDPOINT, phase="action", detail="Invite flow under active verification.", status=WorkflowNodeStatus.REVIEW, x=560, y=60),
        WorkflowNode(id="keys", label="GET /v1/projects/{projectId}/keys", type=WorkflowNodeType.ENDPOINT, phase="read", detail="Key-management endpoint reached through invitation workflow.", status=WorkflowNodeStatus.HIGH, x=900, y=60),
        WorkflowNode(id="delete-project", label="DELETE /v1/projects/{projectId}", type=WorkflowNodeType.ENDPOINT, phase="action", detail="High-impact path being validated for role escalation.", status=WorkflowNodeStatus.REVIEW, x=900, y=260),
        WorkflowNode(id="mapper", label="Workflow Mapper", type=WorkflowNodeType.TOOL, phase="verification", detail="Building actor-switch path through project membership changes.", status=WorkflowNodeStatus.ACTIVE, x=1210, y=160),
        WorkflowNode(id="verifier", label="Automated Verifier", type=WorkflowNodeType.TOOL, phase="verification", detail="Checking if invited users inherit destructive permissions.", status=WorkflowNodeStatus.ACTIVE, x=1510, y=160),
        WorkflowNode(id="review", label="Analyst Review Pending", type=WorkflowNodeType.OBSERVATION, phase="observation", detail="Evidence is partial; exploitability still being confirmed.", status=WorkflowNodeStatus.REVIEW, x=1810, y=160),
    ]
    edges = [
        WorkflowEdge(source="partner-login", target="projects"),
        WorkflowEdge(source="projects", target="members", label="select shared project"),
        WorkflowEdge(source="members", target="keys", label="new member reads keys", animated=True),
        WorkflowEdge(source="members", target="delete-project", label="new member deletes project", animated=True),
        WorkflowEdge(source="keys", target="mapper"),
        WorkflowEdge(source="delete-project", target="mapper"),
        WorkflowEdge(source="mapper", target="verifier", label="build abuse path"),
        WorkflowEdge(source="verifier", target="review", label="waiting for final confirmation", style="dashed", animated=True),
    ]
    return WorkflowGraph(
        id=f"workflow-{scan_id}",
        kind=WorkflowGraphKind.SCAN_RUN,
        scan_id=scan_id,
        title="Partner Project Boundary Audit",
        description="Persisted workflow graph for a running partner-role verification scan.",
        updated_at=_utc_now(),
        stats=_build_graph_stats(nodes, edges, flagged_paths=2),
        nodes=nodes,
        edges=edges,
    )


def _build_queued_scan_graph(scan_id: str, name: str, target: str | None) -> WorkflowGraph:
    title_target = target or "pending target"
    nodes = [
        WorkflowNode(id="queued-spec", label="API Spec Intake", type=WorkflowNodeType.INPUT, phase="ingestion", detail="Waiting for specification parsing.", status=WorkflowNodeStatus.ACTIVE, x=0, y=160),
        WorkflowNode(id="queued-traffic", label="Traffic Capture", type=WorkflowNodeType.INPUT, phase="ingestion", detail="Waiting for live traffic or recorded traces.", status=WorkflowNodeStatus.IDLE, x=320, y=60),
        WorkflowNode(id="queued-context", label="Context Graph", type=WorkflowNodeType.RESOURCE, phase="planning", detail="Will fuse spec, source, auth, and traffic inputs.", status=WorkflowNodeStatus.IDLE, x=320, y=260),
        WorkflowNode(id="queued-plan", label="Initial Scan Plan", type=WorkflowNodeType.ACTION, phase="planning", detail="Will select first authorization and business-flow probes.", status=WorkflowNodeStatus.IDLE, x=640, y=160),
    ]
    edges = [
        WorkflowEdge(source="queued-spec", target="queued-context"),
        WorkflowEdge(source="queued-traffic", target="queued-context"),
        WorkflowEdge(source="queued-context", target="queued-plan", label="plan next steps"),
    ]
    return WorkflowGraph(
        id=f"workflow-{scan_id}",
        kind=WorkflowGraphKind.SCAN_RUN,
        scan_id=scan_id,
        title=f"{name} Workflow",
        description=f"Queued scan workflow for {title_target}. The graph will expand as ingestion and verification run.",
        updated_at=_utc_now(),
        stats=_build_graph_stats(nodes, edges, flagged_paths=0),
        nodes=nodes,
        edges=edges,
    )


def _build_bootstrap_seed_findings(scan_id: str) -> list[FindingUpsert]:
    return [
        FindingUpsert(
            id=f"finding-{scan_id}-bola-read",
            title="Cross-tenant invoice read via direct object reference",
            category="bola",
            severity=FindingSeverity.CRITICAL,
            status=FindingStatus.CONFIRMED,
            confidence=97,
            endpoint="GET /v1/invoices/{invoiceId}",
            actor="second-tenant user",
            impact_summary="A user can read invoice metadata from another tenant by changing the invoice identifier.",
            remediation_summary="Enforce tenant ownership checks before loading invoice resources.",
            description="The verifier replayed a captured owner flow as a second tenant and confirmed that direct invoice object ids returned another tenant's invoice metadata.",
            impact="Attackers with a normal account can enumerate invoice ids and access cross-tenant billing data without elevated privileges.",
            remediation="Scope invoice lookups by tenant and owner before fetching the resource, and fail closed when ownership does not match the current principal.",
            context_references=[
                ContextReference(
                    id=f"ctx-{scan_id}-invoice-controller",
                    kind="source_code",
                    label="Invoice detail loader",
                    location="services/invoice_access.py:44",
                    excerpt="invoice = invoice_repo.get_by_id(invoice_id)",
                    rationale="The invoice is loaded before a tenant or owner constraint is enforced.",
                ),
                ContextReference(
                    id=f"ctx-{scan_id}-invoice-spec",
                    kind="api_spec",
                    label="Invoice detail operation",
                    location="openapi.yaml#/paths/~1v1~1invoices~1{invoiceId}/get",
                    excerpt="parameters:\n  - name: invoiceId\n    in: path",
                    rationale="The API spec exposes a direct object identifier path that aligns with the confirmed exploit path.",
                ),
            ],
            workflow_node_ids=["invoice-detail", "evidence", "finding"],
            tags=["idor", "tenant-isolation", "billing"],
            evidence=[
                FindingEvidence(
                    label="Verifier replay response",
                    detail="Replay as tenant B returned tenant A invoice metadata with HTTP 200.",
                    source="verifier",
                ),
                FindingEvidence(
                    label="Workflow correlation",
                    detail="The invoice identifier was learned from the owner invoice list and replayed in a second tenant session.",
                    source="workflow_mapper",
                ),
            ],
        ),
        FindingUpsert(
            id=f"finding-{scan_id}-document-download",
            title="Cross-tenant invoice PDF download",
            category="excessive_data_exposure",
            severity=FindingSeverity.HIGH,
            status=FindingStatus.CONFIRMED,
            confidence=91,
            endpoint="GET /v1/invoices/{invoiceId}/pdf",
            actor="second-tenant user",
            impact_summary="Invoice documents remain downloadable once a foreign invoice id is known.",
            remediation_summary="Apply the same ownership guard to document download paths as the primary invoice read path.",
            description="The download endpoint reused the same unscoped identifier and returned billing documents for a foreign tenant.",
            impact="Sensitive invoice PDFs can be exfiltrated after discovering a valid cross-tenant object id.",
            remediation="Reuse centralized ownership enforcement for child document routes and avoid loading files before the ownership check passes.",
            context_references=[
                ContextReference(
                    id=f"ctx-{scan_id}-invoice-pdf-route",
                    kind="source_code",
                    label="Invoice PDF download handler",
                    location="controllers/invoice_documents.py:28",
                    excerpt="return document_service.stream_invoice_pdf(invoice_id)",
                    rationale="The document route appears to trust the same invoice id path as the vulnerable detail route.",
                )
            ],
            workflow_node_ids=["invoice-download", "evidence"],
            tags=["document-exposure", "tenant-isolation"],
            evidence=[
                FindingEvidence(
                    label="Document fetch response",
                    detail="The PDF download endpoint returned a valid document stream for a foreign tenant invoice.",
                    source="verifier",
                )
            ],
        ),
        FindingUpsert(
            id=f"finding-{scan_id}-unsafe-send",
            title="Invoice send action uses untrusted object ownership",
            category="business_logic",
            severity=FindingSeverity.REVIEW,
            status=FindingStatus.CANDIDATE,
            confidence=72,
            endpoint="POST /v1/invoices/{invoiceId}/send",
            actor="second-tenant user",
            impact_summary="The send action appears to trust the same cross-tenant invoice id path and may trigger outbound side effects.",
            remediation_summary="Re-validate ownership and recipient scope before executing side-effecting billing actions.",
            description="The send endpoint sits on the same workflow branch as the exploitable invoice read path, but side-effect validation still needs confirmation.",
            impact="If confirmed, attackers could trigger billing emails or workflow side effects for another tenant.",
            remediation="Gate side-effect actions with explicit authorization checks and idempotency controls, and log denied attempts.",
            workflow_node_ids=["invoice-share"],
            tags=["business-logic", "side-effects"],
            evidence=[
                FindingEvidence(
                    label="Shared object path",
                    detail="The send endpoint accepts the same invoice identifier pattern used by the confirmed cross-tenant read finding.",
                    source="orchestrator",
                )
            ],
        ),
    ]


def _build_partner_seed_findings(scan_id: str) -> list[FindingUpsert]:
    return [
        FindingUpsert(
            id=f"finding-{scan_id}-member-keys",
            title="Invited partner member may inherit key-read access",
            category="tenant_isolation",
            severity=FindingSeverity.HIGH,
            status=FindingStatus.CANDIDATE,
            confidence=76,
            endpoint="GET /v1/projects/{projectId}/keys",
            actor="invited partner member",
            impact_summary="A newly invited member may inherit key-management read access through a workflow boundary issue.",
            remediation_summary="Break privilege inheritance between invitation acceptance and key-management capabilities.",
            description="The workflow mapper discovered a path from project invitation to key-management reads that still needs final verifier confirmation.",
            impact="If confirmed, third-party collaborators could view or rotate secrets outside their intended project role.",
            remediation="Separate invitation roles from secret-management roles and require explicit permission grants for key endpoints.",
            context_references=[
                ContextReference(
                    id=f"ctx-{scan_id}-partner-keys-spec",
                    kind="api_spec",
                    label="Project keys operation",
                    location="partner-openapi.yaml#/paths/~1v1~1projects~1{projectId}~1keys/get",
                    excerpt="summary: Read project keys",
                    rationale="The documented key-management path lines up with the suspicious invitation-to-key-read workflow branch.",
                )
            ],
            workflow_node_ids=["keys", "review"],
            tags=["role-boundary", "secrets", "partner-access"],
            evidence=[
                FindingEvidence(
                    label="Workflow path candidate",
                    detail="Project membership changes lead directly into the key-management branch in the captured flow.",
                    source="workflow_mapper",
                )
            ],
        )
    ]


def _build_bootstrap_seed_verifier_run(scan_id: str) -> VerifierRunRecord:
    now = datetime(2026, 3, 19, 0, 24, tzinfo=timezone.utc)
    return VerifierRunRecord(
        id="verify-bootstrap-invoice-read",
        scan_id=scan_id,
        finding_id=f"finding-{scan_id}-bola-read",
        status=VerifierRunStatus.CONFIRMED.value,
        category="bola",
        severity=FindingSeverity.CRITICAL.value,
        confidence=97,
        title="Cross-tenant invoice read via direct object reference",
        endpoint="GET /v1/invoices/{invoiceId}",
        actor="second-tenant user",
        request_fingerprint="invoice-detail-cross-tenant",
        request_summary="Replay as tenant B returned HTTP 200 for tenant A invoice detail.",
        response_status_code=200,
        evidence_json=[
            {
                "label": "Verifier replay response",
                "detail": "Replay as tenant B returned tenant A invoice metadata with HTTP 200.",
                "source": "verifier",
            }
        ],
        context_references_json=[
            {
                "id": f"ctx-{scan_id}-invoice-controller",
                "kind": "source_code",
                "label": "Invoice detail loader",
                "location": "services/invoice_access.py:44",
                "excerpt": "invoice = invoice_repo.get_by_id(invoice_id)",
                "rationale": "The invoice is loaded before a tenant or owner constraint is enforced.",
            },
            {
                "id": f"ctx-{scan_id}-invoice-spec",
                "kind": "api_spec",
                "label": "Invoice detail operation",
                "location": "openapi.yaml#/paths/~1v1~1invoices~1{invoiceId}/get",
                "excerpt": "parameters:\n  - name: invoiceId\n    in: path",
                "rationale": "The API spec exposes a direct object identifier path that aligns with the confirmed exploit path.",
            },
        ],
        workflow_node_ids_json=["invoice-detail", "evidence", "finding"],
        created_at=now,
        updated_at=now,
    )


def _build_partner_seed_verifier_job(scan_id: str) -> VerifierJobRecord:
    now = datetime(2026, 3, 19, 1, 39, tzinfo=timezone.utc)
    payload = VerifierJobPayload(
        path_id="path-partner-member-keys",
        title="Partner member reaches key-management path",
        rationale="The workflow mapper found a high-risk path from project membership changes to key-management reads that should be verified.",
        workflow_node_ids=["projects", "members", "keys", "review"],
        workflow_nodes=[
            WorkflowNode(id="projects", label="GET /v1/projects", type=WorkflowNodeType.ENDPOINT, phase="read", detail="Partner member lists shared projects.", status=WorkflowNodeStatus.REVIEW, x=660.0, y=180.0),
            WorkflowNode(id="members", label="POST /v1/projects/{projectId}/members", type=WorkflowNodeType.ENDPOINT, phase="action", detail="Membership changes are applied to a shared project.", status=WorkflowNodeStatus.REVIEW, x=900.0, y=180.0),
            WorkflowNode(id="keys", label="GET /v1/projects/{projectId}/keys", type=WorkflowNodeType.ENDPOINT, phase="read", detail="Suspicious key-management path reached from the shared member workflow.", status=WorkflowNodeStatus.HIGH, x=1140.0, y=180.0),
            WorkflowNode(id="path-flag-partner-seed", label="Flagged Path: Partner member reaches key-management path", type=WorkflowNodeType.OBSERVATION, phase="verification", detail="Seeded high-risk path awaiting verification.", status=WorkflowNodeStatus.HIGH, x=1380.0, y=180.0),
        ],
        workflow_edges=[
            WorkflowEdge(source="projects", target="members", label="observed sequence", style="solid", animated=True),
            WorkflowEdge(source="members", target="keys", label="observed sequence", style="solid", animated=True),
            WorkflowEdge(source="keys", target="path-flag-partner-seed", label="flagged path", style="dashed", animated=True),
        ],
        replay_plan={
            "actor": "partner-member",
            "requests": [
                {
                    "request_fingerprint": "seed-projects-read",
                    "method": "GET",
                    "host": "qa.example.internal",
                    "path": "/v1/projects",
                    "actor": "partner-member",
                },
                {
                    "request_fingerprint": "seed-members-update",
                    "method": "POST",
                    "host": "qa.example.internal",
                    "path": "/v1/projects/123/members",
                    "actor": "partner-member",
                },
                {
                    "request_fingerprint": "seed-keys-read",
                    "method": "GET",
                    "host": "qa.example.internal",
                    "path": "/v1/projects/123/keys",
                    "actor": "partner-member",
                },
            ],
            "success_status_codes": [200],
        },
    )
    return VerifierJobRecord(
        id="job-partner-member-keys",
        scan_id=scan_id,
        source_path_id=payload.path_id,
        title=payload.title,
        severity=FindingSeverity.HIGH.value,
        status=VerifierJobStatus.QUEUED.value,
        rationale=payload.rationale,
        payload_json=payload.model_dump(mode="json"),
        attempt_count=0,
        max_attempts=3,
        available_at=now,
        claimed_at=None,
        completed_at=None,
        worker_id=None,
        verifier_run_id=None,
        finding_id=None,
        last_error=None,
        created_at=now,
        updated_at=now,
    )


def _persist_graph(record: WorkflowGraphRecord, graph: WorkflowGraph) -> None:
    record.kind = graph.kind.value
    record.scan_id = graph.scan_id
    record.title = graph.title
    record.description = graph.description
    record.flagged_paths = graph.stats.flagged_paths
    record.nodes_json = _serialize_nodes(graph.nodes)
    record.edges_json = _serialize_edges(graph.edges)
    record.updated_at = graph.updated_at


def _apply_graph_update(graph: WorkflowGraph, update: WorkflowGraphUpdate | None, flagged_paths: int) -> WorkflowGraph:
    if update is None:
        graph.updated_at = _utc_now()
        graph.stats = _build_graph_stats(graph.nodes, graph.edges, flagged_paths)
        return graph

    nodes_by_id = {node.id: node for node in graph.nodes}

    for node_id in update.remove_node_ids:
        nodes_by_id.pop(node_id, None)

    for node in update.upsert_nodes:
        nodes_by_id[node.id] = node

    remove_edge_keys = {_edge_key(edge) for edge in update.remove_edges}
    edge_map: dict[tuple[str, str, str], WorkflowEdge] = {}

    for edge in graph.edges:
        key = _edge_key(edge)
        if key in remove_edge_keys:
            continue
        if edge.source in nodes_by_id and edge.target in nodes_by_id:
            edge_map[key] = edge

    for edge in update.upsert_edges:
        if edge.source in nodes_by_id and edge.target in nodes_by_id:
            edge_map[_edge_key(edge)] = edge

    graph.nodes = list(nodes_by_id.values())
    graph.edges = list(edge_map.values())

    if update.title is not None:
        graph.title = update.title
    if update.description is not None:
        graph.description = update.description

    graph.updated_at = _utc_now()
    graph.stats = _build_graph_stats(graph.nodes, graph.edges, flagged_paths)
    return graph


def _create_event_record(scan_id: str, source: EventSource, event_type: str, stage: str, severity: EventSeverity, message: str, payload: dict[str, object] | None = None, created_at: datetime | None = None) -> ScanEventRecord:
    return ScanEventRecord(
        scan_id=scan_id,
        source=source.value,
        event_type=event_type,
        stage=stage,
        severity=severity.value,
        message=message,
        payload_json=payload,
        created_at=created_at or _utc_now(),
    )


def _apply_finding_updates(session: Session, scan_id: str, finding_updates: list[FindingUpsert], *, now: datetime) -> list[FindingRecord]:
    persisted_findings: list[FindingRecord] = []
    finding_repository = FindingRepository(session)

    for finding_update in finding_updates:
        finding_id = finding_update.id or f"finding-{uuid4().hex[:10]}"
        record = finding_repository.get(finding_id)

        if record is None:
            record = FindingRecord(
                id=finding_id,
                scan_id=scan_id,
                created_at=now,
                updated_at=now,
                title=finding_update.title,
                category=finding_update.category,
                severity=finding_update.severity.value,
                status=finding_update.status.value,
                confidence=finding_update.confidence,
                endpoint=finding_update.endpoint,
                actor=finding_update.actor,
                impact_summary=finding_update.impact_summary,
                remediation_summary=finding_update.remediation_summary,
                description=finding_update.description,
                impact=finding_update.impact,
                remediation=finding_update.remediation,
                evidence_json=[item.model_dump(mode="json") for item in finding_update.evidence],
                context_references_json=[item.model_dump(mode="json") for item in finding_update.context_references],
                workflow_node_ids_json=list(finding_update.workflow_node_ids),
                tags_json=list(finding_update.tags),
            )
            finding_repository.add(record)
        else:
            record.scan_id = scan_id
            record.title = finding_update.title
            record.category = finding_update.category
            record.severity = finding_update.severity.value
            record.status = finding_update.status.value
            record.confidence = finding_update.confidence
            record.endpoint = finding_update.endpoint
            record.actor = finding_update.actor
            record.impact_summary = finding_update.impact_summary
            record.remediation_summary = finding_update.remediation_summary
            record.description = finding_update.description
            record.impact = finding_update.impact
            record.remediation = finding_update.remediation
            record.evidence_json = [item.model_dump(mode="json") for item in finding_update.evidence]
            record.context_references_json = [item.model_dump(mode="json") for item in finding_update.context_references]
            record.workflow_node_ids_json = list(finding_update.workflow_node_ids)
            record.tags_json = list(finding_update.tags)
            record.updated_at = now

        persisted_findings.append(record)

    return persisted_findings


def _list_findings_for_scan(session: Session, scan_id: str) -> list[FindingRecord]:
    return FindingRepository(session).list_for_scan(scan_id)


def _upsert_verifier_run(
    session: Session,
    scan_id: str,
    contract: VerifierFindingConfirmedContract,
    *,
    now: datetime,
) -> VerifierRunRecord:
    repository = VerifierRunRepository(session)
    record = repository.get(contract.verifier_run_id)
    finding_id = contract.finding.id
    if record is None:
        record = VerifierRunRecord(
            id=contract.verifier_run_id,
            scan_id=scan_id,
            finding_id=finding_id,
            status=VerifierRunStatus.CONFIRMED.value,
            category=contract.finding.category,
            severity=contract.finding.severity.value,
            confidence=contract.finding.confidence,
            title=contract.finding.title,
            endpoint=contract.finding.endpoint,
            actor=contract.finding.actor,
            request_fingerprint=contract.request_fingerprint,
            request_summary=contract.request_summary,
            response_status_code=contract.response_status_code,
            evidence_json=[item.model_dump(mode="json") for item in contract.finding.evidence],
            context_references_json=[item.model_dump(mode="json") for item in contract.finding.context_references],
            workflow_node_ids_json=list(contract.finding.workflow_node_ids),
            created_at=now,
            updated_at=now,
        )
        repository.add(record)
        return record

    record.scan_id = scan_id
    record.finding_id = finding_id
    record.status = VerifierRunStatus.CONFIRMED.value
    record.category = contract.finding.category
    record.severity = contract.finding.severity.value
    record.confidence = contract.finding.confidence
    record.title = contract.finding.title
    record.endpoint = contract.finding.endpoint
    record.actor = contract.finding.actor
    record.request_fingerprint = contract.request_fingerprint
    record.request_summary = contract.request_summary
    record.response_status_code = contract.response_status_code
    record.evidence_json = [item.model_dump(mode="json") for item in contract.finding.evidence]
    record.context_references_json = [item.model_dump(mode="json") for item in contract.finding.context_references]
    record.workflow_node_ids_json = list(contract.finding.workflow_node_ids)
    record.updated_at = now
    return record


def _build_verifier_job_payload(contract: WorkflowMapperPathFlaggedContract) -> VerifierJobPayload:
    endpoint_node_ids = [
        node.id
        for node in contract.nodes
        if node.type in {WorkflowNodeType.ENDPOINT, WorkflowNodeType.ACTION, WorkflowNodeType.OBSERVATION}
    ]
    return VerifierJobPayload(
        path_id=contract.path_id,
        title=contract.title,
        rationale=contract.rationale,
        workflow_node_ids=endpoint_node_ids,
        workflow_nodes=list(contract.nodes),
        workflow_edges=list(contract.edges),
        replay_plan=contract.replay_plan,
    )


def _queue_verifier_job_from_path_contract(
    session: Session,
    scan_id: str,
    contract: WorkflowMapperPathFlaggedContract,
    *,
    now: datetime,
) -> VerifierJobRecord | None:
    if contract.severity not in {FindingSeverity.HIGH, FindingSeverity.CRITICAL}:
        return None

    repository = VerifierJobRepository(session)
    existing = repository.get_active_by_path(scan_id, contract.path_id)
    payload = _build_verifier_job_payload(contract)

    if existing is not None:
        existing.title = contract.title
        existing.severity = contract.severity.value
        existing.rationale = contract.rationale
        existing.payload_json = payload.model_dump(mode="json")
        existing.updated_at = now
        existing.available_at = min(existing.available_at, now)
        return existing

    job = VerifierJobRecord(
        id=f"job-{uuid4().hex[:10]}",
        scan_id=scan_id,
        source_path_id=contract.path_id,
        title=contract.title,
        severity=contract.severity.value,
        status=VerifierJobStatus.QUEUED.value,
        rationale=contract.rationale,
        payload_json=payload.model_dump(mode="json"),
        attempt_count=0,
        max_attempts=3,
        available_at=now,
        claimed_at=None,
        completed_at=None,
        worker_id=None,
        verifier_run_id=None,
        finding_id=None,
        last_error=None,
        created_at=now,
        updated_at=now,
    )
    repository.add(job)
    return job


class AuditStore:
    def ensure_seed_data(self) -> None:
        with session_scope() as session:
            scan_repository = ScanRepository(session)
            workflow_repository = WorkflowRepository(session)
            finding_repository = FindingRepository(session)
            event_repository = EventRepository(session)

            framework_exists = workflow_repository.get_framework_principle()
            if framework_exists is None:
                framework_graph = _build_framework_principle_graph()
                framework_record = WorkflowGraphRecord(
                    id=framework_graph.id,
                    kind=framework_graph.kind.value,
                    scan_id=None,
                    title=framework_graph.title,
                    description=framework_graph.description,
                    flagged_paths=framework_graph.stats.flagged_paths,
                    nodes_json=_serialize_nodes(framework_graph.nodes),
                    edges_json=_serialize_edges(framework_graph.edges),
                    updated_at=framework_graph.updated_at,
                )
                workflow_repository.add(framework_record)

            if scan_repository.exists_any():
                if not finding_repository.exists_any():
                    if scan_repository.get("bootstrap-scan") is not None:
                        _apply_finding_updates(session, "bootstrap-scan", _build_bootstrap_seed_findings("bootstrap-scan"), now=_utc_now())
                    if scan_repository.get("partner-boundary-scan") is not None:
                        _apply_finding_updates(
                            session,
                            "partner-boundary-scan",
                            _build_partner_seed_findings("partner-boundary-scan"),
                            now=_utc_now(),
                        )
                verifier_run_repository = VerifierRunRepository(session)
                if verifier_run_repository.get("verify-bootstrap-invoice-read") is None and scan_repository.get("bootstrap-scan") is not None:
                    verifier_run_repository.add(_build_bootstrap_seed_verifier_run("bootstrap-scan"))
                verifier_job_repository = VerifierJobRepository(session)
                if verifier_job_repository.get("job-partner-member-keys") is None and scan_repository.get("partner-boundary-scan") is not None:
                    verifier_job_repository.add(_build_partner_seed_verifier_job("partner-boundary-scan"))
                return

            bootstrap_scan = ScanRunRecord(
                id="bootstrap-scan",
                name="Tenant Billing Workflow Audit",
                status=ScanStatus.COMPLETED.value,
                target="staging",
                created_at=datetime(2026, 3, 19, 0, 0, tzinfo=timezone.utc),
                updated_at=datetime(2026, 3, 19, 0, 25, tzinfo=timezone.utc),
                current_stage="reporting",
                findings_count=3,
                flagged_paths=2,
                risk=ScanRisk.CRITICAL.value,
                workflow_id="workflow-bootstrap-scan",
                notes="Seeded sample showing target-derived tenant isolation abuse.",
            )
            bootstrap_graph = _build_billing_scan_graph(bootstrap_scan.id)
            bootstrap_record = WorkflowGraphRecord(
                id=bootstrap_graph.id,
                kind=bootstrap_graph.kind.value,
                scan_id=bootstrap_scan.id,
                title=bootstrap_graph.title,
                description=bootstrap_graph.description,
                flagged_paths=bootstrap_graph.stats.flagged_paths,
                nodes_json=_serialize_nodes(bootstrap_graph.nodes),
                edges_json=_serialize_edges(bootstrap_graph.edges),
                updated_at=bootstrap_graph.updated_at,
            )

            partner_scan = ScanRunRecord(
                id="partner-boundary-scan",
                name="Partner Project Boundary Audit",
                status=ScanStatus.RUNNING.value,
                target="qa",
                created_at=datetime(2026, 3, 19, 1, 30, tzinfo=timezone.utc),
                updated_at=datetime(2026, 3, 19, 1, 46, tzinfo=timezone.utc),
                current_stage="observation",
                findings_count=1,
                flagged_paths=2,
                risk=ScanRisk.HIGH.value,
                workflow_id="workflow-partner-boundary-scan",
                notes="Seeded sample showing a role boundary review in progress.",
            )
            partner_graph = _build_partner_scan_graph(partner_scan.id)
            partner_record = WorkflowGraphRecord(
                id=partner_graph.id,
                kind=partner_graph.kind.value,
                scan_id=partner_scan.id,
                title=partner_graph.title,
                description=partner_graph.description,
                flagged_paths=partner_graph.stats.flagged_paths,
                nodes_json=_serialize_nodes(partner_graph.nodes),
                edges_json=_serialize_edges(partner_graph.edges),
                updated_at=partner_graph.updated_at,
            )

            scan_repository.add(bootstrap_scan)
            workflow_repository.add(bootstrap_record)
            scan_repository.add(partner_scan)
            workflow_repository.add(partner_record)
            _apply_finding_updates(session, bootstrap_scan.id, _build_bootstrap_seed_findings(bootstrap_scan.id), now=_utc_now())
            _apply_finding_updates(session, partner_scan.id, _build_partner_seed_findings(partner_scan.id), now=_utc_now())
            VerifierRunRepository(session).add(_build_bootstrap_seed_verifier_run(bootstrap_scan.id))
            VerifierJobRepository(session).add(_build_partner_seed_verifier_job(partner_scan.id))
            for event_record in [
                _create_event_record(
                    bootstrap_scan.id,
                    EventSource.PROXY,
                    "traffic_capture_completed",
                    "ingestion",
                    EventSeverity.INFO,
                    "Captured owner billing workflow from staging traffic.",
                    {"endpoint_count": 4, "actor": "owner"},
                    created_at=datetime(2026, 3, 19, 0, 3, tzinfo=timezone.utc),
                ),
                _create_event_record(
                    bootstrap_scan.id,
                    EventSource.ORCHESTRATOR,
                    "workflow_hypothesis_generated",
                    "reasoning",
                    EventSeverity.WARNING,
                    "Direct invoice object lookups may bypass tenant ownership checks.",
                    {"focus_node": "invoice-detail"},
                    created_at=datetime(2026, 3, 19, 0, 11, tzinfo=timezone.utc),
                ),
                _create_event_record(
                    bootstrap_scan.id,
                    EventSource.VERIFIER,
                    "finding_confirmed",
                    "reporting",
                    EventSeverity.CRITICAL,
                    "Verifier replay confirmed cross-tenant invoice access through direct object references.",
                    {"focus_node": "finding", "finding_type": "bola"},
                    created_at=datetime(2026, 3, 19, 0, 24, tzinfo=timezone.utc),
                ),
                _create_event_record(
                    partner_scan.id,
                    EventSource.PROXY,
                    "partner_flow_ingested",
                    "ingestion",
                    EventSeverity.INFO,
                    "Partner portal invitation and key-management flow captured for review.",
                    {"focus_node": "projects"},
                    created_at=datetime(2026, 3, 19, 1, 32, tzinfo=timezone.utc),
                ),
                _create_event_record(
                    partner_scan.id,
                    EventSource.WORKFLOW_MAPPER,
                    "boundary_path_discovered",
                    "verification",
                    EventSeverity.WARNING,
                    "Workflow mapper found a candidate privilege-escalation path from project member invite to key read.",
                    {"focus_node": "keys"},
                    created_at=datetime(2026, 3, 19, 1, 38, tzinfo=timezone.utc),
                ),
            ]:
                event_repository.add(event_record)

    def list_scans(self) -> list[ScanRunSummary]:
        with session_scope() as session:
            records = ScanRepository(session).list()
            return [_scan_record_to_model(record) for record in records]

    def get_scan(self, scan_id: str) -> ScanRunSummary | None:
        with session_scope() as session:
            record = ScanRepository(session).get(scan_id)
            return _scan_record_to_model(record) if record else None

    def start_scan(self, payload: StartScanRequest) -> ScanRunSummary:
        scan_id = f"scan-{uuid4().hex[:8]}"
        workflow_id = f"workflow-{scan_id}"
        now = _utc_now()
        graph = _build_queued_scan_graph(scan_id, payload.name, payload.target)
        graph.updated_at = now

        with session_scope() as session:
            scan_repository = ScanRepository(session)
            workflow_repository = WorkflowRepository(session)
            event_repository = EventRepository(session)

            scan_record = ScanRunRecord(
                id=scan_id,
                name=payload.name,
                status=ScanStatus.QUEUED.value,
                target=payload.target,
                created_at=now,
                updated_at=now,
                current_stage="ingestion",
                findings_count=0,
                flagged_paths=0,
                risk=ScanRisk.REVIEW.value,
                workflow_id=workflow_id,
                notes=payload.notes,
            )
            graph_record = WorkflowGraphRecord(
                id=workflow_id,
                kind=graph.kind.value,
                scan_id=scan_id,
                title=graph.title,
                description=graph.description,
                flagged_paths=graph.stats.flagged_paths,
                nodes_json=_serialize_nodes(graph.nodes),
                edges_json=_serialize_edges(graph.edges),
                updated_at=graph.updated_at,
            )
            scan_repository.add(scan_record)
            workflow_repository.add(graph_record)
            event_repository.add(
                _create_event_record(
                    scan_id,
                    EventSource.SYSTEM,
                    "scan_created",
                    "ingestion",
                    EventSeverity.INFO,
                    "Scan created and queued for initial ingestion.",
                    {"target": payload.target, "workflow_id": workflow_id},
                )
            )
            session.flush()
            session.refresh(scan_record)
            return _scan_record_to_model(scan_record)

    def get_scan_workflow(self, scan_id: str) -> WorkflowGraph | None:
        with session_scope() as session:
            record = WorkflowRepository(session).get_by_scan_id(scan_id)
            return _graph_record_to_model(record) if record else None

    def get_framework_principle(self) -> WorkflowGraph | None:
        with session_scope() as session:
            record = WorkflowRepository(session).get_framework_principle()
            return _graph_record_to_model(record) if record else None

    def list_findings(
        self,
        *,
        scan_id: str | None = None,
        severity: FindingSeverity | None = None,
        status: FindingStatus | None = None,
    ) -> list[FindingSummary]:
        with session_scope() as session:
            records = FindingRepository(session).list(
                scan_id=scan_id,
                severity=severity.value if severity is not None else None,
                status=status.value if status is not None else None,
            )
            return [_finding_record_to_summary(record) for record in records]

    def get_finding(self, finding_id: str) -> FindingDetail | None:
        with session_scope() as session:
            record = FindingRepository(session).get(finding_id)
            return _finding_record_to_detail(record) if record else None

    def list_verifier_runs(self, scan_id: str) -> list[VerifierRunSummary]:
        with session_scope() as session:
            records = VerifierRunRepository(session).list_for_scan(scan_id)
            return [_verifier_run_record_to_summary(record) for record in records]

    def get_verifier_run(self, verifier_run_id: str) -> VerifierRunDetail | None:
        with session_scope() as session:
            record = VerifierRunRepository(session).get(verifier_run_id)
            return _verifier_run_record_to_detail(record) if record else None

    def list_verifier_jobs(self, scan_id: str) -> list[VerifierJobSummary]:
        with session_scope() as session:
            records = VerifierJobRepository(session).list_for_scan(scan_id)
            return [_verifier_job_record_to_summary(record) for record in records]

    def get_verifier_job(self, verifier_job_id: str) -> VerifierJobDetail | None:
        with session_scope() as session:
            record = VerifierJobRepository(session).get(verifier_job_id)
            return _verifier_job_record_to_detail(record) if record else None

    def get_replay_artifact_material(self, artifact_id: str) -> ReplayArtifactMaterial | None:
        with session_scope() as session:
            record = ReplayArtifactRepository(session).get(artifact_id)
            return _replay_artifact_record_to_material(record) if record else None

    def list_replay_artifact_materials(self, scan_id: str) -> list[ReplayArtifactMaterial]:
        with session_scope() as session:
            records = ReplayArtifactRepository(session).list_for_scan(scan_id)
            return [_replay_artifact_record_to_material(record) for record in records]

    def purge_expired_replay_artifacts(self, *, now: datetime | None = None) -> int:
        with session_scope() as session:
            effective_now = now or _utc_now()
            settings = get_settings()
            records = ReplayArtifactRepository(session).list_expired(now=effective_now)
            for record in records:
                record.request_headers_json = redact_headers(
                    dict(record.request_headers_json),
                    settings.replay_artifact_redact_headers,
                )
                record.response_headers_json = redact_headers(
                    dict(record.response_headers_json),
                    settings.replay_artifact_redact_headers,
                )
                record.request_body_base64 = None
                record.response_body_excerpt = redact_response_excerpt(
                    record.response_body_excerpt,
                    sensitive_body_keys=settings.replay_artifact_redact_body_keys,
                    limit=4000,
                )
                record.purged_at = effective_now
            return len(records)

    def claim_verifier_job(self, payload: ClaimVerifierJobRequest) -> VerifierJobDetail | None:
        with session_scope() as session:
            repository = VerifierJobRepository(session)
            now = _utc_now()
            claimable = repository.list_claimable(now=now, scan_id=payload.scan_id)
            if not claimable:
                return None

            record = sorted(
                claimable,
                key=lambda item: (_severity_priority(item.severity), item.available_at, item.created_at, item.id),
            )[0]
            record.status = VerifierJobStatus.RUNNING.value
            record.attempt_count += 1
            record.claimed_at = now
            record.worker_id = payload.worker_id or "verifier-worker"
            record.updated_at = now

            EventRepository(session).add(
                _create_event_record(
                    record.scan_id,
                    EventSource.SYSTEM,
                    "verifier_job.claimed",
                    "verification",
                    EventSeverity.INFO,
                    f"Verifier job {record.id} claimed by {record.worker_id}.",
                    {"job_id": record.id, "path_id": record.source_path_id, "worker_id": record.worker_id},
                    created_at=now,
                )
            )

            return _verifier_job_record_to_detail(record)

    def complete_verifier_job(self, verifier_job_id: str, payload: CompleteVerifierJobRequest) -> VerifierJobDetail | None:
        with session_scope() as session:
            repository = VerifierJobRepository(session)
            record = repository.get(verifier_job_id)
            if record is None:
                return None

            now = _utc_now()
            record.status = VerifierJobStatus.SUCCEEDED.value
            record.completed_at = now
            record.updated_at = now
            record.last_error = payload.note
            if payload.verifier_run_id is not None:
                record.verifier_run_id = payload.verifier_run_id
            if payload.finding_id is not None:
                record.finding_id = payload.finding_id

            EventRepository(session).add(
                _create_event_record(
                    record.scan_id,
                    EventSource.SYSTEM,
                    "verifier_job.completed",
                    "reporting",
                    EventSeverity.INFO,
                    f"Verifier job {record.id} completed successfully.",
                    {
                        "job_id": record.id,
                        "verifier_run_id": record.verifier_run_id,
                        "finding_id": record.finding_id,
                    },
                    created_at=now,
                )
            )

            return _verifier_job_record_to_detail(record)

    def fail_verifier_job(self, verifier_job_id: str, payload: FailVerifierJobRequest) -> VerifierJobDetail | None:
        with session_scope() as session:
            repository = VerifierJobRepository(session)
            record = repository.get(verifier_job_id)
            if record is None:
                return None

            now = _utc_now()
            retry_scheduled = payload.retryable and record.attempt_count < record.max_attempts
            record.last_error = payload.error_message
            record.updated_at = now

            if retry_scheduled:
                record.status = VerifierJobStatus.QUEUED.value
                record.available_at = now + timedelta(seconds=payload.retry_delay_seconds)
                record.claimed_at = None
                record.worker_id = None
                event_type = "verifier_job.retry_scheduled"
                message = f"Verifier job {record.id} re-queued after failure."
                stage = "verification"
                severity = EventSeverity.WARNING
            else:
                record.status = VerifierJobStatus.FAILED.value
                record.completed_at = now
                event_type = "verifier_job.failed"
                message = f"Verifier job {record.id} failed permanently."
                stage = "verification"
                severity = EventSeverity.HIGH

            EventRepository(session).add(
                _create_event_record(
                    record.scan_id,
                    EventSource.SYSTEM,
                    event_type,
                    stage,
                    severity,
                    message,
                    {
                        "job_id": record.id,
                        "error": payload.error_message,
                        "retryable": retry_scheduled,
                        "attempt_count": record.attempt_count,
                    },
                    created_at=now,
                )
            )

            return _verifier_job_record_to_detail(record)

    def list_scan_events(self, scan_id: str, *, after_id: int | None = None, limit: int = 40) -> list[ScanEvent]:
        with session_scope() as session:
            records = EventRepository(session).list_for_scan(scan_id, after_id=after_id, limit=limit)
            return [_event_record_to_model(record) for record in records]

    def record_scan_event(self, scan_id: str, payload: RecordScanEventRequest) -> ScanEvent | None:
        with session_scope() as session:
            scan_record = ScanRepository(session).get(scan_id)
            if scan_record is None:
                return None

            now = _utc_now()
            event_record = _create_event_record(
                scan_id,
                payload.source,
                payload.event_type,
                payload.stage,
                payload.severity,
                payload.message,
                payload.payload,
                created_at=now,
            )
            EventRepository(session).add(event_record)
            scan_record.updated_at = now
            session.flush()
            session.refresh(event_record)
            return _event_record_to_model(event_record)

    def get_runtime_snapshot(self, scan_id: str, *, event_limit: int = 25) -> ScanStreamSnapshot | None:
        with session_scope() as session:
            scan_repository = ScanRepository(session)
            workflow_repository = WorkflowRepository(session)
            event_repository = EventRepository(session)

            scan_record = scan_repository.get(scan_id)
            graph_record = workflow_repository.get_by_scan_id(scan_id)

            if scan_record is None or graph_record is None:
                return None

            event_records = event_repository.list_recent_for_scan(scan_id, limit=event_limit)
            events = [_event_record_to_model(record) for record in reversed(event_records)]
            return ScanStreamSnapshot(
                scan=_scan_record_to_model(scan_record),
                graph=_graph_record_to_model(graph_record),
                events=events,
            )

    def ingest_scan_event(self, scan_id: str, payload: IngestScanEventRequest) -> ScanEventEnvelope | None:
        with session_scope() as session:
            scan_repository = ScanRepository(session)
            workflow_repository = WorkflowRepository(session)
            event_repository = EventRepository(session)
            replay_artifact_repository = ReplayArtifactRepository(session)

            scan_record = scan_repository.get(scan_id)
            graph_record = workflow_repository.get_by_scan_id(scan_id)

            if scan_record is None or graph_record is None:
                return None

            now = _utc_now()

            if payload.current_stage is not None:
                scan_record.current_stage = payload.current_stage
            else:
                scan_record.current_stage = payload.stage

            if payload.scan_status is not None:
                scan_record.status = payload.scan_status.value
            elif scan_record.status == ScanStatus.QUEUED.value and payload.source != EventSource.SYSTEM:
                scan_record.status = ScanStatus.RUNNING.value

            finding_risk: ScanRisk | None = None
            if payload.finding_updates:
                persisted_findings = _apply_finding_updates(session, scan_id, payload.finding_updates, now=now)
                session.flush()
                if persisted_findings:
                    finding_risk = max(
                        (_risk_from_finding_severity(FindingSeverity(record.severity)) for record in persisted_findings),
                        key=lambda risk: RISK_ORDER[risk],
                    )

                active_findings = [
                    record
                    for record in _list_findings_for_scan(session, scan_id)
                    if FindingStatus(record.status) != FindingStatus.RESOLVED
                ]
                scan_record.findings_count = len(active_findings)
            elif payload.findings_increment != 0:
                scan_record.findings_count = max(0, scan_record.findings_count + payload.findings_increment)

            if payload.flagged_paths_increment != 0:
                scan_record.flagged_paths = max(0, scan_record.flagged_paths + payload.flagged_paths_increment)

            merged_risk = _merge_risk(ScanRisk(scan_record.risk), _risk_from_severity(payload.severity))
            merged_risk = _merge_risk(merged_risk, payload.risk)
            merged_risk = _merge_risk(merged_risk, finding_risk)
            scan_record.risk = merged_risk.value
            scan_record.updated_at = now

            graph = _graph_record_to_model(graph_record)
            graph = _apply_graph_update(graph, payload.graph_update, scan_record.flagged_paths)
            _persist_graph(graph_record, graph)

            event_payload = dict(payload.payload or {})
            mapper_contract: WorkflowMapperPathFlaggedContract | None = None
            if isinstance(payload.producer_contract, WorkflowMapperPathFlaggedContract):
                mapper_contract = cast(WorkflowMapperPathFlaggedContract, payload.producer_contract)
            if mapper_contract is not None and mapper_contract.replay_plan is not None:
                event_payload.setdefault("path_id", mapper_contract.path_id)
            proxy_contract = getattr(payload, "producer_contract", None)
            if isinstance(proxy_contract, ProxyHttpObservedContract) and proxy_contract.replay_artifact is not None:
                artifact_record = _upsert_replay_artifact(
                    session,
                    scan_id,
                    request_fingerprint=proxy_contract.request_fingerprint,
                    actor=proxy_contract.actor,
                    method=proxy_contract.method,
                    host=proxy_contract.host,
                    path=proxy_contract.path,
                    artifact_input=proxy_contract.replay_artifact,
                    now=now,
                )
                session.flush()
                event_payload["replay_artifact_id"] = artifact_record.id

            queued_job: VerifierJobRecord | None = None
            if isinstance(payload.producer_contract, WorkflowMapperPathFlaggedContract):
                queued_job = _queue_verifier_job_from_path_contract(session, scan_id, payload.producer_contract, now=now)
                if queued_job is not None:
                    EventRepository(session).add(
                        _create_event_record(
                            scan_id,
                            EventSource.SYSTEM,
                            "verifier_job.queued",
                            "verification",
                            EventSeverity.INFO,
                            f"Queued verifier job {queued_job.id} for flagged path {queued_job.source_path_id}.",
                            {
                                "job_id": queued_job.id,
                                "path_id": queued_job.source_path_id,
                                "severity": queued_job.severity,
                            },
                            created_at=now,
                        )
                    )

            if isinstance(payload.producer_contract, VerifierFindingConfirmedContract):
                _upsert_verifier_run(session, scan_id, payload.producer_contract, now=now)

            event_record = _create_event_record(
                scan_id,
                payload.source,
                payload.event_type,
                payload.stage,
                payload.severity,
                payload.message,
                event_payload or None,
                created_at=now,
            )
            event_repository.add(event_record)
            session.flush()
            session.refresh(event_record)

            return ScanEventEnvelope(
                event=_event_record_to_model(event_record),
                scan=_scan_record_to_model(scan_record),
                graph=_graph_record_to_model(graph_record),
            )


audit_store = AuditStore()
