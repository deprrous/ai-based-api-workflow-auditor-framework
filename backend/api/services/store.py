from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select

from api.app.database import session_scope
from api.app.db_models import ScanEventRecord, ScanRunRecord, WorkflowGraphRecord
from api.schemas.events import (
    EventSeverity,
    EventSource,
    IngestScanEventRequest,
    ScanEvent,
    ScanEventEnvelope,
    ScanStreamSnapshot,
    WorkflowEdgeReference,
    WorkflowGraphUpdate,
)
from api.schemas.scans import ScanRisk, ScanRunSummary, ScanStatus, StartScanRequest
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


class AuditStore:
    def ensure_seed_data(self) -> None:
        with session_scope() as session:
            framework_exists = session.scalar(
                select(WorkflowGraphRecord).where(WorkflowGraphRecord.kind == WorkflowGraphKind.FRAMEWORK_PRINCIPLE.value)
            )
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
                session.add(framework_record)

            scan_exists = session.scalar(select(ScanRunRecord.id).limit(1))
            if scan_exists is not None:
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

            session.add_all([bootstrap_scan, bootstrap_record, partner_scan, partner_record])
            session.add_all(
                [
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
                ]
            )

    def list_scans(self) -> list[ScanRunSummary]:
        with session_scope() as session:
            records = session.scalars(select(ScanRunRecord).order_by(ScanRunRecord.created_at.desc())).all()
            return [_scan_record_to_model(record) for record in records]

    def get_scan(self, scan_id: str) -> ScanRunSummary | None:
        with session_scope() as session:
            record = session.get(ScanRunRecord, scan_id)
            return _scan_record_to_model(record) if record else None

    def start_scan(self, payload: StartScanRequest) -> ScanRunSummary:
        scan_id = f"scan-{uuid4().hex[:8]}"
        workflow_id = f"workflow-{scan_id}"
        now = _utc_now()
        graph = _build_queued_scan_graph(scan_id, payload.name, payload.target)
        graph.updated_at = now

        with session_scope() as session:
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
            session.add_all([scan_record, graph_record])
            session.add(
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
            record = session.scalar(select(WorkflowGraphRecord).where(WorkflowGraphRecord.scan_id == scan_id))
            return _graph_record_to_model(record) if record else None

    def get_framework_principle(self) -> WorkflowGraph | None:
        with session_scope() as session:
            record = session.scalar(
                select(WorkflowGraphRecord).where(WorkflowGraphRecord.kind == WorkflowGraphKind.FRAMEWORK_PRINCIPLE.value)
            )
            return _graph_record_to_model(record) if record else None

    def list_scan_events(self, scan_id: str, *, after_id: int | None = None, limit: int = 40) -> list[ScanEvent]:
        with session_scope() as session:
            query = select(ScanEventRecord).where(ScanEventRecord.scan_id == scan_id)
            if after_id is not None:
                query = query.where(ScanEventRecord.id > after_id)

            records = session.scalars(query.order_by(ScanEventRecord.id.asc()).limit(limit)).all()
            return [_event_record_to_model(record) for record in records]

    def get_runtime_snapshot(self, scan_id: str, *, event_limit: int = 25) -> ScanStreamSnapshot | None:
        with session_scope() as session:
            scan_record = session.get(ScanRunRecord, scan_id)
            graph_record = session.scalar(select(WorkflowGraphRecord).where(WorkflowGraphRecord.scan_id == scan_id))

            if scan_record is None or graph_record is None:
                return None

            event_records = session.scalars(
                select(ScanEventRecord)
                .where(ScanEventRecord.scan_id == scan_id)
                .order_by(ScanEventRecord.id.desc())
                .limit(event_limit)
            ).all()
            events = [_event_record_to_model(record) for record in reversed(event_records)]
            return ScanStreamSnapshot(
                scan=_scan_record_to_model(scan_record),
                graph=_graph_record_to_model(graph_record),
                events=events,
            )

    def ingest_scan_event(self, scan_id: str, payload: IngestScanEventRequest) -> ScanEventEnvelope | None:
        with session_scope() as session:
            scan_record = session.get(ScanRunRecord, scan_id)
            graph_record = session.scalar(select(WorkflowGraphRecord).where(WorkflowGraphRecord.scan_id == scan_id))

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

            if payload.findings_increment != 0:
                scan_record.findings_count = max(0, scan_record.findings_count + payload.findings_increment)

            if payload.flagged_paths_increment != 0:
                scan_record.flagged_paths = max(0, scan_record.flagged_paths + payload.flagged_paths_increment)

            merged_risk = _merge_risk(
                ScanRisk(scan_record.risk),
                payload.risk or _risk_from_severity(payload.severity),
            )
            scan_record.risk = merged_risk.value
            scan_record.updated_at = now

            graph = _graph_record_to_model(graph_record)
            graph = _apply_graph_update(graph, payload.graph_update, scan_record.flagged_paths)
            _persist_graph(graph_record, graph)

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
            session.add(event_record)
            session.flush()
            session.refresh(event_record)

            return ScanEventEnvelope(
                event=_event_record_to_model(event_record),
                scan=_scan_record_to_model(scan_record),
                graph=_graph_record_to_model(graph_record),
            )


audit_store = AuditStore()
