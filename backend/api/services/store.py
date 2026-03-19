from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

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


class AuditStore:
    def __init__(self) -> None:
        self._framework_principle = _build_framework_principle_graph()
        self._scans: dict[str, ScanRunSummary] = {}
        self._scan_workflows: dict[str, WorkflowGraph] = {}
        self._seed()

    def _seed(self) -> None:
        bootstrap_scan = ScanRunSummary(
            id="bootstrap-scan",
            name="Tenant Billing Workflow Audit",
            status=ScanStatus.COMPLETED,
            target="staging",
            created_at=datetime(2026, 3, 19, 0, 0, tzinfo=timezone.utc),
            current_stage="reporting",
            findings_count=3,
            flagged_paths=2,
            risk=ScanRisk.CRITICAL,
            workflow_id="workflow-bootstrap-scan",
        )
        partner_scan = ScanRunSummary(
            id="partner-boundary-scan",
            name="Partner Project Boundary Audit",
            status=ScanStatus.RUNNING,
            target="qa",
            created_at=datetime(2026, 3, 19, 1, 30, tzinfo=timezone.utc),
            current_stage="observation",
            findings_count=1,
            flagged_paths=2,
            risk=ScanRisk.HIGH,
            workflow_id="workflow-partner-boundary-scan",
        )
        self._scans[bootstrap_scan.id] = bootstrap_scan
        self._scans[partner_scan.id] = partner_scan
        self._scan_workflows[bootstrap_scan.id] = _build_billing_scan_graph(bootstrap_scan.id)
        self._scan_workflows[partner_scan.id] = _build_partner_scan_graph(partner_scan.id)

    def list_scans(self) -> list[ScanRunSummary]:
        return [scan.model_copy(deep=True) for scan in sorted(self._scans.values(), key=lambda item: item.created_at, reverse=True)]

    def get_scan(self, scan_id: str) -> ScanRunSummary | None:
        scan = self._scans.get(scan_id)
        return scan.model_copy(deep=True) if scan else None

    def start_scan(self, payload: StartScanRequest) -> ScanRunSummary:
        scan_id = f"scan-{uuid4().hex[:8]}"
        workflow_id = f"workflow-{scan_id}"
        scan = ScanRunSummary(
            id=scan_id,
            name=payload.name,
            status=ScanStatus.QUEUED,
            target=payload.target,
            created_at=_utc_now(),
            current_stage="ingestion",
            findings_count=0,
            flagged_paths=0,
            risk=ScanRisk.REVIEW,
            workflow_id=workflow_id,
        )
        self._scans[scan_id] = scan
        self._scan_workflows[scan_id] = _build_queued_scan_graph(scan_id, payload.name, payload.target)
        return scan.model_copy(deep=True)

    def get_scan_workflow(self, scan_id: str) -> WorkflowGraph | None:
        graph = self._scan_workflows.get(scan_id)
        return graph.model_copy(deep=True) if graph else None

    def get_framework_principle(self) -> WorkflowGraph:
        return self._framework_principle.model_copy(deep=True)


audit_store = AuditStore()
