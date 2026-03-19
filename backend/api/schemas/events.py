from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from api.schemas.scans import ScanRisk, ScanRunSummary, ScanStatus
from api.schemas.workflows import WorkflowEdge, WorkflowGraph, WorkflowNode


class EventSource(StrEnum):
    SYSTEM = "system"
    PROXY = "proxy"
    ORCHESTRATOR = "orchestrator"
    ANALYZER = "analyzer"
    WORKFLOW_MAPPER = "workflow_mapper"
    VERIFIER = "verifier"


class EventSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    HIGH = "high"
    CRITICAL = "critical"


class WorkflowEdgeReference(BaseModel):
    source: str
    target: str
    label: str | None = None


class WorkflowGraphUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    upsert_nodes: list[WorkflowNode] = Field(default_factory=list)
    upsert_edges: list[WorkflowEdge] = Field(default_factory=list)
    remove_node_ids: list[str] = Field(default_factory=list)
    remove_edges: list[WorkflowEdgeReference] = Field(default_factory=list)


class IngestScanEventRequest(BaseModel):
    source: EventSource
    event_type: str = Field(min_length=2, max_length=80)
    stage: str = Field(min_length=2, max_length=64)
    severity: EventSeverity = EventSeverity.INFO
    message: str = Field(min_length=3, max_length=500)
    payload: dict[str, Any] | None = None
    scan_status: ScanStatus | None = None
    risk: ScanRisk | None = None
    current_stage: str | None = None
    findings_increment: int = 0
    flagged_paths_increment: int = 0
    graph_update: WorkflowGraphUpdate | None = None


class ScanEvent(BaseModel):
    id: int
    scan_id: str
    source: EventSource
    event_type: str
    stage: str
    severity: EventSeverity
    message: str
    payload: dict[str, Any] | None = None
    created_at: datetime


class ScanEventEnvelope(BaseModel):
    event: ScanEvent
    scan: ScanRunSummary
    graph: WorkflowGraph


class ScanStreamSnapshot(BaseModel):
    scan: ScanRunSummary
    graph: WorkflowGraph
    events: list[ScanEvent]
