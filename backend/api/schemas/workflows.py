from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class WorkflowGraphKind(StrEnum):
    FRAMEWORK_PRINCIPLE = "framework_principle"
    SCAN_RUN = "scan_run"


class WorkflowNodeType(StrEnum):
    INPUT = "input"
    INGESTION = "ingestion"
    CORE = "core"
    ACTION = "action"
    TOOL = "tool"
    CONTROL = "control"
    OBSERVATION = "observation"
    OUTPUT = "output"
    SUCCESS = "success"
    ACTOR = "actor"
    ENDPOINT = "endpoint"
    RESOURCE = "resource"
    FINDING = "finding"
    REMEDIATION = "remediation"


class WorkflowNodeStatus(StrEnum):
    IDLE = "idle"
    ACTIVE = "active"
    REVIEW = "review"
    HIGH = "high"
    CRITICAL = "critical"
    SAFE = "safe"


class WorkflowNode(BaseModel):
    id: str = Field(description="Stable node identifier.")
    label: str = Field(description="Short node label for the UI.")
    type: WorkflowNodeType = Field(description="Presentation category for the node.")
    phase: str = Field(description="Logical phase used for grouping in the UI.")
    detail: str | None = Field(default=None, description="Optional node detail text.")
    status: WorkflowNodeStatus = Field(default=WorkflowNodeStatus.IDLE, description="Risk or activity state for the node.")
    x: float = Field(description="X coordinate used by the workflow UI.")
    y: float = Field(description="Y coordinate used by the workflow UI.")


class WorkflowEdge(BaseModel):
    source: str = Field(description="Source node identifier.")
    target: str = Field(description="Target node identifier.")
    label: str | None = Field(default=None, description="Optional edge label.")
    style: str = Field(default="solid", description="Display hint for the edge style.")
    animated: bool = Field(default=False, description="Whether the edge should render as animated.")


class WorkflowGraphStats(BaseModel):
    node_count: int = Field(description="Total node count in the graph.")
    edge_count: int = Field(description="Total edge count in the graph.")
    critical_nodes: int = Field(description="Number of critical nodes in the graph.")
    flagged_paths: int = Field(description="Number of flagged or risky paths in the graph.")


class WorkflowGraph(BaseModel):
    id: str = Field(description="Stable graph identifier.")
    kind: WorkflowGraphKind = Field(description="Whether this graph is a framework principle or scan workflow.")
    scan_id: str | None = Field(default=None, description="Owning scan identifier when this graph belongs to a scan run.")
    title: str = Field(description="Human-readable graph title.")
    description: str = Field(description="What the graph represents.")
    updated_at: datetime = Field(description="UTC timestamp when the graph was last refreshed.")
    stats: WorkflowGraphStats = Field(description="Summary metrics attached to the graph.")
    nodes: list[WorkflowNode] = Field(description="Nodes shown in the workflow graph.")
    edges: list[WorkflowEdge] = Field(description="Directed edges between nodes.")
