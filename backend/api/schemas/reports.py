from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from api.schemas.events import ScanEvent
from api.schemas.findings import FindingDetail, FindingSummary
from api.schemas.scans import ScanRunSummary


class WorkflowReportSummary(BaseModel):
    workflow_id: str = Field(description="Workflow identifier linked to the scan report.")
    title: str = Field(description="Workflow title used in the report.")
    updated_at: datetime = Field(description="Last workflow update timestamp.")
    node_count: int = Field(description="Workflow node count.")
    edge_count: int = Field(description="Workflow edge count.")
    flagged_paths: int = Field(description="Flagged workflow paths in the graph.")
    critical_nodes: int = Field(description="Critical workflow nodes in the graph.")


class SeverityBreakdown(BaseModel):
    review: int = 0
    high: int = 0
    critical: int = 0


class StatusBreakdown(BaseModel):
    candidate: int = 0
    confirmed: int = 0
    resolved: int = 0


class ScanReport(BaseModel):
    generated_at: datetime
    scan: ScanRunSummary
    workflow: WorkflowReportSummary
    severity_breakdown: SeverityBreakdown
    status_breakdown: StatusBreakdown
    findings: list[FindingSummary]
    recent_events: list[ScanEvent]


class ScanEvidenceBundle(BaseModel):
    exported_at: datetime
    scan: ScanRunSummary
    findings: list[FindingDetail]
    total_evidence_items: int
