from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"


class ScanRisk(StrEnum):
    SAFE = "safe"
    REVIEW = "review"
    HIGH = "high"
    CRITICAL = "critical"


class ScanRunSummary(BaseModel):
    id: str = Field(description="Stable identifier for the scan run.")
    name: str = Field(description="Human-readable scan run name.")
    status: ScanStatus = Field(description="Current scan lifecycle state.")
    target: str | None = Field(default=None, description="Optional target environment label.")
    created_at: datetime = Field(description="UTC timestamp when the scan run was created.")
    current_stage: str = Field(description="Current lifecycle stage for the scan run.")
    findings_count: int = Field(description="Total findings attached to the scan run.")
    flagged_paths: int = Field(description="Flagged workflow paths in the current graph.")
    risk: ScanRisk = Field(description="Highest current risk seen in the scan run.")
    workflow_id: str = Field(description="Workflow graph identifier attached to the scan run.")


class StartScanRequest(BaseModel):
    name: str = Field(min_length=3, max_length=120, description="Name for the new scan run.")
    target: str | None = Field(
        default=None,
        max_length=120,
        description="Optional target environment or application label.",
    )
    notes: str | None = Field(
        default=None,
        max_length=500,
        description="Optional operator notes for the scan run.",
    )


class StartScanResponse(BaseModel):
    run: ScanRunSummary
    message: str = Field(description="Short status message for the caller.")
