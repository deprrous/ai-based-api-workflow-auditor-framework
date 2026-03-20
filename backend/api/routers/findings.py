from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from api.schemas.findings import FindingDetail, FindingSeverity, FindingStatus, FindingSummary
from api.services.finding_service import finding_service

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=list[FindingSummary], summary="List findings")
async def list_findings(
    scan_id: str | None = Query(default=None, description="Optional scan identifier used to scope findings."),
    severity: FindingSeverity | None = Query(default=None, description="Optional severity filter."),
    status_filter: FindingStatus | None = Query(default=None, alias="status", description="Optional finding status filter."),
) -> list[FindingSummary]:
    return finding_service.list_findings(scan_id=scan_id, severity=severity, status=status_filter)


@router.get("/{finding_id}", response_model=FindingDetail, summary="Read finding detail")
async def get_finding(finding_id: str) -> FindingDetail:
    finding = finding_service.get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")

    return finding
