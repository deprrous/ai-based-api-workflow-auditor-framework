from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from api.schemas.reports import ScanComparisonReport, ScanEvidenceBundle, ScanReport
from api.services.report_service import report_service

router = APIRouter(prefix="/scans", tags=["reports"])


@router.get("/{scan_id}/report", response_model=ScanReport, summary="Read scan report")
async def get_scan_report(scan_id: str) -> ScanReport:
    report = report_service.get_scan_report(scan_id)
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan report not found.")

    return report


@router.get("/{scan_id}/evidence-bundle", response_model=ScanEvidenceBundle, summary="Read scan evidence bundle")
async def get_scan_evidence_bundle(scan_id: str) -> ScanEvidenceBundle:
    bundle = report_service.get_scan_evidence_bundle(scan_id)
    if bundle is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence bundle not found.")

    return bundle


@router.get("/compare", response_model=ScanComparisonReport, summary="Compare findings between two scans")
async def compare_scans(
    baseline_scan_id: str = Query(description="Baseline scan identifier."),
    current_scan_id: str = Query(description="Current scan identifier."),
) -> ScanComparisonReport:
    comparison = report_service.compare_scans(baseline_scan_id, current_scan_id)
    if comparison is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="One or both scan runs were not found.")

    return comparison
