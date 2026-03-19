from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from api.schemas.scans import ScanRunSummary, StartScanRequest, StartScanResponse
from api.schemas.workflows import WorkflowGraph
from api.services.scan_service import scan_service
from api.services.workflow_service import workflow_service

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("", response_model=list[ScanRunSummary], summary="List scan runs")
async def list_scans() -> list[ScanRunSummary]:
    return scan_service.list_scans()


@router.get("/{scan_id}", response_model=ScanRunSummary, summary="Read scan run detail")
async def get_scan(scan_id: str) -> ScanRunSummary:
    scan = scan_service.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan run not found.")

    return scan


@router.get("/{scan_id}/workflow", response_model=WorkflowGraph, summary="Read workflow graph for a scan run")
async def get_scan_workflow(scan_id: str) -> WorkflowGraph:
    graph = workflow_service.get_scan_workflow(scan_id)
    if graph is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workflow graph not found for scan run.")

    return graph


@router.post(
    "",
    response_model=StartScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Queue a new audit scan",
)
async def start_scan(payload: StartScanRequest) -> StartScanResponse:
    scan = scan_service.start_scan(payload)
    return StartScanResponse(
        run=scan,
        message="Scan queued. Workflow mapping and verification will be attached later.",
    )
