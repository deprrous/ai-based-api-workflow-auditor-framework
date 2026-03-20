from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from api.schemas.verifier_runs import VerifierRunDetail, VerifierRunSummary
from api.services.scan_service import scan_service
from api.services.verifier_run_service import verifier_run_service

router = APIRouter(prefix="/verifier-runs", tags=["verifier-runs"])


@router.get("/scan/{scan_id}", response_model=list[VerifierRunSummary], summary="List verifier runs for a scan")
async def list_verifier_runs(scan_id: str) -> list[VerifierRunSummary]:
    scan = scan_service.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan run not found.")

    return verifier_run_service.list_verifier_runs(scan_id)


@router.get("/{verifier_run_id}", response_model=VerifierRunDetail, summary="Read verifier run detail")
async def get_verifier_run(verifier_run_id: str) -> VerifierRunDetail:
    verifier_run = verifier_run_service.get_verifier_run(verifier_run_id)
    if verifier_run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Verifier run not found.")

    return verifier_run
