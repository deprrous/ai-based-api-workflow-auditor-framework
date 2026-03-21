from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from api.schemas.hypotheses import HypothesisDetail, HypothesisSummary
from api.services.hypothesis_service import hypothesis_service
from api.services.scan_service import scan_service

router = APIRouter(prefix="/hypotheses", tags=["hypotheses"])


@router.get("/scan/{scan_id}", response_model=list[HypothesisSummary], summary="List orchestration hypotheses for a scan")
async def list_hypotheses(scan_id: str) -> list[HypothesisSummary]:
    scan = scan_service.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan run not found.")
    return hypothesis_service.list_hypotheses(scan_id)


@router.get("/{hypothesis_id}", response_model=HypothesisDetail, summary="Read orchestration hypothesis detail")
async def get_hypothesis(hypothesis_id: str) -> HypothesisDetail:
    hypothesis = hypothesis_service.get_hypothesis(hypothesis_id)
    if hypothesis is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Hypothesis not found.")
    return hypothesis
