from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from api.app.security import require_admin_token
from api.schemas.ai import AiPlanningRunRequest, AiPlanningRunResponse
from api.schemas.planner import PlannerRunResponse
from api.services.planner_service import planner_service

router = APIRouter(prefix="/scans", tags=["planner"])


@router.post("/{scan_id}/planner/run", response_model=PlannerRunResponse, summary="Run the workflow planner for a scan")
async def run_workflow_planner(scan_id: str, _: None = Depends(require_admin_token)) -> PlannerRunResponse:
    result = planner_service.run_workflow_planner(scan_id)
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan run not found.")

    return result


@router.post("/{scan_id}/planner/run-ai", response_model=AiPlanningRunResponse, summary="Run the AI-assisted workflow planner for a scan")
async def run_ai_workflow_planner(
    scan_id: str,
    payload: AiPlanningRunRequest,
    _: None = Depends(require_admin_token),
) -> AiPlanningRunResponse:
    result = planner_service.run_ai_workflow_planner(scan_id, payload)
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan run not found.")

    return result
