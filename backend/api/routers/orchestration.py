from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from api.app.security import require_admin_token
from api.schemas.orchestration import OrchestrationSessionDetail, OrchestrationSessionSummary, StartOrchestrationRequest
from api.services.orchestration_service import orchestration_service
from api.services.scan_service import scan_service

router = APIRouter(prefix="/scans", tags=["orchestration"])


@router.post("/{scan_id}/orchestration/start", response_model=OrchestrationSessionDetail, summary="Start an autonomous pentest orchestration session")
async def start_orchestration_session(
    scan_id: str,
    payload: StartOrchestrationRequest,
    _: None = Depends(require_admin_token),
) -> OrchestrationSessionDetail:
    session = orchestration_service.start_session(scan_id, payload)
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan run not found.")
    return session


@router.get("/{scan_id}/orchestration/sessions", response_model=list[OrchestrationSessionSummary], summary="List orchestration sessions for a scan")
async def list_orchestration_sessions(scan_id: str, _: None = Depends(require_admin_token)) -> list[OrchestrationSessionSummary]:
    scan = scan_service.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan run not found.")
    return orchestration_service.list_sessions(scan_id)


@router.get("/orchestration/sessions/{session_id}", response_model=OrchestrationSessionDetail, summary="Read orchestration session detail")
async def get_orchestration_session(session_id: str, _: None = Depends(require_admin_token)) -> OrchestrationSessionDetail:
    session = orchestration_service.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Orchestration session not found.")
    return session
