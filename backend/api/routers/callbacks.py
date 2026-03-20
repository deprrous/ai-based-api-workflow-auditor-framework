from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from api.app.security import require_verifier_job_token
from api.schemas.callbacks import CallbackExpectationDetail, CallbackExpectationSummary
from api.services.callback_service import callback_service
from api.services.scan_service import scan_service

router = APIRouter(prefix="/callbacks", tags=["callbacks"])


@router.api_route(
    "/public/{token}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    summary="Receive public callback events for SSRF/XSS verification",
)
async def receive_public_callback(token: str, request: Request) -> dict[str, str]:
    body = await request.body()
    expectation = callback_service.record_event(
        token=token,
        method=request.method,
        path=request.url.path,
        query_string=request.url.query or None,
        headers={str(key): str(value) for key, value in request.headers.items()},
        body_excerpt=body.decode("utf-8", errors="ignore")[:2000] if body else None,
        source_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    if expectation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Callback expectation not found.")

    return {"status": "received", "token": token}


@router.get("/scan/{scan_id}", response_model=list[CallbackExpectationSummary], summary="List callback expectations for a scan")
async def list_callbacks(scan_id: str, _: None = Depends(require_verifier_job_token)) -> list[CallbackExpectationSummary]:
    scan = scan_service.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan run not found.")
    return callback_service.list_expectations(scan_id)


@router.get("/token/{token}", response_model=CallbackExpectationDetail, summary="Read callback expectation detail")
async def get_callback(token: str, _: None = Depends(require_verifier_job_token)) -> CallbackExpectationDetail:
    expectation = callback_service.get_expectation_by_token(token)
    if expectation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Callback expectation not found.")
    return expectation
