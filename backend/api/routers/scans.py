from __future__ import annotations

import asyncio

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import StreamingResponse

from api.app.config import get_settings
from api.schemas.events import IngestScanEventRequest, ScanEvent, ScanEventEnvelope
from api.schemas.scans import ScanRunSummary, StartScanRequest, StartScanResponse
from api.schemas.workflows import WorkflowGraph
from api.services.event_service import event_service
from api.services.scan_service import scan_service
from api.services.workflow_service import workflow_service
from api.streaming.sse import encode_sse

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("", response_model=list[ScanRunSummary], summary="List scan runs")
async def list_scans() -> list[ScanRunSummary]:
    return scan_service.list_scans()


@router.get("/{scan_id}/events", response_model=list[ScanEvent], summary="List runtime events for a scan run")
async def list_scan_events(scan_id: str) -> list[ScanEvent]:
    scan = scan_service.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan run not found.")

    return event_service.list_scan_events(scan_id)


@router.post(
    "/{scan_id}/events",
    response_model=ScanEventEnvelope,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest runtime output for a scan run",
)
async def ingest_scan_event(scan_id: str, payload: IngestScanEventRequest) -> ScanEventEnvelope:
    envelope = event_service.ingest_scan_event(scan_id, payload)
    if envelope is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan run not found.")

    return envelope


@router.get("/{scan_id}/events/stream", summary="Stream live runtime events for a scan run")
async def stream_scan_events(scan_id: str, request: Request) -> StreamingResponse:
    snapshot = event_service.get_runtime_snapshot(scan_id)
    if snapshot is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan run not found.")

    settings = get_settings()

    async def event_stream():
        last_event_id = snapshot.events[-1].id if snapshot.events else 0
        yield encode_sse("snapshot", snapshot.model_dump(mode="json"))

        while True:
            if await request.is_disconnected():
                break

            events = event_service.list_scan_events(scan_id, after_id=last_event_id, limit=100)
            if events:
                runtime = event_service.get_runtime_snapshot(scan_id)
                if runtime is None:
                    break

                for event in events:
                    last_event_id = event.id
                    payload = {
                        "event": event.model_dump(mode="json"),
                        "scan": runtime.scan.model_dump(mode="json"),
                        "graph": runtime.graph.model_dump(mode="json"),
                    }
                    yield encode_sse("scan.event", payload)

            await asyncio.sleep(settings.sse_poll_interval)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


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
