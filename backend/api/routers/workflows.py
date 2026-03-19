from __future__ import annotations

from fastapi import APIRouter

from api.schemas.workflows import WorkflowGraph
from api.services.workflow_service import workflow_service

router = APIRouter(prefix="/workflows", tags=["workflows"])


@router.get(
    "/framework-principle",
    response_model=WorkflowGraph,
    summary="Read the improved framework work-principle graph",
)
async def read_framework_principle() -> WorkflowGraph:
    return workflow_service.get_framework_principle_graph()


@router.get(
    "/agentic-loop",
    response_model=WorkflowGraph,
    summary="Backward-compatible alias for the framework work-principle graph",
    deprecated=True,
)
async def read_agentic_loop() -> WorkflowGraph:
    return workflow_service.get_framework_principle_graph()
