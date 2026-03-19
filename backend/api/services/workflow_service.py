from __future__ import annotations

from api.schemas.workflows import WorkflowGraph
from api.services.store import audit_store


class WorkflowService:
    def get_framework_principle_graph(self) -> WorkflowGraph:
        return audit_store.get_framework_principle()

    def get_scan_workflow(self, scan_id: str) -> WorkflowGraph | None:
        return audit_store.get_scan_workflow(scan_id)


workflow_service = WorkflowService()
