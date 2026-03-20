from __future__ import annotations

from tools.workflow.worker import (
    WorkflowMapperPublishOptions,
    WorkflowMapperWorker,
    WorkflowObservedStep,
    WorkflowPathFindingCandidate,
    build_ingest_request,
    build_workflow_mapper_contract,
)


def _sample_candidate() -> WorkflowPathFindingCandidate:
    return WorkflowPathFindingCandidate(
        scan_id="partner-boundary-scan",
        path_id="path-delete-escalation",
        title="Partner member reaches destructive project delete path",
        rationale="Captured invitation and membership steps lead into a destructive delete action without an explicit owner gate.",
        severity="high",
        steps=[
            WorkflowObservedStep(
                node_id="projects",
                label="GET /v1/projects",
                phase="read",
                detail="Partner member lists shared projects.",
                host="qa.example.internal",
                path="/v1/projects",
                method="GET",
                actor="partner-member",
                request_fingerprint="fp-projects",
            ),
            WorkflowObservedStep(
                node_id="members",
                label="POST /v1/projects/{projectId}/members",
                phase="action",
                detail="Partner member invitation path is followed.",
                host="qa.example.internal",
                path="/v1/projects/123/members",
                method="POST",
                actor="partner-member",
                request_fingerprint="fp-members",
            ),
            WorkflowObservedStep(
                node_id="delete-project",
                label="DELETE /v1/projects/{projectId}",
                phase="action",
                detail="Destructive project delete path is reachable from the shared member flow.",
                host="qa.example.internal",
                path="/v1/projects/123",
                method="DELETE",
                actor="partner-member",
                request_fingerprint="fp-delete",
            ),
        ],
        actor="partner-member",
    )


def test_workflow_mapper_builds_flagged_path_contract() -> None:
    candidate = _sample_candidate()
    contract = build_workflow_mapper_contract(candidate)
    request = build_ingest_request(candidate)

    assert contract.kind == "workflow_mapper.path_flagged"
    assert contract.flagged_paths_increment == 1
    assert len(contract.nodes) == 4
    assert contract.nodes[-1].type == "observation"
    assert len(contract.edges) == 3
    assert contract.replay_plan is not None
    assert len(contract.replay_plan.requests) == 3
    assert request.event_type == "workflow_mapper.path_flagged"
    assert request.source == "workflow_mapper"


def test_workflow_mapper_worker_can_publish_flagged_path_into_backend(client) -> None:
    options = WorkflowMapperPublishOptions(
        backend_url="http://testserver/api/v1",
        ingest_token="test-ingest-token",
    )

    def sender(_: WorkflowMapperPublishOptions, scan_id: str, payload: dict[str, object]) -> int:
        response = client.post(
            f"/api/v1/scans/{scan_id}/events",
            headers={"X-Auditor-Ingest-Token": "test-ingest-token"},
            json=payload,
        )
        return response.status_code

    worker = WorkflowMapperWorker(options=options, sender=sender)
    assert worker.publish_flagged_path(_sample_candidate()) is True

    scan_response = client.get("/api/v1/scans/partner-boundary-scan")
    assert scan_response.status_code == 200
    assert scan_response.json()["flagged_paths"] == 3

    workflow_response = client.get("/api/v1/scans/partner-boundary-scan/workflow")
    assert workflow_response.status_code == 200
    workflow = workflow_response.json()
    assert any(node["label"].startswith("Flagged Path:") for node in workflow["nodes"])
