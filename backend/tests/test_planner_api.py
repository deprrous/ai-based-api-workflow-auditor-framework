from __future__ import annotations


def _post_proxy_event(client, scan_id: str, *, request_id: str, fingerprint: str, method: str, path: str, node_id: str, label: str, actor: str) -> None:
    response = client.post(
        f"/api/v1/scans/{scan_id}/events",
        headers={"X-Auditor-Ingest-Token": "test-ingest-token"},
        json={
            "source": "proxy",
            "event_type": "proxy.http_observed",
            "stage": "ingestion",
            "severity": "info",
            "message": f"Observed {method} {path}",
            "producer_contract": {
                "kind": "proxy.http_observed",
                "request_id": request_id,
                "request_fingerprint": fingerprint,
                "method": method,
                "host": "qa.example.internal",
                "path": path,
                "status_code": 200 if method != "DELETE" else 204,
                "actor": actor,
                    "node": {
                    "id": node_id,
                    "label": label,
                    "type": "endpoint",
                    "phase": "action" if method in {"POST", "PUT", "PATCH", "DELETE"} else "read",
                    "detail": f"Observed {method} {path}",
                    "status": "high" if method == "DELETE" else "review",
                    "x": 600,
                        "y": 180,
                    },
                    "replay_artifact": {
                        "request_headers": {"Content-Type": "application/json"} if method in {"POST", "PUT", "PATCH", "DELETE"} else {},
                        "request_body_base64": "eyJwbGFubmVyIjp0cnVlfQ==" if method in {"POST", "PUT", "PATCH", "DELETE"} else None,
                        "request_content_type": "application/json" if method in {"POST", "PUT", "PATCH", "DELETE"} else None,
                        "response_status_code": 200 if method != "DELETE" else 204,
                        "response_headers": {},
                        "response_body_excerpt": "ok",
                    },
                },
            },
        )
    assert response.status_code == 202


def test_workflow_planner_derives_flagged_path_from_proxy_observations(client):
    create_response = client.post(
        "/api/v1/scans",
        json={"name": "Planner Derived Path Scan", "target": "qa", "notes": "planner test"},
    )
    assert create_response.status_code == 202
    scan_id = create_response.json()["run"]["id"]

    _post_proxy_event(
        client,
        scan_id,
        request_id="req-1",
        fingerprint="fp-projects-list",
        method="GET",
        path="/v1/projects",
        node_id="projects-list",
        label="GET /v1/projects",
        actor="partner-member",
    )
    _post_proxy_event(
        client,
        scan_id,
        request_id="req-2",
        fingerprint="fp-members-invite",
        method="POST",
        path="/v1/projects/123/members",
        node_id="members-invite",
        label="POST /v1/projects/{projectId}/members",
        actor="partner-member",
    )
    _post_proxy_event(
        client,
        scan_id,
        request_id="req-3",
        fingerprint="fp-delete-project",
        method="DELETE",
        path="/v1/projects/123",
        node_id="delete-project",
        label="DELETE /v1/projects/{projectId}",
        actor="partner-member",
    )

    planner_response = client.post(
        f"/api/v1/scans/{scan_id}/planner/run",
        headers={"X-Auditor-Admin-Token": "test-admin-token"},
    )
    assert planner_response.status_code == 200
    planner_payload = planner_response.json()
    assert planner_payload["planning_run_id"]
    assert planner_payload["candidate_count"] >= 1
    assert planner_payload["emitted_count"] >= 1
    assert planner_payload["queued_job_count"] >= 1
    assert planner_payload["candidates"][0]["vulnerability_class"]
    assert planner_payload["candidates"][0]["confidence"] >= 0
    assert planner_payload["candidates"][0]["matched_rule"]
    assert planner_payload["candidates"][0]["verifier_strategy"]

    jobs_response = client.get(f"/api/v1/scans/{scan_id}/verifier-jobs")
    assert jobs_response.status_code == 200
    jobs = jobs_response.json()
    assert len(jobs) >= 1
    assert jobs[0]["status"] == "queued"
    assert jobs[0]["severity"] in {"critical", "high"}

    job_detail_response = client.get(f"/api/v1/verifier-jobs/{jobs[0]['id']}")
    assert job_detail_response.status_code == 200
    job_detail = job_detail_response.json()
    assert all(request["artifact_id"] for request in job_detail["payload"]["replay_plan"]["requests"])

    events_response = client.get(f"/api/v1/scans/{scan_id}/events")
    assert events_response.status_code == 200
    events = events_response.json()
    assert any(event["event_type"] == "workflow_mapper.path_flagged" for event in events)
    assert any(event["event_type"] == "orchestrator.workflow_planner.completed" for event in events)

    history_response = client.get(
        f"/api/v1/scans/{scan_id}/planner/history",
        headers={"X-Auditor-Admin-Token": "test-admin-token"},
    )
    assert history_response.status_code == 200
    history = history_response.json()
    assert len(history) >= 1
    assert history[0]["mode"] == "deterministic"

    detail_response = client.get(
        f"/api/v1/scans/planner/runs/{planner_payload['planning_run_id']}",
        headers={"X-Auditor-Admin-Token": "test-admin-token"},
    )
    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert detail["provider_key"] == "deterministic"
    assert len(detail["candidates"]) >= 1
    assert detail["proposals"] == []

    rerun_response = client.post(
        f"/api/v1/scans/{scan_id}/planner/run",
        headers={"Authorization": "Bearer test-admin-token"},
    )
    assert rerun_response.status_code == 200
    rerun_payload = rerun_response.json()
    assert rerun_payload["emitted_count"] == 0
    assert rerun_payload["skipped_existing_count"] >= 1
