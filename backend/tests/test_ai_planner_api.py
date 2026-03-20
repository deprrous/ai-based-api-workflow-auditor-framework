from __future__ import annotations


def _seed_scan_with_risky_proxy_sequence(client) -> str:
    create_response = client.post(
        "/api/v1/scans",
        json={"name": "AI Planner Scan", "target": "qa", "notes": "ai-planner"},
    )
    assert create_response.status_code == 202
    scan_id = create_response.json()["run"]["id"]

    client.post(
        f"/api/v1/artifacts/scan/{scan_id}/api-spec",
        json={
            "name": "planner-openapi.yaml",
            "path": "specs/planner-openapi.yaml",
            "format": "openapi",
            "content": """
openapi: 3.1.0
paths:
  /v1/projects:
    get:
      summary: List projects
  /v1/projects/123/members:
    post:
      summary: Invite member
  /v1/projects/123:
    delete:
      summary: Delete project
""",
        },
    )

    def post_proxy_event(request_id: str, fingerprint: str, method: str, path: str):
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
                    "actor": "partner-member",
                    "node": {
                        "id": request_id,
                        "label": f"{method} {path}",
                        "type": "endpoint",
                        "phase": "action" if method in {"POST", "DELETE"} else "read",
                        "detail": f"Observed {method} {path}",
                        "status": "high" if method == "DELETE" else "review",
                        "x": 640,
                        "y": 180,
                    },
                },
            },
        )
        assert response.status_code == 202

    post_proxy_event("evt-a", "fp-projects", "GET", "/v1/projects")
    post_proxy_event("evt-b", "fp-members", "POST", "/v1/projects/123/members")
    post_proxy_event("evt-c", "fp-delete", "DELETE", "/v1/projects/123")

    return scan_id


def test_ai_planner_mock_provider_can_preview_candidates_without_emitting(client):
    scan_id = _seed_scan_with_risky_proxy_sequence(client)

    response = client.post(
        f"/api/v1/scans/{scan_id}/planner/run-ai",
        headers={"X-Auditor-Admin-Token": "test-admin-token"},
        json={
            "provider_key": "mock",
            "apply": False,
            "candidate_limit": 8,
            "min_priority_score": 50,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["planning_run_id"]
    assert payload["provider_key"] == "mock"
    assert payload["candidate_count"] >= 1
    assert payload["suggested_count"] >= 1
    assert payload["emitted_count"] == 0
    assert payload["apply"] is False
    assert payload["proposals"][0]["tags"]
    assert any(proposal["include_in_plan"] for proposal in payload["proposals"])


def test_ai_planner_mock_provider_can_emit_flagged_paths_and_jobs(client):
    scan_id = _seed_scan_with_risky_proxy_sequence(client)

    response = client.post(
        f"/api/v1/scans/{scan_id}/planner/run-ai",
        headers={"Authorization": "Bearer test-admin-token"},
        json={
            "provider_key": "mock",
            "apply": True,
            "candidate_limit": 8,
            "min_priority_score": 50,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["planning_run_id"]
    assert payload["provider_key"] == "mock"
    assert payload["suggested_count"] >= 1
    assert payload["emitted_count"] >= 1

    jobs_response = client.get(f"/api/v1/scans/{scan_id}/verifier-jobs")
    assert jobs_response.status_code == 200
    assert len(jobs_response.json()) >= 1

    events_response = client.get(f"/api/v1/scans/{scan_id}/events")
    assert events_response.status_code == 200
    event_types = {event["event_type"] for event in events_response.json()}
    assert "orchestrator.ai_planner.completed" in event_types

    history_response = client.get(
        f"/api/v1/scans/{scan_id}/planner/history",
        headers={"X-Auditor-Admin-Token": "test-admin-token"},
    )
    assert history_response.status_code == 200
    history = history_response.json()
    assert len(history) >= 1
    assert history[0]["mode"] == "ai_assisted"

    detail_response = client.get(
        f"/api/v1/scans/planner/runs/{payload['planning_run_id']}",
        headers={"X-Auditor-Admin-Token": "test-admin-token"},
    )
    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert detail["provider_key"] == "mock"
    assert len(detail["proposals"]) >= 1


def test_ai_provider_catalog_includes_mock_provider(client):
    response = client.get("/api/v1/ai/providers/catalog")

    assert response.status_code == 200
    payload = response.json()
    provider_keys = {provider["key"] for provider in payload["providers"]}
    assert "mock" in provider_keys
