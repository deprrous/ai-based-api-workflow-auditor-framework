from __future__ import annotations


def _post_proxy_event(client, scan_id: str, *, request_id: str, fingerprint: str, method: str, path: str) -> None:
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
                "replay_artifact": {
                    "request_headers": {},
                    "request_body_base64": None,
                    "request_content_type": None,
                    "response_status_code": 200 if method != "DELETE" else 204,
                    "response_headers": {},
                    "response_body_excerpt": "ok",
                },
            },
        },
    )
    assert response.status_code == 202


def test_orchestration_session_runs_planners_and_verifier_cycles(client):
    create_response = client.post(
        "/api/v1/scans",
        json={"name": "Autonomous Session Scan", "target": "qa", "notes": "autonomous-session"},
    )
    assert create_response.status_code == 202
    scan_id = create_response.json()["run"]["id"]

    _post_proxy_event(client, scan_id, request_id="evt-1", fingerprint="fp-projects", method="GET", path="/v1/projects")
    _post_proxy_event(client, scan_id, request_id="evt-2", fingerprint="fp-members", method="POST", path="/v1/projects/123/members")
    _post_proxy_event(client, scan_id, request_id="evt-3", fingerprint="fp-delete", method="DELETE", path="/v1/projects/123")

    response = client.post(
        f"/api/v1/scans/{scan_id}/orchestration/start",
        headers={"X-Auditor-Admin-Token": "test-admin-token"},
        json={
            "use_ai_planner": True,
            "ai_provider_key": "mock",
            "max_verifier_cycles": 5,
            "ai_candidate_limit": 5,
            "ai_min_priority_score": 50,
        },
    )

    assert response.status_code == 200
    session = response.json()
    assert session["status"] == "completed"
    assert session["mode"] == "autonomous"
    assert session["provider_key"] == "mock"
    assert session["completed_verifier_cycles"] >= 1
    step_kinds = [step["kind"] for step in session["steps"]]
    assert step_kinds[0] == "prepare"
    assert "decision" in step_kinds
    assert "deterministic_planner" in step_kinds
    assert "ai_planner" in step_kinds
    assert "summary" in step_kinds
    assert session["memory"]["planning_runs"]
    assert session["memory"]["verifier_cycles"]
    assert session["memory"]["decisions"]

    history_response = client.get(
        f"/api/v1/scans/{scan_id}/orchestration/sessions",
        headers={"Authorization": "Bearer test-admin-token"},
    )
    assert history_response.status_code == 200
    history = history_response.json()
    assert len(history) >= 1
    assert history[0]["id"] == session["id"]

    detail_response = client.get(
        f"/api/v1/scans/orchestration/sessions/{session['id']}",
        headers={"X-Auditor-Admin-Token": "test-admin-token"},
    )
    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert detail["id"] == session["id"]
    assert len(detail["steps"]) >= 4
