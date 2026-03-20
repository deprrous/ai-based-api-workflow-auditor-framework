from __future__ import annotations


def test_runtime_ingest_contract_catalog_is_available(client):
    response = client.get("/api/v1/contracts/runtime-ingest")

    assert response.status_code == 200
    payload = response.json()

    assert payload["version"] == "v1"
    assert {item["kind"] for item in payload["definitions"]} == {
        "proxy.http_observed",
        "orchestrator.hypothesis_created",
        "workflow_mapper.path_flagged",
        "verifier.finding_confirmed",
    }


def test_proxy_contract_event_updates_scan_workflow_consistently(client):
    response = client.post(
        "/api/v1/scans/partner-boundary-scan/events",
        headers={"X-Auditor-Ingest-Token": "test-ingest-token"},
        json={
            "source": "proxy",
            "event_type": "proxy.http_observed",
            "stage": "ingestion",
            "severity": "info",
            "message": "Observed delete request from real target traffic.",
            "producer_contract": {
                "kind": "proxy.http_observed",
                "request_id": "req-001",
                "request_fingerprint": "fp-delete-project",
                "method": "DELETE",
                "host": "qa.example.internal",
                "path": "/v1/projects/123",
                "status_code": 204,
                "actor": "partner-member",
                "node": {
                    "id": "captured-delete-project",
                    "label": "DELETE /v1/projects/{projectId}",
                    "type": "endpoint",
                    "phase": "action",
                    "detail": "Captured directly by the proxy from target traffic.",
                    "status": "high",
                    "x": 1140,
                    "y": 360,
                },
                "edge": {
                    "source": "members",
                    "target": "captured-delete-project",
                    "label": "captured destructive path",
                    "style": "solid",
                    "animated": True,
                },
                "replay_artifact": {
                    "request_headers": {"Content-Type": "application/json", "Cookie": "session=abc123"},
                    "request_body_base64": "eyJkZWxldGUiOnRydWV9",
                    "request_content_type": "application/json",
                    "response_status_code": 204,
                    "response_headers": {},
                    "response_body_excerpt": "",
                },
            },
        },
    )

    assert response.status_code == 202
    envelope = response.json()
    assert envelope["graph"]["stats"]["node_count"] >= 9
    assert envelope["event"]["payload"]["request_fingerprint"] == "fp-delete-project"
    artifact_id = envelope["event"]["payload"]["replay_artifact_id"]
    assert artifact_id

    workflow_response = client.get("/api/v1/scans/partner-boundary-scan/workflow")
    assert workflow_response.status_code == 200

    workflow = workflow_response.json()
    assert any(node["id"] == "captured-delete-project" for node in workflow["nodes"])
    assert any(edge["target"] == "captured-delete-project" for edge in workflow["edges"])

    artifact_response = client.get(
        f"/api/v1/replay-artifacts/{artifact_id}",
        headers={"X-Auditor-Ingest-Token": "test-ingest-token"},
    )
    assert artifact_response.status_code == 200
    artifact = artifact_response.json()
    assert artifact["request_fingerprint"] == "fp-delete-project"
    assert artifact["method"] == "DELETE"
    assert artifact["request_headers"]["Content-Type"] == "application/json"
    assert artifact["request_headers"]["Cookie"] == "session=[REDACTED]"
    assert artifact["request_body_preview"] == '{"delete":true}'


def test_verifier_contract_creates_confirmed_finding(client):
    response = client.post(
        "/api/v1/scans/partner-boundary-scan/events",
        headers={"Authorization": "Bearer test-ingest-token"},
        json={
            "source": "verifier",
            "event_type": "verifier.finding_confirmed",
            "stage": "reporting",
            "severity": "info",
            "message": "Verifier confirmed destructive delete escalation.",
            "producer_contract": {
                "kind": "verifier.finding_confirmed",
                "verifier_run_id": "verify-001",
                "finding": {
                    "id": "finding-partner-boundary-scan-delete-confirmed",
                    "title": "Partner member can delete shared projects",
                    "category": "bfla",
                    "severity": "critical",
                    "status": "candidate",
                    "confidence": 96,
                    "endpoint": "DELETE /v1/projects/{projectId}",
                    "actor": "invited partner member",
                    "impact_summary": "Invited external members can delete shared projects.",
                    "remediation_summary": "Restrict destructive endpoints to explicit project-owner roles.",
                    "description": "The verifier replayed the destructive path as an invited partner member and received HTTP 204.",
                    "impact": "External collaborators can destroy shared projects and disrupt customers.",
                    "remediation": "Enforce destructive-role checks before project deletion and add role regression tests.",
                    "workflow_node_ids": ["delete-project", "verifier"],
                    "tags": ["bfla", "destructive-action"],
                    "evidence": [
                        {
                            "label": "Verifier delete replay",
                            "detail": "Replay succeeded with HTTP 204 while using invited partner credentials.",
                            "source": "verifier",
                        }
                    ],
                },
                "finding_node": {
                    "id": "finding-delete-confirmed-node",
                    "label": "Finding: Delete Escalation",
                    "type": "finding",
                    "phase": "reporting",
                    "detail": "Confirmed destructive privilege escalation.",
                    "status": "critical",
                    "x": 2040,
                    "y": 320,
                },
                "edges": [
                    {
                        "source": "delete-project",
                        "target": "finding-delete-confirmed-node",
                        "label": "confirmed exploit",
                        "style": "dashed",
                        "animated": True,
                    }
                ],
            },
        },
    )

    assert response.status_code == 202
    envelope = response.json()
    assert envelope["scan"]["risk"] == "critical"

    finding_response = client.get("/api/v1/findings/finding-partner-boundary-scan-delete-confirmed")
    assert finding_response.status_code == 200
    finding = finding_response.json()
    assert finding["status"] == "confirmed"
    assert finding["severity"] == "critical"


def test_contract_source_mismatch_is_rejected(client):
    response = client.post(
        "/api/v1/scans/partner-boundary-scan/events",
        headers={"X-Auditor-Ingest-Token": "test-ingest-token"},
        json={
            "source": "proxy",
            "event_type": "verifier.finding_confirmed",
            "stage": "reporting",
            "severity": "critical",
            "message": "Invalid mixed producer contract.",
            "producer_contract": {
                "kind": "verifier.finding_confirmed",
                "verifier_run_id": "verify-bad",
                "finding": {
                    "title": "Invalid",
                    "category": "bfla",
                    "severity": "critical",
                    "status": "candidate",
                    "confidence": 90,
                    "impact_summary": "bad",
                    "remediation_summary": "bad",
                    "description": "bad",
                    "impact": "bad",
                    "remediation": "bad",
                    "evidence": [],
                    "workflow_node_ids": [],
                    "tags": [],
                },
            },
        },
    )

    assert response.status_code == 422
