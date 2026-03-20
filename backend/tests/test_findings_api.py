from __future__ import annotations


def test_list_scan_findings_returns_seeded_findings(client):
    response = client.get("/api/v1/scans/bootstrap-scan/findings")

    assert response.status_code == 200
    payload = response.json()

    assert len(payload) == 3
    assert all(item["scan_id"] == "bootstrap-scan" for item in payload)
    assert {item["severity"] for item in payload} == {"critical", "high", "review"}


def test_global_findings_endpoint_supports_filters(client):
    response = client.get(
        "/api/v1/findings",
        params={"scan_id": "partner-boundary-scan", "status": "candidate", "severity": "high"},
    )

    assert response.status_code == 200
    payload = response.json()

    assert len(payload) == 1
    assert payload[0]["id"] == "finding-partner-boundary-scan-member-keys"
    assert payload[0]["status"] == "candidate"


def test_ingesting_event_can_create_a_new_finding_and_update_scan_state(client):
    response = client.post(
        "/api/v1/scans/partner-boundary-scan/events",
        headers={"X-Auditor-Ingest-Token": "test-ingest-token"},
        json={
            "source": "verifier",
            "event_type": "finding_confirmed",
            "stage": "reporting",
            "severity": "critical",
            "message": "Verifier confirmed destructive partner role escalation.",
            "finding_updates": [
                {
                    "id": "finding-partner-boundary-scan-delete-escalation",
                    "title": "Invited partner member can delete shared projects",
                    "category": "bfla",
                    "severity": "critical",
                    "status": "confirmed",
                    "confidence": 95,
                    "endpoint": "DELETE /v1/projects/{projectId}",
                    "actor": "invited partner member",
                    "impact_summary": "Invited members can perform destructive project deletion without intended privileges.",
                    "remediation_summary": "Require explicit destructive-role authorization before project deletion.",
                    "description": "Verifier replay confirmed that a newly invited partner member can call the project delete endpoint successfully.",
                    "impact": "A low-trust external collaborator can remove shared projects and disrupt customer environments.",
                    "remediation": "Separate invitation acceptance from destructive roles and enforce permission checks before delete handlers execute.",
                    "workflow_node_ids": ["delete-project", "verifier", "review"],
                    "tags": ["role-boundary", "destructive-action"],
                    "evidence": [
                        {
                            "label": "Delete replay response",
                            "detail": "Replay as invited member returned HTTP 204 for project deletion.",
                            "source": "verifier",
                        }
                    ],
                }
            ],
        },
    )

    assert response.status_code == 202
    envelope = response.json()

    assert envelope["scan"]["risk"] == "critical"
    assert envelope["scan"]["findings_count"] == 2

    detail_response = client.get("/api/v1/findings/finding-partner-boundary-scan-delete-escalation")
    assert detail_response.status_code == 200

    detail = detail_response.json()
    assert detail["severity"] == "critical"
    assert detail["status"] == "confirmed"
    assert detail["evidence_count"] == 1

    scan_findings_response = client.get("/api/v1/scans/partner-boundary-scan/findings")
    assert scan_findings_response.status_code == 200
    assert len(scan_findings_response.json()) == 2


def test_ingest_endpoint_requires_valid_worker_token(client):
    response = client.post(
        "/api/v1/scans/partner-boundary-scan/events",
        json={
            "source": "proxy",
            "event_type": "partner_flow_ingested",
            "stage": "ingestion",
            "severity": "info",
            "message": "Captured flow without auth.",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Valid ingest token required."


def test_ingest_endpoint_accepts_bearer_worker_token(client):
    response = client.post(
        "/api/v1/scans/partner-boundary-scan/events",
        headers={"Authorization": "Bearer test-ingest-token"},
        json={
            "source": "proxy",
            "event_type": "partner_flow_ingested",
            "stage": "ingestion",
            "severity": "info",
            "message": "Captured flow with bearer auth.",
        },
    )

    assert response.status_code == 202
    assert response.json()["event"]["event_type"] == "partner_flow_ingested"
