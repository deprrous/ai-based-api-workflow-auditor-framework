from __future__ import annotations


def test_scan_report_and_evidence_bundle_return_seeded_backend_data(client):
    report_response = client.get("/api/v1/scans/bootstrap-scan/report")

    assert report_response.status_code == 200
    report = report_response.json()
    assert report["scan"]["id"] == "bootstrap-scan"
    assert report["severity_breakdown"] == {"review": 1, "high": 1, "critical": 1}
    assert report["status_breakdown"] == {"candidate": 1, "confirmed": 2, "resolved": 0}
    assert len(report["findings"]) == 3
    assert report["workflow"]["workflow_id"] == "workflow-bootstrap-scan"
    assert len(report["recent_events"]) >= 1

    bundle_response = client.get("/api/v1/scans/bootstrap-scan/evidence-bundle")
    assert bundle_response.status_code == 200

    bundle = bundle_response.json()
    assert bundle["scan"]["id"] == "bootstrap-scan"
    assert len(bundle["findings"]) == 3
    assert bundle["total_evidence_items"] == 4


def test_scan_comparison_reports_new_resolved_and_changed_findings(client):
    create_response = client.post(
        "/api/v1/scans",
        json={"name": "Current Comparison Scan", "target": "qa", "notes": "comparison"},
    )
    assert create_response.status_code == 202
    current_scan_id = create_response.json()["run"]["id"]

    ingest_response = client.post(
        f"/api/v1/scans/{current_scan_id}/events",
        headers={"X-Auditor-Ingest-Token": "test-ingest-token"},
        json={
            "source": "verifier",
            "event_type": "finding_confirmed",
            "stage": "reporting",
            "severity": "critical",
            "message": "Confirmed comparison findings.",
            "finding_updates": [
                    {
                        "id": "finding-current-bola-read-updated",
                        "title": "Cross-tenant invoice read via direct object reference",
                    "category": "bola",
                    "severity": "critical",
                    "status": "confirmed",
                    "confidence": 99,
                    "endpoint": "GET /v1/invoices/{invoiceId}",
                    "actor": "second-tenant user",
                    "impact_summary": "Updated confidence summary.",
                    "remediation_summary": "Updated remediation summary.",
                    "description": "Updated finding description.",
                    "impact": "Updated impact.",
                    "remediation": "Updated remediation.",
                    "evidence": [
                        {
                            "label": "Updated verifier replay",
                            "detail": "Updated evidence for comparison drift.",
                            "source": "verifier",
                        }
                    ],
                    "context_references": [],
                    "workflow_node_ids": ["invoice-detail"],
                    "tags": ["bola"],
                },
                {
                    "id": "finding-current-new-ssrf",
                    "title": "Callback import path can reach internal metadata target",
                    "category": "ssrf",
                    "severity": "high",
                    "status": "confirmed",
                    "confidence": 91,
                    "endpoint": "POST /v1/imports",
                    "actor": "partner-member",
                    "impact_summary": "New SSRF finding.",
                    "remediation_summary": "Restrict outbound requests.",
                    "description": "New SSRF description.",
                    "impact": "New SSRF impact.",
                    "remediation": "New SSRF remediation.",
                    "evidence": [
                        {
                            "label": "OOB callback",
                            "detail": "Metadata callback observed.",
                            "source": "verifier",
                        }
                    ],
                    "context_references": [],
                    "workflow_node_ids": ["imports"],
                    "tags": ["ssrf"],
                },
            ],
        },
    )
    assert ingest_response.status_code == 202

    comparison_response = client.get(
        "/api/v1/scans/compare",
        params={"baseline_scan_id": "bootstrap-scan", "current_scan_id": current_scan_id},
    )
    assert comparison_response.status_code == 200
    comparison = comparison_response.json()

    assert comparison["summary"]["new_findings"] == 1
    assert comparison["summary"]["resolved_findings"] == 2
    assert comparison["summary"]["changed_findings"] == 1
    assert comparison["summary"]["unchanged_findings"] == 0

    kinds = {entry["kind"] for entry in comparison["comparisons"]}
    assert {"new", "resolved", "changed"}.issubset(kinds)


def test_service_account_lifecycle_can_secure_worker_ingest(client):
    create_response = client.post(
        "/api/v1/service-accounts",
        headers={"X-Auditor-Admin-Token": "test-admin-token"},
        json={
            "name": "proxy-worker",
            "kind": "worker",
            "description": "Worker used by the proxy ingestion pipeline.",
            "scopes": ["ingest:events"],
        },
    )

    assert create_response.status_code == 201
    created = create_response.json()
    service_account_id = created["account"]["id"]
    worker_token = created["token"]

    list_response = client.get(
        "/api/v1/service-accounts",
        headers={"Authorization": "Bearer test-admin-token"},
    )
    assert list_response.status_code == 200
    assert any(item["id"] == service_account_id for item in list_response.json())

    ingest_payload = {
        "source": "proxy",
        "event_type": "target_request_observed",
        "stage": "ingestion",
        "severity": "warning",
        "message": "Observed a destructive request path from target traffic.",
    }

    ingest_response = client.post(
        "/api/v1/scans/partner-boundary-scan/events",
        headers={"Authorization": f"Bearer {worker_token}"},
        json=ingest_payload,
    )
    assert ingest_response.status_code == 202

    rotate_response = client.post(
        f"/api/v1/service-accounts/{service_account_id}/rotate",
        headers={"X-Auditor-Admin-Token": "test-admin-token"},
    )
    assert rotate_response.status_code == 200
    rotated = rotate_response.json()
    rotated_token = rotated["token"]
    assert rotated_token != worker_token

    stale_token_response = client.post(
        "/api/v1/scans/partner-boundary-scan/events",
        headers={"Authorization": f"Bearer {worker_token}"},
        json=ingest_payload,
    )
    assert stale_token_response.status_code == 401

    revoke_response = client.post(
        f"/api/v1/service-accounts/{service_account_id}/revoke",
        headers={"X-Auditor-Admin-Token": "test-admin-token"},
    )
    assert revoke_response.status_code == 200
    assert revoke_response.json()["is_active"] is False

    revoked_token_response = client.post(
        "/api/v1/scans/partner-boundary-scan/events",
        headers={"Authorization": f"Bearer {rotated_token}"},
        json=ingest_payload,
    )
    assert revoked_token_response.status_code == 401
