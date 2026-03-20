from __future__ import annotations


def test_seeded_verifier_job_is_available_for_partner_scan(client):
    response = client.get("/api/v1/scans/partner-boundary-scan/verifier-jobs")

    assert response.status_code == 200
    payload = response.json()
    assert len(payload) >= 1
    assert any(job["id"] == "job-partner-member-keys" for job in payload)


def test_path_flagged_event_queues_verifier_job(client):
    response = client.post(
        "/api/v1/scans/partner-boundary-scan/events",
        headers={"X-Auditor-Ingest-Token": "test-ingest-token"},
        json={
            "source": "workflow_mapper",
            "event_type": "workflow_mapper.path_flagged",
            "stage": "verification",
            "severity": "high",
            "message": "Workflow mapper flagged a destructive partner path.",
            "producer_contract": {
                "kind": "workflow_mapper.path_flagged",
                "path_id": "path-destructive-delete",
                "title": "Partner member reaches destructive delete path",
                "severity": "high",
                "rationale": "The shared membership flow reaches the destructive delete action without an explicit owner gate.",
                "nodes": [
                    {
                        "id": "projects",
                        "label": "GET /v1/projects",
                        "type": "endpoint",
                        "phase": "read",
                        "detail": "Partner member lists projects.",
                        "status": "review",
                        "x": 640,
                        "y": 180,
                    },
                    {
                        "id": "delete-project",
                        "label": "DELETE /v1/projects/{projectId}",
                        "type": "endpoint",
                        "phase": "action",
                        "detail": "Destructive delete path reached from shared project context.",
                        "status": "high",
                        "x": 920,
                        "y": 180,
                    },
                ],
                "edges": [
                    {
                        "source": "projects",
                        "target": "delete-project",
                        "label": "observed sequence",
                        "style": "solid",
                        "animated": True,
                    }
                ],
                "flagged_paths_increment": 1,
            },
        },
    )

    assert response.status_code == 202

    jobs_response = client.get("/api/v1/scans/partner-boundary-scan/verifier-jobs")
    assert jobs_response.status_code == 200
    jobs = jobs_response.json()
    assert any(job["source_path_id"] == "path-destructive-delete" for job in jobs)


def test_verifier_job_claim_fail_retry_and_complete_lifecycle(client):
    claim_response = client.post(
        "/api/v1/verifier-jobs/claim",
        headers={"X-Auditor-Ingest-Token": "test-ingest-token"},
        json={"scan_id": "partner-boundary-scan", "worker_id": "verifier-worker-1"},
    )

    assert claim_response.status_code == 200
    job = claim_response.json()["job"]
    assert job is not None
    job_id = job["id"]
    assert job["status"] == "running"
    assert job["attempt_count"] == 1

    fail_response = client.post(
        f"/api/v1/verifier-jobs/{job_id}/fail",
        headers={"Authorization": "Bearer test-ingest-token"},
        json={
            "error_message": "Transient upstream timeout during replay.",
            "retryable": True,
            "retry_delay_seconds": 0,
        },
    )
    assert fail_response.status_code == 200
    failed_job = fail_response.json()
    assert failed_job["status"] == "queued"
    assert failed_job["last_error"] == "Transient upstream timeout during replay."

    second_claim_response = client.post(
        "/api/v1/verifier-jobs/claim",
        headers={"X-Auditor-Ingest-Token": "test-ingest-token"},
        json={"scan_id": "partner-boundary-scan", "worker_id": "verifier-worker-2"},
    )
    assert second_claim_response.status_code == 200
    second_job = second_claim_response.json()["job"]
    assert second_job is not None
    assert second_job["id"] == job_id
    assert second_job["attempt_count"] == 2

    complete_response = client.post(
        f"/api/v1/verifier-jobs/{job_id}/complete",
        headers={"X-Auditor-Ingest-Token": "test-ingest-token"},
        json={
            "verifier_run_id": "verify-job-lifecycle",
            "finding_id": "finding-job-lifecycle",
            "note": "Replay completed successfully after retry.",
        },
    )
    assert complete_response.status_code == 200
    completed_job = complete_response.json()
    assert completed_job["status"] == "succeeded"
    assert completed_job["verifier_run_id"] == "verify-job-lifecycle"
    assert completed_job["finding_id"] == "finding-job-lifecycle"
