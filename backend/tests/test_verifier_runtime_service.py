from __future__ import annotations

from dataclasses import replace
from datetime import timedelta, timezone

from api.app.config import get_settings
from api.app.database import session_scope
from api.repositories.replay_artifact_repository import ReplayArtifactRepository
from api.schemas.verifier_jobs import (
    ClaimVerifierJobRequest,
    CompleteVerifierJobRequest,
    ReplayMutationSpec,
    ReplayRefreshRequestSpec,
)
from api.services.replay_artifact_service import replay_artifact_service
from api.services.verifier_job_service import verifier_job_service
from api.services.verifier_runtime_service import (
    DeterministicDevVerifierExecutor,
    HttpReplayVerifierExecutor,
    ReplayHttpResult,
    VerifierRuntimeService,
    build_runtime_service,
)


def _create_scan_with_planned_job(client) -> str:
    create_response = client.post(
        "/api/v1/scans",
        json={"name": "Replay Artifact Scan", "target": "qa", "notes": "replay-artifact-test"},
    )
    assert create_response.status_code == 202
    scan_id = create_response.json()["run"]["id"]

    def post_proxy_event(*, request_id: str, fingerprint: str, method: str, path: str, node_id: str, label: str, body: str | None = None):
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
                    "status_code": 200,
                    "actor": "partner-member",
                    "node": {
                        "id": node_id,
                        "label": label,
                        "type": "endpoint",
                        "phase": "action" if method in {"POST", "PUT", "PATCH", "DELETE"} else "read",
                        "detail": f"Observed {method} {path}",
                        "status": "high" if method == "DELETE" else "review",
                        "x": 640,
                        "y": 180,
                    },
                    "replay_artifact": {
                        "request_headers": {"Content-Type": "application/json"} if body is not None else {},
                        "request_body_base64": "eyJ0ZXN0Ijp0cnVlfQ==" if body is not None else None,
                        "request_content_type": "application/json" if body is not None else None,
                        "response_status_code": 200,
                        "response_headers": {},
                        "response_body_excerpt": "ok",
                    },
                },
            },
        )
        assert response.status_code == 202

    post_proxy_event(
        request_id="req-1",
        fingerprint="fp-projects",
        method="GET",
        path="/v1/projects",
        node_id="projects-list",
        label="GET /v1/projects",
    )
    post_proxy_event(
        request_id="req-2",
        fingerprint="fp-members",
        method="POST",
        path="/v1/projects/123/members",
        node_id="members-update",
        label="POST /v1/projects/{projectId}/members",
        body='{"test":true}',
    )
    post_proxy_event(
        request_id="req-3",
        fingerprint="fp-delete",
        method="DELETE",
        path="/v1/projects/123",
        node_id="delete-project",
        label="DELETE /v1/projects/{projectId}",
    )

    planner_response = client.post(
        f"/api/v1/scans/{scan_id}/planner/run",
        headers={"X-Auditor-Admin-Token": "test-admin-token"},
    )
    assert planner_response.status_code == 200
    return scan_id


def test_build_runtime_service_returns_none_when_disabled() -> None:
    settings = replace(
        get_settings(),
        verifier_autorun_mode="disabled",
        verifier_autorun_worker_id="worker",
        verifier_autorun_poll_interval=1.0,
    )
    assert build_runtime_service(settings=settings) is None


def test_build_runtime_service_supports_http_replay_mode() -> None:
    settings = replace(
        get_settings(),
        verifier_autorun_mode="http-replay",
        verifier_autorun_worker_id="worker",
        verifier_autorun_poll_interval=1.0,
        verifier_replay_base_url="https://qa.example.internal",
        verifier_replay_actor_headers={"partner-member": {"Authorization": "Bearer token"}},
    )

    service = build_runtime_service(settings=settings)
    assert service is not None


def test_runtime_service_can_process_seeded_queued_job(client) -> None:
    service = VerifierRuntimeService(
        executor=DeterministicDevVerifierExecutor(),
        worker_id="runtime-worker-test",
        poll_interval_seconds=0.01,
    )

    assert service.run_once() is True

    jobs_response = client.get("/api/v1/scans/partner-boundary-scan/verifier-jobs")
    assert jobs_response.status_code == 200
    jobs = jobs_response.json()
    seeded_job = next(job for job in jobs if job["id"] == "job-partner-member-keys")
    assert seeded_job["status"] == "succeeded"
    assert seeded_job["verifier_run_id"] == "verify-job-partner-member-keys"

    finding_response = client.get("/api/v1/findings/finding-job-partner-member-keys")
    assert finding_response.status_code == 200
    finding = finding_response.json()
    assert finding["status"] == "confirmed"
    assert finding["severity"] == "high"

    verifier_run_response = client.get("/api/v1/verifier-runs/verify-job-partner-member-keys")
    assert verifier_run_response.status_code == 200
    verifier_run = verifier_run_response.json()
    assert verifier_run["status"] == "confirmed"

    events_response = client.get("/api/v1/scans/partner-boundary-scan/events")
    assert events_response.status_code == 200
    event_types = {event["event_type"] for event in events_response.json()}
    assert "verifier_runtime.completed" in event_types


def test_runtime_service_returns_false_when_no_job_is_available(client) -> None:
    service = VerifierRuntimeService(
        executor=DeterministicDevVerifierExecutor(),
        worker_id="runtime-worker-empty",
        poll_interval_seconds=0.01,
    )

    first_job = verifier_job_service.claim_verifier_job(ClaimVerifierJobRequest(scan_id="partner-boundary-scan", worker_id="manual"))
    assert first_job is not None
    verifier_job_service.complete_verifier_job(first_job.id, CompleteVerifierJobRequest(note="manual completion"))

    assert service.run_once() is False


def test_http_replay_executor_confirms_job_with_replay_plan(client) -> None:
    scan_id = _create_scan_with_planned_job(client)
    jobs = verifier_job_service.list_verifier_jobs(scan_id)
    job = verifier_job_service.get_verifier_job(jobs[0].id)
    assert job is not None

    seen_requests: list[tuple[str, bytes | None]] = []

    def transport(request_spec, *, base_url, timeout_seconds, verify_tls, headers, body):
        assert base_url == "https://qa.example.internal"
        assert timeout_seconds == 4.0
        assert verify_tls is True
        assert headers["Authorization"] == "Bearer partner-token"
        seen_requests.append((request_spec.method.upper(), body))
        status_code = 200
        return ReplayHttpResult(
            request=request_spec,
            url=f"{base_url}{request_spec.path}",
            status_code=status_code,
            body_excerpt="ok",
            response_headers={},
        )

    executor = HttpReplayVerifierExecutor(
        base_url="https://qa.example.internal",
        actor_headers={"partner-member": {"Authorization": "Bearer partner-token"}},
        timeout_seconds=4.0,
        verify_tls=True,
        transport=transport,
    )

    outcome = executor.execute(job)
    assert outcome.confirmed is True
    assert outcome.replay_result is not None
    assert outcome.replay_result.response_status_code == 200
    assert outcome.replay_result.request_fingerprint in {"fp-delete", "fp-members", "fp-projects"}
    assert any(method == "POST" and body is not None for method, body in seen_requests)


def test_http_replay_executor_returns_unconfirmed_when_target_denies_access(client) -> None:
    scan_id = _create_scan_with_planned_job(client)
    jobs = verifier_job_service.list_verifier_jobs(scan_id)
    job = verifier_job_service.get_verifier_job(jobs[0].id)
    assert job is not None

    def transport(request_spec, *, base_url, timeout_seconds, verify_tls, headers, body):
        return ReplayHttpResult(
            request=request_spec,
            url=f"https://qa.example.internal{request_spec.path}",
            status_code=403 if request_spec == job.payload.replay_plan.requests[-1] else 200,
            body_excerpt="forbidden",
            response_headers={},
        )

    executor = HttpReplayVerifierExecutor(
        base_url="https://qa.example.internal",
        actor_headers={"partner-member": {"Authorization": "Bearer partner-token"}},
        transport=transport,
    )

    outcome = executor.execute(job)
    assert outcome.confirmed is False
    assert outcome.replay_result is None
    assert "HTTP 403" in outcome.note


def test_replay_artifact_retention_purges_sensitive_material_and_blocks_replay(client) -> None:
    scan_id = _create_scan_with_planned_job(client)
    jobs = verifier_job_service.list_verifier_jobs(scan_id)
    job = verifier_job_service.get_verifier_job(jobs[0].id)
    assert job is not None
    artifact_id = job.payload.replay_plan.requests[1].artifact_id
    assert artifact_id is not None

    with session_scope() as session:
        record = ReplayArtifactRepository(session).get(artifact_id)
        assert record is not None
        record.expires_at = record.created_at - timedelta(seconds=1)

    purged_count = replay_artifact_service.purge_expired_replay_artifacts()
    assert purged_count >= 1

    artifact_response = client.get(
        f"/api/v1/replay-artifacts/{artifact_id}",
        headers={"X-Auditor-Ingest-Token": "test-ingest-token"},
    )
    assert artifact_response.status_code == 200
    artifact = artifact_response.json()
    assert artifact["replayable"] is False
    assert artifact["purged_at"] is not None
    assert artifact["request_body_preview"] is None
    assert "authorization" not in {key.lower() for key in artifact["request_headers"]}
    assert "cookie" not in {key.lower() for key in artifact["request_headers"]}

    executor = HttpReplayVerifierExecutor(
        base_url="https://qa.example.internal",
        actor_headers={"partner-member": {"Authorization": "Bearer partner-token"}},
        transport=lambda request_spec, **kwargs: ReplayHttpResult(
            request=request_spec,
            url=f"https://qa.example.internal{request_spec.path}",
            status_code=200,
            body_excerpt="ok",
            response_headers={},
        ),
    )
    outcome = executor.execute(job)
    assert outcome.confirmed is False
    assert outcome.replay_result is None
    assert "expired under retention policy" in outcome.note


def test_http_replay_executor_applies_path_body_and_header_mutations(client) -> None:
    scan_id = _create_scan_with_planned_job(client)
    jobs = verifier_job_service.list_verifier_jobs(scan_id)
    job = verifier_job_service.get_verifier_job(jobs[0].id)
    assert job is not None

    job.payload.replay_plan.mutations = [
        ReplayMutationSpec(
            type="path_replace",
            target_request_fingerprint="fp-delete",
            from_value="123",
            to_value="999999",
        ),
        ReplayMutationSpec(
            type="body_json_set",
            target_request_fingerprint="fp-members",
            body_field="role",
            value="admin",
        ),
        ReplayMutationSpec(
            type="header_set",
            target_request_fingerprint="fp-delete",
            header_name="X-Role",
            value="admin",
        ),
        ReplayMutationSpec(
            type="actor_switch",
            target_request_fingerprint="fp-delete",
            actor="admin-member",
        ),
    ]

    captured = []

    def transport(request_spec, *, base_url, timeout_seconds, verify_tls, headers, body):
        captured.append((request_spec.path, dict(headers), body))
        return ReplayHttpResult(
            request=request_spec,
            url=f"https://qa.example.internal{request_spec.path}",
            status_code=200,
            body_excerpt="ok",
            response_headers={},
        )

    executor = HttpReplayVerifierExecutor(
        base_url="https://qa.example.internal",
        actor_headers={
            "partner-member": {"Authorization": "Bearer partner-token"},
            "admin-member": {"Authorization": "Bearer admin-token"},
        },
        transport=transport,
    )

    outcome = executor.execute(job)
    assert outcome.confirmed is True
    assert any(path.endswith("/999999") for path, _, _ in captured)
    assert any(headers.get("X-Role") == "admin" for _, headers, _ in captured)
    assert any(headers.get("Authorization") == "Bearer admin-token" for path, headers, _ in captured if path.endswith("/999999"))
    assert any(body and b'"role": "admin"' in body for _, _, body in captured)


def test_http_replay_executor_refreshes_session_and_retries(client) -> None:
    scan_id = _create_scan_with_planned_job(client)
    jobs = verifier_job_service.list_verifier_jobs(scan_id)
    job = verifier_job_service.get_verifier_job(jobs[0].id)
    assert job is not None

    job.payload.replay_plan.refresh_requests = [
        ReplayRefreshRequestSpec(
            method="POST",
            host="qa.example.internal",
            path="/auth/refresh",
            actor="partner-member",
            headers={"X-Refresh": "true"},
        )
    ]

    seen = {"delete_attempts": 0, "refresh_attempts": 0}

    def transport(request_spec, *, base_url, timeout_seconds, verify_tls, headers, body):
        if request_spec.path == "/auth/refresh":
            seen["refresh_attempts"] += 1
            return ReplayHttpResult(
                request=request_spec,
                url=f"https://qa.example.internal{request_spec.path}",
                status_code=200,
                body_excerpt="refreshed",
                response_headers={"Set-Cookie": "session=newsession; Path=/; HttpOnly"},
            )

        if request_spec.path == "/v1/projects/123":
            seen["delete_attempts"] += 1
            status_code = 401 if seen["delete_attempts"] == 1 else 200
            return ReplayHttpResult(
                request=request_spec,
                url=f"https://qa.example.internal{request_spec.path}",
                status_code=status_code,
                body_excerpt="ok" if status_code == 200 else "unauthorized",
                response_headers={},
            )

        return ReplayHttpResult(
            request=request_spec,
            url=f"https://qa.example.internal{request_spec.path}",
            status_code=200,
            body_excerpt="ok",
            response_headers={},
        )

    executor = HttpReplayVerifierExecutor(
        base_url="https://qa.example.internal",
        actor_headers={"partner-member": {"Authorization": "Bearer partner-token"}},
        transport=transport,
    )

    outcome = executor.execute(job)
    assert outcome.confirmed is True
    assert seen["delete_attempts"] == 2
    assert seen["refresh_attempts"] == 1
