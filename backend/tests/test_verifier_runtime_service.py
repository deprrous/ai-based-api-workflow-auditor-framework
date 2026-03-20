from __future__ import annotations

from dataclasses import replace

from api.app.config import get_settings
from api.schemas.verifier_jobs import ClaimVerifierJobRequest, CompleteVerifierJobRequest
from api.services.verifier_job_service import verifier_job_service
from api.services.verifier_runtime_service import (
    DeterministicDevVerifierExecutor,
    HttpReplayVerifierExecutor,
    ReplayHttpResult,
    VerifierRuntimeService,
    build_runtime_service,
)


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
    job = verifier_job_service.get_verifier_job("job-partner-member-keys")
    assert job is not None

    def transport(request_spec, *, base_url, timeout_seconds, verify_tls, headers):
        assert base_url == "https://qa.example.internal"
        assert timeout_seconds == 4.0
        assert verify_tls is True
        assert headers == {"Authorization": "Bearer partner-token"}
        status_code = 200
        return ReplayHttpResult(
            request=request_spec,
            url=f"{base_url}{request_spec.path}",
            status_code=status_code,
            body_excerpt="ok",
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
    assert outcome.replay_result.request_fingerprint == "seed-keys-read"


def test_http_replay_executor_returns_unconfirmed_when_target_denies_access(client) -> None:
    job = verifier_job_service.get_verifier_job("job-partner-member-keys")
    assert job is not None

    def transport(request_spec, *, base_url, timeout_seconds, verify_tls, headers):
        return ReplayHttpResult(
            request=request_spec,
            url=f"https://qa.example.internal{request_spec.path}",
            status_code=403 if request_spec == job.payload.replay_plan.requests[-1] else 200,
            body_excerpt="forbidden",
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
