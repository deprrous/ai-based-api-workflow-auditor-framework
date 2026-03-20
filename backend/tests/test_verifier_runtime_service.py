from __future__ import annotations

from api.schemas.verifier_jobs import ClaimVerifierJobRequest, CompleteVerifierJobRequest
from api.services.verifier_job_service import verifier_job_service
from api.services.verifier_runtime_service import DeterministicDevVerifierExecutor, VerifierRuntimeService, build_runtime_service


def test_build_runtime_service_returns_none_when_disabled() -> None:
    assert build_runtime_service(mode="disabled", worker_id="worker", poll_interval_seconds=1.0) is None


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
