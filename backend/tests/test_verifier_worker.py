from __future__ import annotations

from pydantic import ValidationError

from api.schemas.findings import FindingEvidence
from tools.analyzer.correlation import CorrelationCandidate
from tools.verifier.worker import VerifierPublishOptions, VerifierReplayResult, VerifierWorker, build_ingest_request, build_verifier_contract


def _sample_result() -> VerifierReplayResult:
    return VerifierReplayResult(
        verifier_run_id="verify-001",
        scan_id="partner-boundary-scan",
        finding_id="finding-partner-boundary-scan-delete-worker",
        title="Partner member can delete shared projects",
        category="bfla",
        severity="critical",
        confidence=96,
        endpoint="DELETE /v1/projects/{projectId}",
        actor="invited partner member",
        request_fingerprint="delete-project-fingerprint",
        request_summary="DELETE /v1/projects/123 returned 204 during verifier replay.",
        response_status_code=204,
        message="Verifier confirmed destructive delete escalation.",
        impact_summary="Invited external members can delete shared projects.",
        remediation_summary="Restrict destructive endpoints to explicit project-owner roles.",
        description="The verifier replayed the destructive path as an invited partner member and received HTTP 204.",
        impact="External collaborators can destroy shared projects and disrupt customers.",
        remediation="Enforce destructive-role checks before project deletion and add role regression tests.",
        workflow_node_ids=["delete-project", "verifier"],
        evidence=[
            FindingEvidence(
                label="Verifier delete replay",
                detail="Replay succeeded with HTTP 204 while using invited partner credentials.",
                source="verifier",
            )
        ],
        tags=["bfla", "destructive-action"],
        source_candidates=[
            CorrelationCandidate(
                label="delete_project authorization guard",
                location="services/project_access.py:88",
                excerpt="if user.role not in {\"owner\", \"admin\"}: raise PermissionDenied",
                hint="delete project permission enforcement",
            )
        ],
        spec_candidates=[
            CorrelationCandidate(
                label="Project deletion operation",
                location="openapi.yaml#/paths/~1v1~1projects~1{projectId}/delete",
                excerpt="responses:\n  '204':\n    description: Project deleted",
                hint="delete operation contract",
            )
        ],
    )


def test_verifier_replay_result_requires_evidence_and_workflow_nodes() -> None:
    try:
        VerifierReplayResult(
            verifier_run_id="verify-bad",
            scan_id="partner-boundary-scan",
            title="Invalid result",
            category="bfla",
            severity="critical",
            confidence=90,
            message="Bad result",
            impact_summary="bad",
            remediation_summary="bad",
            description="bad",
            impact="bad",
            remediation="bad",
            workflow_node_ids=[],
            evidence=[],
        )
    except ValidationError:
        pass
    else:  # pragma: no cover
        raise AssertionError("Verifier replay result should require evidence and workflow nodes.")


def test_build_ingest_request_creates_verifier_contract() -> None:
    result = _sample_result()

    contract = build_verifier_contract(result)
    request = build_ingest_request(result)

    assert contract.kind == "verifier.finding_confirmed"
    assert contract.finding.status == "confirmed"
    assert contract.finding.context_references
    assert len(contract.edges) == 2
    assert request.event_type == "verifier.finding_confirmed"
    assert request.source == "verifier"
    assert request.producer_contract is not None


def test_verifier_worker_can_publish_result_into_backend_contract_ingest(client) -> None:
    options = VerifierPublishOptions(
        backend_url="http://testserver/api/v1",
        ingest_token="test-ingest-token",
    )

    def sender(_: VerifierPublishOptions, scan_id: str, payload: dict[str, object]) -> int:
        response = client.post(
            f"/api/v1/scans/{scan_id}/events",
            headers={"X-Auditor-Ingest-Token": "test-ingest-token"},
            json=payload,
        )
        return response.status_code

    worker = VerifierWorker(options=options, sender=sender)

    assert worker.publish_verified_finding(_sample_result()) is True

    finding_response = client.get("/api/v1/findings/finding-partner-boundary-scan-delete-worker")
    assert finding_response.status_code == 200
    finding = finding_response.json()
    assert finding["severity"] == "critical"
    assert finding["status"] == "confirmed"
    assert finding["context_reference_count"] == 2

    verifier_runs_response = client.get("/api/v1/scans/partner-boundary-scan/verifier-runs")
    assert verifier_runs_response.status_code == 200
    verifier_runs = verifier_runs_response.json()
    assert any(run["id"] == "verify-001" for run in verifier_runs)

    verifier_run_detail_response = client.get("/api/v1/verifier-runs/verify-001")
    assert verifier_run_detail_response.status_code == 200
    verifier_run_detail = verifier_run_detail_response.json()
    assert verifier_run_detail["request_fingerprint"] == "delete-project-fingerprint"
    assert verifier_run_detail["response_status_code"] == 204
    assert len(verifier_run_detail["context_references"]) == 2


def test_verifier_worker_can_claim_and_complete_jobs(client) -> None:
    options = VerifierPublishOptions(
        backend_url="http://testserver/api/v1",
        ingest_token="test-ingest-token",
    )

    def claim_sender(_: VerifierPublishOptions, payload: dict[str, object]) -> dict[str, object] | None:
        response = client.post(
            "/api/v1/verifier-jobs/claim",
            headers={"X-Auditor-Ingest-Token": "test-ingest-token"},
            json=payload,
        )
        return response.json() if response.status_code == 200 else None

    def job_sender(_: VerifierPublishOptions, job_id: str, action: str, payload: dict[str, object]) -> int:
        response = client.post(
            f"/api/v1/verifier-jobs/{job_id}/{action}",
            headers={"X-Auditor-Ingest-Token": "test-ingest-token"},
            json=payload,
        )
        return response.status_code

    worker = VerifierWorker(options=options, claim_sender=claim_sender, job_sender=job_sender)

    claimed_job = worker.claim_job(scan_id="partner-boundary-scan", worker_id="worker-claim-test")
    assert claimed_job is not None
    assert claimed_job.status.value == "running"

    assert worker.complete_job(claimed_job.id, verifier_run_id="verify-queue-complete", finding_id="finding-queue-complete") is True
