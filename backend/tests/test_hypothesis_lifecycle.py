from __future__ import annotations

from api.schemas.planner import PlannerCandidateSummary, VerifierStrategy, VulnerabilityClass
from api.services.hypothesis_service import hypothesis_service


def _candidate(path_id: str, *, confidence: int, severity: str = "high") -> PlannerCandidateSummary:
    return PlannerCandidateSummary(
        path_id=path_id,
        title="Partner member reaches privileged endpoint after transition",
        severity=severity,
        vulnerability_class=VulnerabilityClass.BFLA,
        confidence=confidence,
        matched_rule="bfla",
        verifier_strategy=VerifierStrategy.PRIVILEGE_TRANSITION_REPLAY,
        match_explanation="Detected a privilege transition followed by a destructive endpoint.",
        matched_signals=["privilege-transition", "DELETE"],
        step_count=3,
        workflow_node_ids=["evt-1", "evt-2", "evt-3"],
    )


def test_hypothesis_merge_downgrade_reopen_and_abandon(client):
    create_response = client.post(
        "/api/v1/scans",
        json={"name": "Hypothesis Lifecycle Scan", "target": "qa", "notes": "hypothesis-lifecycle"},
    )
    assert create_response.status_code == 202
    scan_id = create_response.json()["run"]["id"]

    synced = hypothesis_service.sync_hypotheses(
        scan_id=scan_id,
        session_id=None,
        planning_run_id=None,
        candidates=[_candidate("path-a", confidence=95), _candidate("path-b", confidence=90)],
        decision_source="test",
    )
    assert synced

    hypotheses = hypothesis_service.list_hypotheses(scan_id)
    assert len(hypotheses) == 2
    merged = [item for item in hypotheses if item.status.value == "merged"]
    active = [item for item in hypotheses if item.status.value != "merged"]
    assert len(merged) == 1
    assert len(active) == 1
    active_id = active[0].id
    active_path_id = active[0].source_path_id

    downgraded = hypothesis_service.sync_hypotheses(
        scan_id=scan_id,
        session_id=None,
        planning_run_id=None,
        candidates=[_candidate(active_path_id, confidence=60, severity="review")],
        decision_source="test",
    )
    assert downgraded[0].status.value == "downgraded"

    # First stale pass keeps it downgraded, second stale pass abandons it.
    hypothesis_service.sync_hypotheses(
        scan_id=scan_id,
        session_id=None,
        planning_run_id=None,
        candidates=[],
        decision_source="test",
    )
    abandoned = hypothesis_service.sync_hypotheses(
        scan_id=scan_id,
        session_id=None,
        planning_run_id=None,
        candidates=[],
        decision_source="test",
    )
    assert abandoned == []
    abandoned_detail = hypothesis_service.get_hypothesis(active_id)
    assert abandoned_detail is not None
    assert abandoned_detail.status.value == "abandoned"

    reopened = hypothesis_service.sync_hypotheses(
        scan_id=scan_id,
        session_id=None,
        planning_run_id=None,
        candidates=[_candidate(active_path_id, confidence=92, severity="critical")],
        decision_source="test",
    )
    assert reopened[0].status.value == "new"
    reopened_detail = hypothesis_service.get_hypothesis(active_id)
    assert reopened_detail is not None
    assert reopened_detail.reopen_count >= 1
