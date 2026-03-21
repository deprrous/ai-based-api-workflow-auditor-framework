from __future__ import annotations

import json

from api.schemas.ai import AiHypothesisSelectionRequest, AiNextActionRequest, AiPlanningCandidate
from api.services.ai_provider_service import ai_provider_service
from orchestrator.providers.openai_compatible_planner import OpenAiCompatiblePlanningProvider


def test_openai_compatible_planner_parses_structured_response() -> None:
    def transport(*, base_url, api_key, model, verify_tls, payload):
        assert base_url == "https://llm.example.com/v1"
        assert api_key == "secret"
        assert model == "planner-model"
        assert verify_tls is True
        assert payload["model"] == "planner-model"
        return {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "proposals": [
                                    {
                                        "path_id": "planned-path-1",
                                        "include_in_plan": True,
                                        "priority_score": 88,
                                        "recommended_severity": "critical",
                                        "suggested_rationale": "Model ranked the destructive path highly.",
                                        "explanation": "The sequence leads from membership changes into a destructive endpoint.",
                                        "tags": ["ai", "destructive-action"],
                                    }
                                ]
                            }
                        )
                    }
                }
            ]
        }

    provider = OpenAiCompatiblePlanningProvider(
        base_url="https://llm.example.com/v1",
        api_key="secret",
        model="planner-model",
        transport=transport,
    )

    proposals = provider.plan(
        [
            AiPlanningCandidate(
                path_id="planned-path-1",
                title="Delete path",
                severity="critical",
                vulnerability_class="bfla",
                confidence=91,
                matched_rule="bfla",
                verifier_strategy="privilege_transition_replay",
                rationale="Destructive path after role change.",
                step_count=3,
                matched_signals=["privilege-transition", "DELETE"],
                workflow_node_ids=["a", "b", "c"],
            )
        ],
        min_priority_score=50,
    )

    assert len(proposals) == 1
    assert proposals[0].priority_score == 88
    assert proposals[0].recommended_severity == "critical"


def test_mock_provider_can_decide_next_action() -> None:
    provider_key, decision = ai_provider_service.decide_next_action(
        AiNextActionRequest(
            scan_id="scan-1",
            use_ai_planner=True,
            max_planning_passes=2,
            max_ai_planning_passes=1,
            max_verifier_cycles=5,
            memory={
                "proxy_event_count": 5,
                "finding_count": 0,
                "pending_verifier_jobs": 0,
                "deterministic_planning_runs": 0,
                "ai_planning_runs": 0,
                "last_deterministic_event_count": 0,
                "last_deterministic_candidate_count": 0,
                "last_ai_candidate_count": 0,
                "completed_verifier_cycles": 0,
                "candidate_backlog": [],
                "unresolved_hypotheses": [],
                "verifier_outcomes": [],
            },
        ),
        provider_key="mock",
    )

    assert provider_key == "mock"
    assert decision.next_action == "deterministic_planner"
    assert decision.confidence >= 0


def test_mock_provider_can_select_hypothesis() -> None:
    provider_key, decision = ai_provider_service.select_hypothesis(
        AiHypothesisSelectionRequest(
            scan_id="scan-1",
            hypotheses=[
                {
                    "hypothesis_id": "hyp-1",
                    "source_path_id": "path-1",
                    "title": "Tenant billing read path",
                    "vulnerability_class": "tenant_isolation",
                    "severity": "high",
                    "confidence": 84,
                    "matched_rule": "tenant_isolation",
                    "verifier_strategy": "tenant_boundary_replay",
                    "status": "new",
                    "available_payload_variant_ids": ["tenant-boundary-1", "tenant-boundary-2"],
                    "matched_signals": ["tenant-boundary-resource"],
                },
                {
                    "hypothesis_id": "hyp-2",
                    "source_path_id": "path-2",
                    "title": "Destructive delete path",
                    "vulnerability_class": "unsafe_destructive_action",
                    "severity": "critical",
                    "confidence": 91,
                    "matched_rule": "unsafe_destructive_action",
                    "verifier_strategy": "destructive_action_replay",
                    "status": "new",
                    "available_payload_variant_ids": ["destructive-confirmation-bypass"],
                    "matched_signals": ["destructive-action"],
                },
            ],
        ),
        provider_key="mock",
    )

    assert provider_key == "mock"
    assert decision.selected_hypothesis_id == "hyp-2"
    assert decision.selected_payload_variant_id == "destructive-confirmation-bypass"
