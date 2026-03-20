from __future__ import annotations

import json

from api.schemas.ai import AiPlanningCandidate
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
