from __future__ import annotations


def test_scan_setup_bootstraps_scan_artifacts_actors_and_orchestration(client):
    response = client.post(
        "/api/v1/scans/setup",
        json={
            "scan": {
                "name": "Full Setup Scan",
                "target": "staging",
                "target_base_url": "https://staging.example.internal",
                "notes": "setup-endpoint",
            },
            "actors": [
                {
                    "actor_id": "partner-member",
                    "label": "Partner Member",
                    "description": "Low-privilege actor used during replay.",
                    "headers": {"Authorization": "Bearer partner-token"},
                },
                {
                    "actor_id": "admin-member",
                    "label": "Admin Member",
                    "description": "Higher-privilege actor for comparison.",
                    "headers": {"Authorization": "Bearer admin-token"},
                },
            ],
            "source_artifacts": [
                {
                    "name": "routes.py",
                    "path": "services/routes.py",
                    "language": "python",
                    "content": '@router.delete("/v1/projects/{projectId}")\ndef delete_project(request):\n    pass\n',
                }
            ],
            "api_spec_artifacts": [
                {
                    "name": "openapi.yaml",
                    "path": "specs/openapi.yaml",
                    "format": "openapi",
                    "content": """
openapi: 3.1.0
paths:
  /v1/projects/{projectId}:
    delete:
      summary: Delete project
""",
                }
            ],
            "start_orchestration": True,
            "orchestration": {
                "use_ai_planner": True,
                "use_ai_decision": True,
                "use_ai_hypothesis_selection": True,
                "ai_provider_key": "mock",
                "max_planning_passes": 2,
                "max_ai_planning_passes": 1,
                "max_verifier_cycles": 3,
                "ai_candidate_limit": 4,
                "ai_min_priority_score": 50,
            },
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["scan"]["target_base_url"] == "https://staging.example.internal"
    assert len(payload["actor_profiles"]) == 2
    assert payload["source_artifact_ids"]
    assert payload["api_spec_artifact_ids"]
    assert payload["orchestration_session"] is not None

    scan_id = payload["scan"]["id"]
    actor_response = client.get(f"/api/v1/scans/{scan_id}/actors")
    assert actor_response.status_code == 200
    actors = actor_response.json()
    assert {actor["actor_id"] for actor in actors} == {"partner-member", "admin-member"}

    scan_detail = client.get(f"/api/v1/scans/{scan_id}").json()
    assert scan_detail["target_base_url"] == "https://staging.example.internal"
