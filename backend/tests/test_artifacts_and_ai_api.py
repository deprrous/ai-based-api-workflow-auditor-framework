from __future__ import annotations


def test_source_and_api_spec_artifact_ingestion(client):
    create_response = client.post(
        "/api/v1/scans",
        json={"name": "Artifact Ingestion Scan", "target": "qa", "notes": "artifact-test"},
    )
    assert create_response.status_code == 202
    scan_id = create_response.json()["run"]["id"]

    source_response = client.post(
        f"/api/v1/artifacts/scan/{scan_id}/source",
        json={
            "name": "project_routes.py",
            "path": "services/project_routes.py",
            "language": "python",
            "content": '@router.delete("/v1/projects/{projectId}")\ndef delete_project():\n    pass\n',
        },
    )
    assert source_response.status_code == 201
    source_artifact = source_response.json()
    assert source_artifact["kind"] == "source_code"
    assert source_artifact["route_count"] == 1

    spec_response = client.post(
        f"/api/v1/artifacts/scan/{scan_id}/api-spec",
        json={
            "name": "openapi.yaml",
            "path": "specs/openapi.yaml",
            "format": "openapi",
            "content": """
openapi: 3.1.0
paths:
  /v1/projects/{projectId}:
    delete:
      summary: Delete project
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
""",
        },
    )
    assert spec_response.status_code == 201
    spec_artifact = spec_response.json()
    assert spec_artifact["kind"] == "api_spec"
    assert spec_artifact["auth_scheme_count"] == 1

    list_response = client.get(f"/api/v1/artifacts/scan/{scan_id}")
    assert list_response.status_code == 200
    listed = list_response.json()
    assert len(listed) == 2

    detail_response = client.get(f"/api/v1/artifacts/{spec_artifact['id']}")
    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert detail["parsed_summary"]["route_count"] == 1
    assert detail["parsed_summary"]["auth_schemes"] == ["bearerAuth"]


def test_planner_uses_artifact_context_to_enrich_rationale(client):
    create_response = client.post(
        "/api/v1/scans",
        json={"name": "Planner Artifact Scan", "target": "qa", "notes": "planner-artifact"},
    )
    assert create_response.status_code == 202
    scan_id = create_response.json()["run"]["id"]

    client.post(
        f"/api/v1/artifacts/scan/{scan_id}/api-spec",
        json={
            "name": "projects-openapi.yaml",
            "path": "specs/projects-openapi.yaml",
            "format": "openapi",
            "content": """
openapi: 3.1.0
paths:
  /v1/projects:
    get:
      summary: List projects
  /v1/projects/123/members:
    post:
      summary: Invite member
  /v1/projects/123:
    delete:
      summary: Delete project
""",
        },
    )

    def post_proxy_event(request_id: str, fingerprint: str, method: str, path: str):
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
                    "status_code": 200 if method != "DELETE" else 204,
                    "actor": "partner-member",
                    "node": {
                        "id": request_id,
                        "label": f"{method} {path}",
                        "type": "endpoint",
                        "phase": "action" if method in {"POST", "DELETE"} else "read",
                        "detail": f"Observed {method} {path}",
                        "status": "high" if method == "DELETE" else "review",
                        "x": 640,
                        "y": 180,
                    },
                },
            },
        )
        assert response.status_code == 202

    post_proxy_event("evt-1", "fp-projects", "GET", "/v1/projects")
    post_proxy_event("evt-2", "fp-members", "POST", "/v1/projects/123/members")
    post_proxy_event("evt-3", "fp-delete", "DELETE", "/v1/projects/123")

    planner_response = client.post(
        f"/api/v1/scans/{scan_id}/planner/run",
        headers={"X-Auditor-Admin-Token": "test-admin-token"},
    )
    assert planner_response.status_code == 200
    payload = planner_response.json()
    assert payload["emitted_count"] >= 1

    jobs_response = client.get(f"/api/v1/scans/{scan_id}/verifier-jobs")
    assert jobs_response.status_code == 200
    job_id = jobs_response.json()[0]["id"]

    job_detail_response = client.get(f"/api/v1/verifier-jobs/{job_id}")
    assert job_detail_response.status_code == 200
    assert "projects-openapi.yaml" in job_detail_response.json()["rationale"]


def test_ai_provider_catalog_endpoint_returns_provider_neutral_catalog(client):
    response = client.get("/api/v1/ai/providers/catalog")

    assert response.status_code == 200
    payload = response.json()
    assert payload["version"] == "v1"
    provider_keys = {provider["key"] for provider in payload["providers"]}
    assert {"openai", "anthropic", "openai-compatible", "local-model"}.issubset(provider_keys)
