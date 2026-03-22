from __future__ import annotations

from api.services import ai_auth_service as ai_auth_module


def test_provider_catalog_exposes_auth_methods(client):
    response = client.get("/api/v1/ai/providers/catalog")

    assert response.status_code == 200
    payload = response.json()
    provider_map = {provider["key"]: provider for provider in payload["providers"]}
    assert {method["method"] for method in provider_map["openai"]["auth_methods"]} == {"api_key", "oauth_browser"}
    assert {method["method"] for method in provider_map["google"]["auth_methods"]} == {"api_key", "cloud_credentials"}


def test_create_provider_config_and_api_key_auth_flow(client):
    create_response = client.post(
        "/api/v1/ai/providers/configs",
        headers={"X-Auditor-Admin-Token": "test-admin-token"},
        json={
            "provider_key": "openai",
            "display_name": "OpenAI Primary",
            "default_model": "gpt-4.1",
            "enabled": True,
            "is_default": True,
        },
    )
    assert create_response.status_code == 201
    config = create_response.json()
    assert config["provider_key"] == "openai"
    config_id = config["id"]

    auth_response = client.post(
        f"/api/v1/ai/providers/configs/{config_id}/auth",
        headers={"Authorization": "Bearer test-admin-token"},
        json={
            "auth_method": "api_key",
            "secret": {
                "api_key": "sk-test-openai-12345678",
                "model": "gpt-4.1",
                "base_url": "https://api.openai.com/v1",
            },
        },
    )
    assert auth_response.status_code == 200
    auth_config = auth_response.json()
    assert auth_config["auth_method"] == "api_key"
    assert auth_config["redacted_summary"]["last4"] == "5678"

    validate_response = client.post(
        f"/api/v1/ai/providers/configs/{config_id}/validate",
        headers={"X-Auditor-Admin-Token": "test-admin-token"},
    )
    assert validate_response.status_code == 200
    validation = validate_response.json()
    assert validation["status"] == "valid"

    activate_response = client.post(
        f"/api/v1/ai/providers/configs/{config_id}/activate",
        headers={"X-Auditor-Admin-Token": "test-admin-token"},
    )
    assert activate_response.status_code == 200
    assert activate_response.json()["is_default"] is True

    list_response = client.get(
        "/api/v1/ai/providers/configs",
        headers={"X-Auditor-Admin-Token": "test-admin-token"},
    )
    assert list_response.status_code == 200
    assert any(item["id"] == config_id for item in list_response.json())


def test_google_cloud_credentials_and_openai_oauth_flow(client, monkeypatch):
    create_response = client.post(
        "/api/v1/ai/providers/configs",
        headers={"X-Auditor-Admin-Token": "test-admin-token"},
        json={
            "provider_key": "google",
            "display_name": "Google Cloud",
            "default_model": "gemini-2.5-pro",
        },
    )
    assert create_response.status_code == 201
    config_id = create_response.json()["id"]

    cloud_auth_response = client.post(
        f"/api/v1/ai/providers/configs/{config_id}/auth",
        headers={"X-Auditor-Admin-Token": "test-admin-token"},
        json={
            "auth_method": "cloud_credentials",
            "secret": {
                "project_id": "demo-project",
                "client_email": "svc@example.iam.gserviceaccount.com",
                "access_token": "ya29.test-token",
                "model": "gemini-2.5-pro",
            },
        },
    )
    assert cloud_auth_response.status_code == 200
    cloud_config = cloud_auth_response.json()
    assert cloud_config["redacted_summary"]["project_id"] == "demo-project"

    validate_response = client.post(
        f"/api/v1/ai/providers/configs/{config_id}/validate",
        headers={"X-Auditor-Admin-Token": "test-admin-token"},
    )
    assert validate_response.status_code == 200
    assert validate_response.json()["status"] == "valid"

    openai_create = client.post(
        "/api/v1/ai/providers/configs",
        headers={"X-Auditor-Admin-Token": "test-admin-token"},
        json={"provider_key": "openai", "display_name": "OpenAI Browser Auth"},
    )
    assert openai_create.status_code == 201
    openai_config_id = openai_create.json()["id"]

    authorize_response = client.post(
        f"/api/v1/ai/providers/openai/oauth/authorize?config_id={openai_config_id}",
        headers={"X-Auditor-Admin-Token": "test-admin-token"},
    )
    assert authorize_response.status_code == 200
    authorization = authorize_response.json()
    assert authorization["state"]
    assert authorization["authorization_url"].startswith("https://auth.openai.com/oauth/authorize")

    def fake_exchange(*, code: str, verifier: str, redirect_uri: str):
        assert code == "test-oauth-code"
        assert verifier
        assert redirect_uri.endswith("/openai/oauth/callback")
        return {
            "access_token": "access.jwt.token",
            "refresh_token": "refresh-token",
            "expires_at": 32503680000,
            "account_id": "acct_demo123",
        }

    monkeypatch.setattr(ai_auth_module, "exchange_openai_authorization_code", fake_exchange)

    callback_response = client.get(
        f"/api/v1/ai/providers/openai/oauth/callback?state={authorization['state']}&code=test-oauth-code&account_label=Plus Account"
    )
    assert callback_response.status_code == 200
    callback_config = callback_response.json()
    assert callback_config["auth_method"] == "oauth_browser"
    assert callback_config["redacted_summary"]["account_label"] == "Plus Account"

    validate_response = client.post(
        f"/api/v1/ai/providers/configs/{openai_config_id}/validate",
        headers={"X-Auditor-Admin-Token": "test-admin-token"},
    )
    assert validate_response.status_code == 200
    assert validate_response.json()["status"] == "valid"
