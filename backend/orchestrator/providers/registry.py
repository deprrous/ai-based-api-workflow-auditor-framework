from __future__ import annotations

from api.app.config import Settings
from api.schemas.ai import AiAuthMethod, AiCapability, AiProviderCatalog, AiProviderKind
from orchestrator.providers.base import AiPlanningProvider, auth_descriptor, build_descriptor
from orchestrator.providers.anthropic_planner import AnthropicPlanningProvider
from orchestrator.providers.google_planner import GooglePlanningProvider
from orchestrator.providers.mock_planner import MockPlanningProvider
from orchestrator.providers.openai_codex_oauth_planner import OpenAiCodexOAuthPlanningProvider
from orchestrator.providers.openai_compatible import OpenAiCompatibleProvider
from orchestrator.providers.openai_compatible_planner import OpenAiCompatiblePlanningProvider
from orchestrator.providers.openai_planner import OpenAiPlanningProvider


def get_provider_catalog() -> AiProviderCatalog:
    providers = [
        MockPlanningProvider().descriptor,
        build_descriptor(
            key="openai",
            kind=AiProviderKind.OPENAI,
            display_name="OpenAI",
            description="Native OpenAI provider integration planned through the provider-neutral orchestration layer.",
            capabilities=[AiCapability.CHAT, AiCapability.TOOL_CALLING, AiCapability.JSON_OUTPUT, AiCapability.EMBEDDINGS],
            config_fields=["api_key", "model"],
            auth_methods=[
                auth_descriptor(
                    method=AiAuthMethod.API_KEY,
                    label="API Key",
                    description="Use an OpenAI platform API key.",
                    required_fields=["api_key"],
                ),
                auth_descriptor(
                    method=AiAuthMethod.OAUTH_BROWSER,
                    label="Browser Auth",
                    description="OAuth/browser auth scaffold for account-based provider login.",
                    required_fields=["account_label"],
                ),
            ],
        ),
        build_descriptor(
            key="anthropic",
            kind=AiProviderKind.ANTHROPIC,
            display_name="Anthropic",
            description="Native Anthropic provider integration planned through the provider-neutral orchestration layer.",
            capabilities=[AiCapability.CHAT, AiCapability.TOOL_CALLING, AiCapability.JSON_OUTPUT],
            config_fields=["api_key", "model"],
            auth_methods=[
                auth_descriptor(
                    method=AiAuthMethod.API_KEY,
                    label="API Key",
                    description="Use an Anthropic API key.",
                    required_fields=["api_key"],
                )
            ],
        ),
        OpenAiCompatibleProvider(
            key="openai-compatible",
            display_name="OpenAI-Compatible",
            description="Use OpenAI-compatible local or hosted gateways such as vLLM, Ollama, LiteLLM, or custom proxy layers.",
        ).descriptor,
        build_descriptor(
            key="google",
            kind=AiProviderKind.GOOGLE,
            display_name="Google / Gemini",
            description="Google Gemini style provider with API-key or cloud-credential support.",
            capabilities=[AiCapability.CHAT, AiCapability.JSON_OUTPUT],
            config_fields=["api_key", "project_id", "location", "model"],
            auth_methods=[
                auth_descriptor(
                    method=AiAuthMethod.API_KEY,
                    label="API Key",
                    description="Use a Google Gemini API key.",
                    required_fields=["api_key"],
                ),
                auth_descriptor(
                    method=AiAuthMethod.CLOUD_CREDENTIALS,
                    label="Cloud Credentials",
                    description="Use Google cloud credentials such as service account JSON or application default credentials metadata.",
                    required_fields=["project_id"],
                ),
            ],
        ),
        build_descriptor(
            key="local-model",
            kind=AiProviderKind.LOCAL,
            display_name="Local Model Runtime",
            description="Local provider slot for self-hosted model runtimes and offline deployments.",
            capabilities=[AiCapability.CHAT, AiCapability.JSON_OUTPUT],
            config_fields=["base_url", "model"],
            auth_methods=[
                auth_descriptor(
                    method=AiAuthMethod.NONE,
                    label="No Auth",
                    description="No credential required for local runtimes.",
                    required_fields=[],
                )
            ],
        ),
    ]
    return AiProviderCatalog(version="v1", providers=providers)
def build_planning_provider(*, settings: Settings, provider_key: str | None = None, runtime_auth: dict[str, object] | None = None) -> AiPlanningProvider:
    selected = (provider_key or settings.ai_default_provider).strip().lower()
    secret = runtime_auth.get("secret", {}) if runtime_auth else {}
    auth_record = runtime_auth.get("auth_record") if runtime_auth else None
    auth_method = getattr(auth_record, "auth_method", None)
    if selected == "mock":
        return MockPlanningProvider()
    if selected == "openai-compatible":
        return OpenAiCompatiblePlanningProvider(
            base_url=str(secret.get("base_url") or settings.ai_openai_compatible_base_url or ""),
            api_key=str(secret.get("api_key") or settings.ai_openai_compatible_api_key or ""),
            model=str(secret.get("model") or settings.ai_openai_compatible_model or ""),
            verify_tls=bool(secret.get("verify_tls", settings.ai_openai_compatible_verify_tls)),
        )
    if selected == "openai":
        if auth_method == AiAuthMethod.OAUTH_BROWSER.value:
            return OpenAiCodexOAuthPlanningProvider(
                access_token=str(secret.get("access_token") or ""),
                refresh_token=str(secret.get("refresh_token") or ""),
                account_id=str(secret.get("account_id") or ""),
                model=str(secret.get("model") or "gpt-5.1"),
            )
        return OpenAiPlanningProvider(
            base_url=str(secret.get("base_url") or "https://api.openai.com/v1"),
            api_key=str(secret.get("api_key") or ""),
            model=str(secret.get("model") or ""),
            verify_tls=bool(secret.get("verify_tls", True)),
        )
    if selected == "anthropic":
        return AnthropicPlanningProvider(
            api_key=str(secret.get("api_key") or ""),
            model=str(secret.get("model") or ""),
        )
    if selected == "google":
        return GooglePlanningProvider(
            model=str(secret.get("model") or ""),
            api_key=str(secret.get("api_key") or "") or None,
            access_token=str(secret.get("access_token") or "") or None,
        )

    raise ValueError(f"Unsupported AI planning provider: {selected}")
