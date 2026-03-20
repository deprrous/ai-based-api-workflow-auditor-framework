from __future__ import annotations

from api.app.config import Settings
from api.schemas.ai import AiCapability, AiProviderCatalog, AiProviderKind
from orchestrator.providers.base import AiPlanningProvider, build_descriptor
from orchestrator.providers.mock_planner import MockPlanningProvider
from orchestrator.providers.openai_compatible import OpenAiCompatibleProvider
from orchestrator.providers.openai_compatible_planner import OpenAiCompatiblePlanningProvider


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
        ),
        build_descriptor(
            key="anthropic",
            kind=AiProviderKind.ANTHROPIC,
            display_name="Anthropic",
            description="Native Anthropic provider integration planned through the provider-neutral orchestration layer.",
            capabilities=[AiCapability.CHAT, AiCapability.TOOL_CALLING, AiCapability.JSON_OUTPUT],
            config_fields=["api_key", "model"],
        ),
        OpenAiCompatibleProvider(
            key="openai-compatible",
            display_name="OpenAI-Compatible",
            description="Use OpenAI-compatible local or hosted gateways such as vLLM, Ollama, LiteLLM, or custom proxy layers.",
        ).descriptor,
        build_descriptor(
            key="local-model",
            kind=AiProviderKind.LOCAL,
            display_name="Local Model Runtime",
            description="Local provider slot for self-hosted model runtimes and offline deployments.",
            capabilities=[AiCapability.CHAT, AiCapability.JSON_OUTPUT],
            config_fields=["base_url", "model"],
        ),
    ]
    return AiProviderCatalog(version="v1", providers=providers)


def build_planning_provider(*, settings: Settings, provider_key: str | None = None) -> AiPlanningProvider:
    selected = (provider_key or settings.ai_default_provider).strip().lower()
    if selected == "mock":
        return MockPlanningProvider()
    if selected == "openai-compatible":
        return OpenAiCompatiblePlanningProvider(
            base_url=settings.ai_openai_compatible_base_url or "",
            api_key=settings.ai_openai_compatible_api_key or "",
            model=settings.ai_openai_compatible_model or "",
            verify_tls=settings.ai_openai_compatible_verify_tls,
        )

    raise ValueError(f"Unsupported AI planning provider: {selected}")
