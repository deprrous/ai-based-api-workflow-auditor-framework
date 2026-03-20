from __future__ import annotations

from api.schemas.ai import AiCapability, AiProviderCatalog, AiProviderKind
from orchestrator.providers.base import build_descriptor
from orchestrator.providers.openai_compatible import OpenAiCompatibleProvider


def get_provider_catalog() -> AiProviderCatalog:
    providers = [
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
