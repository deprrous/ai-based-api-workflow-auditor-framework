from __future__ import annotations

from dataclasses import dataclass

from api.schemas.ai import AiAuthMethod, AiCapability, AiProviderKind
from orchestrator.providers.base import auth_descriptor, build_descriptor


@dataclass(frozen=True, slots=True)
class OpenAiCompatibleProvider:
    key: str
    display_name: str
    description: str

    @property
    def descriptor(self):
        return build_descriptor(
            key=self.key,
            kind=AiProviderKind.OPENAI_COMPATIBLE,
            display_name=self.display_name,
            description=self.description,
            capabilities=[AiCapability.CHAT, AiCapability.TOOL_CALLING, AiCapability.JSON_OUTPUT],
            config_fields=["base_url", "api_key", "model"],
            auth_methods=[
                auth_descriptor(
                    method=AiAuthMethod.API_KEY,
                    label="API Key",
                    description="Use an API key against an OpenAI-compatible endpoint.",
                    required_fields=["api_key", "base_url"],
                )
            ],
        )

    def validate(self) -> None:
        return None
