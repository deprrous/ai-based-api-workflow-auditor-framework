from __future__ import annotations

from dataclasses import dataclass

from api.schemas.ai import AiCapability, AiProviderKind
from orchestrator.providers.base import build_descriptor


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
        )

    def validate(self) -> None:
        return None
