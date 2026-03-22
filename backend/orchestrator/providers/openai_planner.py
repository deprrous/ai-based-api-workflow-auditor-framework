from __future__ import annotations

from dataclasses import dataclass

from api.schemas.ai import AiAuthMethod, AiCapability, AiProviderKind
from orchestrator.providers.base import auth_descriptor, build_descriptor
from orchestrator.providers.openai_compatible_planner import OpenAiCompatiblePlanningProvider


@dataclass(frozen=True, slots=True)
class OpenAiPlanningProvider:
    api_key: str
    model: str
    base_url: str = "https://api.openai.com/v1"
    verify_tls: bool = True

    @property
    def descriptor(self):
        return build_descriptor(
            key="openai",
            kind=AiProviderKind.OPENAI,
            display_name="OpenAI",
            description="Native OpenAI planning provider.",
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
        )

    def validate(self) -> None:
        OpenAiCompatiblePlanningProvider(
            base_url=self.base_url,
            api_key=self.api_key,
            model=self.model,
            verify_tls=self.verify_tls,
        ).validate()

    def plan(self, *args, **kwargs):
        return OpenAiCompatiblePlanningProvider(
            base_url=self.base_url,
            api_key=self.api_key,
            model=self.model,
            verify_tls=self.verify_tls,
        ).plan(*args, **kwargs)

    def decide_next_action(self, *args, **kwargs):
        return OpenAiCompatiblePlanningProvider(
            base_url=self.base_url,
            api_key=self.api_key,
            model=self.model,
            verify_tls=self.verify_tls,
        ).decide_next_action(*args, **kwargs)

    def select_hypothesis(self, *args, **kwargs):
        return OpenAiCompatiblePlanningProvider(
            base_url=self.base_url,
            api_key=self.api_key,
            model=self.model,
            verify_tls=self.verify_tls,
        ).select_hypothesis(*args, **kwargs)
