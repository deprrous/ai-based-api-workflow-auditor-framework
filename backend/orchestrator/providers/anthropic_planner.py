from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Callable

import httpx

from api.schemas.ai import (
    AiHypothesisSelectionDecision,
    AiHypothesisSelectionRequest,
    AiCapability,
    AiNextActionDecision,
    AiNextActionRequest,
    AiPlanningCandidate,
    AiPlanningProposal,
    AiProviderKind,
)
from orchestrator.providers.base import auth_descriptor, build_descriptor
from api.schemas.ai import AiAuthMethod


def _default_transport(*, api_key: str, model: str, payload: list[dict[str, str]]) -> dict[str, Any]:
    response = httpx.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": model,
            "max_tokens": 1200,
            "messages": payload,
        },
        timeout=20.0,
    )
    response.raise_for_status()
    return response.json()


@dataclass(frozen=True, slots=True)
class AnthropicPlanningProvider:
    api_key: str
    model: str
    transport: Callable[..., dict[str, Any]] = _default_transport

    @property
    def descriptor(self):
        return build_descriptor(
            key="anthropic",
            kind=AiProviderKind.ANTHROPIC,
            display_name="Anthropic",
            description="Native Anthropic planning provider.",
            capabilities=[AiCapability.CHAT, AiCapability.JSON_OUTPUT],
            config_fields=["api_key", "model"],
            auth_methods=[
                auth_descriptor(
                    method=AiAuthMethod.API_KEY,
                    label="API Key",
                    description="Use an Anthropic API key.",
                    required_fields=["api_key"],
                )
            ],
        )

    def validate(self) -> None:
        if not self.api_key or not self.model:
            raise ValueError("Anthropic planner requires api_key and model.")

    def _invoke(self, system_instruction: str, user_payload: dict[str, object]) -> dict[str, object]:
        self.validate()
        response_payload = self.transport(
            api_key=self.api_key,
            model=self.model,
            payload=[
                {"role": "user", "content": f"{system_instruction}\n\n{json.dumps(user_payload, ensure_ascii=True)}"},
            ],
        )
        content = response_payload["content"][0]["text"]
        parsed = json.loads(content)
        return parsed if isinstance(parsed, dict) else {}

    def plan(self, candidates: list[AiPlanningCandidate], *, min_priority_score: int) -> list[AiPlanningProposal]:
        parsed = self._invoke(
            "Return JSON with a top-level 'proposals' array for ranked API security planning candidates.",
            {
                "min_priority_score": min_priority_score,
                "candidates": [candidate.model_dump(mode="json") for candidate in candidates],
            },
        )
        return [AiPlanningProposal.model_validate(item) for item in parsed.get("proposals", []) if isinstance(item, dict)]

    def decide_next_action(self, request: AiNextActionRequest) -> AiNextActionDecision:
        parsed = self._invoke(
            "Return JSON with next_action, confidence, rationale, and supporting_observations.",
            request.model_dump(mode="json"),
        )
        return AiNextActionDecision.model_validate(parsed)

    def select_hypothesis(self, request: AiHypothesisSelectionRequest) -> AiHypothesisSelectionDecision:
        parsed = self._invoke(
            "Return JSON choosing which hypothesis to verify next and which payload variant to try first.",
            request.model_dump(mode="json"),
        )
        return AiHypothesisSelectionDecision.model_validate(parsed)
