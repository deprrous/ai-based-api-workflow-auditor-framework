from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Callable

import httpx

from api.schemas.ai import (
    AiCapability,
    AiNextActionDecision,
    AiNextActionRequest,
    AiPlanningCandidate,
    AiPlanningProposal,
    AiProviderKind,
)
from orchestrator.providers.base import build_descriptor


def _default_transport(
    *,
    base_url: str,
    api_key: str,
    model: str,
    verify_tls: bool,
    payload: dict[str, Any],
) -> dict[str, Any]:
    response = httpx.post(
        f"{base_url.rstrip('/')}/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=20.0,
        verify=verify_tls,
    )
    response.raise_for_status()
    return response.json()


@dataclass(frozen=True, slots=True)
class OpenAiCompatiblePlanningProvider:
    base_url: str
    api_key: str
    model: str
    verify_tls: bool = True
    transport: Callable[..., dict[str, Any]] = _default_transport

    @property
    def descriptor(self):
        return build_descriptor(
            key="openai-compatible",
            kind=AiProviderKind.OPENAI_COMPATIBLE,
            display_name="OpenAI-Compatible",
            description="AI planner powered by an OpenAI-compatible chat completion endpoint.",
            capabilities=[AiCapability.CHAT, AiCapability.JSON_OUTPUT],
            config_fields=["base_url", "api_key", "model"],
        )

    def validate(self) -> None:
        if not self.base_url or not self.api_key or not self.model:
            raise ValueError("OpenAI-compatible planner requires base_url, api_key, and model.")

    def plan(self, candidates: list[AiPlanningCandidate], *, min_priority_score: int) -> list[AiPlanningProposal]:
        self.validate()
        payload = {
            "model": self.model,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You rank deterministic API security planning candidates. "
                        "Return JSON with a top-level 'proposals' array. "
                        "Each proposal must include: path_id, include_in_plan, priority_score, recommended_severity, suggested_rationale, explanation, tags."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "min_priority_score": min_priority_score,
                            "candidates": [candidate.model_dump(mode="json") for candidate in candidates],
                        },
                        ensure_ascii=True,
                    ),
                },
            ],
        }
        response_payload = self.transport(
            base_url=self.base_url,
            api_key=self.api_key,
            model=self.model,
            verify_tls=self.verify_tls,
            payload=payload,
        )
        content = response_payload["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        proposals = parsed.get("proposals", [])
        return [AiPlanningProposal.model_validate(item) for item in proposals if isinstance(item, dict)]

    def decide_next_action(self, request: AiNextActionRequest) -> AiNextActionDecision:
        self.validate()
        payload = {
            "model": self.model,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You choose the next action for an autonomous API security orchestration loop. "
                        "Return JSON with: next_action, confidence, rationale, supporting_observations. "
                        "Valid next_action values are: deterministic_planner, ai_planner, verifier_cycle, summary."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(request.model_dump(mode="json"), ensure_ascii=True),
                },
            ],
        }
        response_payload = self.transport(
            base_url=self.base_url,
            api_key=self.api_key,
            model=self.model,
            verify_tls=self.verify_tls,
            payload=payload,
        )
        content = response_payload["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        return AiNextActionDecision.model_validate(parsed)
