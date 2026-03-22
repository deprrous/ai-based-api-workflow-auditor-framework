from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Callable

import httpx

from api.schemas.ai import (
    AiAuthMethod,
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


def _default_transport(
    *,
    model: str,
    api_key: str | None,
    access_token: str | None,
    payload: dict[str, Any],
) -> dict[str, Any]:
    headers = {"content-type": "application/json"}
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        params = None
    else:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        params = {"key": api_key or ""}
    response = httpx.post(url, headers=headers, params=params, json=payload, timeout=20.0)
    response.raise_for_status()
    return response.json()


@dataclass(frozen=True, slots=True)
class GooglePlanningProvider:
    model: str
    api_key: str | None = None
    access_token: str | None = None
    transport: Callable[..., dict[str, Any]] = _default_transport

    @property
    def descriptor(self):
        return build_descriptor(
            key="google",
            kind=AiProviderKind.GOOGLE,
            display_name="Google / Gemini",
            description="Native Google Gemini planning provider.",
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
                    description="Use Google cloud credentials or an access token.",
                    required_fields=["project_id"],
                ),
            ],
        )

    def validate(self) -> None:
        if not self.model:
            raise ValueError("Google planner requires model.")
        if not self.api_key and not self.access_token:
            raise ValueError("Google planner requires an api_key or access_token.")

    def _invoke(self, instruction: str, payload: dict[str, object]) -> dict[str, object]:
        self.validate()
        response_payload = self.transport(
            model=self.model,
            api_key=self.api_key,
            access_token=self.access_token,
            payload={
                "contents": [
                    {
                        "parts": [
                            {"text": f"{instruction}\n\n{json.dumps(payload, ensure_ascii=True)}"},
                        ]
                    }
                ],
                "generationConfig": {"responseMimeType": "application/json"},
            },
        )
        parts = response_payload.get("candidates", [{}])[0].get("content", {}).get("parts", [])
        text = parts[0].get("text", "{}") if parts else "{}"
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else {}

    def plan(self, candidates: list[AiPlanningCandidate], *, min_priority_score: int) -> list[AiPlanningProposal]:
        parsed = self._invoke(
            "Return JSON with a top-level proposals array for ranked API security planning candidates.",
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
