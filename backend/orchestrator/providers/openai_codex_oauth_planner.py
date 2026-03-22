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

CODEX_BASE_URL = "https://chatgpt.com/backend-api/codex/responses"


def _default_transport(*, access_token: str, account_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    response = httpx.post(
        CODEX_BASE_URL,
        headers={
            "Authorization": f"Bearer {access_token}",
            "chatgpt-account-id": account_id,
            "OpenAI-Beta": "responses=experimental",
            "originator": "codex_cli_rs",
            "accept": "text/event-stream",
            "content-type": "application/json",
        },
        json=payload,
        timeout=30.0,
    )
    response.raise_for_status()
    return {"sse": response.text}


def _extract_final_response(sse_text: str) -> dict[str, Any]:
    for line in sse_text.splitlines():
        if not line.startswith("data: "):
            continue
        try:
            parsed = json.loads(line[6:])
        except json.JSONDecodeError:
            continue
        if parsed.get("type") in {"response.done", "response.completed"}:
            response = parsed.get("response")
            return response if isinstance(response, dict) else {}
    return {}


def _extract_text(response: dict[str, Any]) -> str:
    if isinstance(response.get("output"), str):
        return response["output"]
    if isinstance(response.get("output_text"), str):
        return response["output_text"]
    output = response.get("output")
    if isinstance(output, list):
        texts: list[str] = []
        for item in output:
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            if isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        texts.append(part["text"])
        return "\n".join(texts)
    return ""


@dataclass(frozen=True, slots=True)
class OpenAiCodexOAuthPlanningProvider:
    access_token: str
    refresh_token: str
    account_id: str
    model: str
    transport: Callable[..., dict[str, Any]] = _default_transport

    @property
    def descriptor(self):
        return build_descriptor(
            key="openai",
            kind=AiProviderKind.OPENAI,
            display_name="OpenAI",
            description="OpenAI ChatGPT Plus/Pro browser-auth provider using the Codex backend.",
            capabilities=[AiCapability.CHAT, AiCapability.JSON_OUTPUT],
            config_fields=["model"],
            auth_methods=[
                auth_descriptor(
                    method=AiAuthMethod.OAUTH_BROWSER,
                    label="ChatGPT Plus/Pro",
                    description="Browser auth using ChatGPT Plus/Pro through the Codex backend.",
                    required_fields=["account_label"],
                )
            ],
        )

    def validate(self) -> None:
        if not self.access_token or not self.refresh_token or not self.account_id or not self.model:
            raise ValueError("OpenAI Codex OAuth provider requires access token, refresh token, account id, and model.")

    def _invoke(self, instruction: str, payload: dict[str, object]) -> dict[str, object]:
        self.validate()
        request_payload = {
            "model": self.model,
            "store": False,
            "stream": True,
            "instructions": instruction,
            "input": [
                {
                    "type": "message",
                    "role": "user",
                    "content": [
                        {
                            "type": "input_text",
                            "text": json.dumps(payload, ensure_ascii=True),
                        }
                    ],
                }
            ],
            "reasoning": {"effort": "medium", "summary": "auto"},
            "text": {"verbosity": "medium"},
            "include": ["reasoning.encrypted_content"],
        }
        raw = self.transport(access_token=self.access_token, account_id=self.account_id, payload=request_payload)
        response = _extract_final_response(str(raw.get("sse") or ""))
        text = _extract_text(response)
        parsed = json.loads(text or "{}")
        return parsed if isinstance(parsed, dict) else {}

    def plan(self, candidates: list[AiPlanningCandidate], *, min_priority_score: int) -> list[AiPlanningProposal]:
        parsed = self._invoke(
            "Return JSON with a top-level proposals array for ranked API security planning candidates.",
            {"min_priority_score": min_priority_score, "candidates": [candidate.model_dump(mode="json") for candidate in candidates]},
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
