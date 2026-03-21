from __future__ import annotations

from api.app.config import get_settings
from api.schemas.ai import (
    AiHypothesisSelectionDecision,
    AiHypothesisSelectionRequest,
    AiNextActionDecision,
    AiNextActionRequest,
    AiPlanningCandidate,
    AiPlanningProposal,
    AiProviderCatalog,
)
from orchestrator.providers.registry import build_planning_provider, get_provider_catalog


class AiProviderService:
    def get_catalog(self) -> AiProviderCatalog:
        return get_provider_catalog()

    def plan_candidates(
        self,
        candidates: list[AiPlanningCandidate],
        *,
        provider_key: str | None = None,
        min_priority_score: int,
    ) -> tuple[str, list[AiPlanningProposal]]:
        provider = build_planning_provider(settings=get_settings(), provider_key=provider_key)
        proposals = provider.plan(candidates, min_priority_score=min_priority_score)
        return provider.descriptor.key, proposals

    def decide_next_action(
        self,
        request: AiNextActionRequest,
        *,
        provider_key: str | None = None,
    ) -> tuple[str, AiNextActionDecision]:
        provider = build_planning_provider(settings=get_settings(), provider_key=provider_key)
        decision = provider.decide_next_action(request)
        return provider.descriptor.key, decision

    def select_hypothesis(
        self,
        request: AiHypothesisSelectionRequest,
        *,
        provider_key: str | None = None,
    ) -> tuple[str, AiHypothesisSelectionDecision]:
        provider = build_planning_provider(settings=get_settings(), provider_key=provider_key)
        decision = provider.select_hypothesis(request)
        return provider.descriptor.key, decision


ai_provider_service = AiProviderService()
