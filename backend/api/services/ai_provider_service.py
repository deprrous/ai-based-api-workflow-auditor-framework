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
    AiProviderConfigCreateRequest,
    AiProviderConfigDetail,
    AiProviderConfigSummary,
    AiProviderValidationResult,
    AiAuthMethod,
    AiOAuthAuthorizationResponse,
)
from api.services.ai_auth_service import ai_auth_service
from orchestrator.providers.registry import build_planning_provider, get_provider_catalog


class AiProviderService:
    def get_catalog(self) -> AiProviderCatalog:
        return get_provider_catalog()

    def list_configs(self) -> list[AiProviderConfigSummary]:
        return ai_auth_service.list_configs()

    def get_config(self, config_id: str) -> AiProviderConfigDetail | None:
        return ai_auth_service.get_config(config_id)

    def create_config(self, payload: AiProviderConfigCreateRequest) -> AiProviderConfigDetail:
        return ai_auth_service.create_config(payload)

    def upsert_auth(self, config_id: str, auth_method: AiAuthMethod, secret: dict[str, object]) -> AiProviderConfigDetail | None:
        return ai_auth_service.upsert_auth(config_id, auth_method, secret)

    def validate_config(self, config_id: str) -> AiProviderValidationResult | None:
        return ai_auth_service.validate_config(config_id)

    def activate_config(self, config_id: str) -> AiProviderConfigDetail | None:
        return ai_auth_service.activate_config(config_id)

    def start_oauth_browser(self, config_id: str) -> AiOAuthAuthorizationResponse | None:
        return ai_auth_service.start_oauth_browser(config_id)

    def finalize_oauth_browser(self, provider_key: str, state: str, code: str, account_label: str | None = None) -> AiProviderConfigDetail | None:
        return ai_auth_service.finalize_oauth_browser(provider_key, state, code, account_label)

    def plan_candidates(
        self,
        candidates: list[AiPlanningCandidate],
        *,
        provider_key: str | None = None,
        min_priority_score: int,
    ) -> tuple[str, list[AiPlanningProposal]]:
        provider = build_planning_provider(settings=get_settings(), provider_key=provider_key, runtime_auth=ai_auth_service.resolve_runtime_auth(provider_key))
        proposals = provider.plan(candidates, min_priority_score=min_priority_score)
        return provider.descriptor.key, proposals

    def decide_next_action(
        self,
        request: AiNextActionRequest,
        *,
        provider_key: str | None = None,
    ) -> tuple[str, AiNextActionDecision]:
        provider = build_planning_provider(settings=get_settings(), provider_key=provider_key, runtime_auth=ai_auth_service.resolve_runtime_auth(provider_key))
        decision = provider.decide_next_action(request)
        return provider.descriptor.key, decision

    def select_hypothesis(
        self,
        request: AiHypothesisSelectionRequest,
        *,
        provider_key: str | None = None,
    ) -> tuple[str, AiHypothesisSelectionDecision]:
        provider = build_planning_provider(settings=get_settings(), provider_key=provider_key, runtime_auth=ai_auth_service.resolve_runtime_auth(provider_key))
        decision = provider.select_hypothesis(request)
        return provider.descriptor.key, decision


ai_provider_service = AiProviderService()
