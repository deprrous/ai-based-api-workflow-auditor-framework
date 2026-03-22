from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from api.schemas.ai import (
    AiHypothesisSelectionDecision,
    AiHypothesisSelectionRequest,
    AiAuthMethod,
    AiProviderAuthMethodDescriptor,
    AiCapability,
    AiNextActionDecision,
    AiNextActionRequest,
    AiPlanningCandidate,
    AiPlanningProposal,
    AiProviderDescriptor,
    AiProviderKind,
)


@dataclass(frozen=True, slots=True)
class ProviderSettingsField:
    name: str


class AiProvider(Protocol):
    descriptor: AiProviderDescriptor

    def validate(self) -> None: ...


class AiPlanningProvider(AiProvider, Protocol):
    def plan(self, candidates: list[AiPlanningCandidate], *, min_priority_score: int) -> list[AiPlanningProposal]: ...

    def decide_next_action(self, request: AiNextActionRequest) -> AiNextActionDecision: ...

    def select_hypothesis(self, request: AiHypothesisSelectionRequest) -> AiHypothesisSelectionDecision: ...


def build_descriptor(
    *,
    key: str,
    kind: AiProviderKind,
    display_name: str,
    description: str,
    capabilities: list[AiCapability],
    config_fields: list[str],
    auth_methods: list[AiProviderAuthMethodDescriptor] | None = None,
) -> AiProviderDescriptor:
    return AiProviderDescriptor(
        key=key,
        kind=kind,
        display_name=display_name,
        description=description,
        capabilities=capabilities,
        config_fields=config_fields,
        auth_methods=auth_methods or [],
    )


def auth_descriptor(
    *,
    method: AiAuthMethod,
    label: str,
    description: str,
    required_fields: list[str],
) -> AiProviderAuthMethodDescriptor:
    return AiProviderAuthMethodDescriptor(
        method=method,
        label=label,
        description=description,
        required_fields=required_fields,
    )
