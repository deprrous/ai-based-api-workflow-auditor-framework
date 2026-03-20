from __future__ import annotations

from dataclasses import dataclass

from api.schemas.ai import AiCapability, AiPlanningCandidate, AiPlanningProposal, AiProviderKind
from orchestrator.providers.base import build_descriptor


def _severity_score(severity: str) -> int:
    normalized = severity.lower()
    if normalized == "critical":
        return 90
    if normalized == "high":
        return 75
    if normalized == "review":
        return 55
    return 40


@dataclass(frozen=True, slots=True)
class MockPlanningProvider:
    key: str = "mock"
    display_name: str = "Mock Planner"
    description: str = "Deterministic no-key planner provider for local testing and backend development."

    @property
    def descriptor(self):
        return build_descriptor(
            key=self.key,
            kind=AiProviderKind.MOCK,
            display_name=self.display_name,
            description=self.description,
            capabilities=[AiCapability.CHAT, AiCapability.JSON_OUTPUT],
            config_fields=[],
        )

    def validate(self) -> None:
        return None

    def plan(self, candidates: list[AiPlanningCandidate], *, min_priority_score: int) -> list[AiPlanningProposal]:
        proposals: list[AiPlanningProposal] = []
        for candidate in candidates:
            artifact_bonus = 8 if "Matched artifact context" in candidate.rationale else 0
            destructive_bonus = 8 if any(token in candidate.title.lower() for token in ("delete", "admin", "key", "tenant")) else 0
            coverage_bonus = 6 if candidate.vulnerability_class in {"bfla", "bola_idor", "tenant_isolation", "unsafe_destructive_action"} else 0
            signal_bonus = min(10, len(candidate.matched_signals) * 2)
            priority_score = min(
                100,
                _severity_score(candidate.severity) + artifact_bonus + destructive_bonus + coverage_bonus + signal_bonus + max(0, candidate.confidence - 70) // 2,
            )
            include_in_plan = priority_score >= min_priority_score
            proposals.append(
                AiPlanningProposal(
                    path_id=candidate.path_id,
                    include_in_plan=include_in_plan,
                    priority_score=priority_score,
                    recommended_severity=candidate.severity,
                    suggested_rationale=(
                        f"AI-assisted mock planner ranked this {candidate.vulnerability_class.value if hasattr(candidate.vulnerability_class, 'value') else candidate.vulnerability_class} path at {priority_score} "
                        f"using severity, rule confidence, matched signals, artifact context, and risk keywords. {candidate.rationale}"
                    ),
                    explanation="Mock planner uses deterministic heuristics so backend AI planning can be exercised without external model access.",
                    tags=["mock-ai", candidate.severity.lower(), str(candidate.vulnerability_class), *candidate.matched_signals[:4]],
                )
            )

        return sorted(proposals, key=lambda item: (item.priority_score, item.path_id), reverse=True)
