from __future__ import annotations

from dataclasses import dataclass

from api.schemas.ai import (
    AiHypothesisSelectionDecision,
    AiHypothesisSelectionRequest,
    AiCapability,
    AiNextAction,
    AiNextActionDecision,
    AiNextActionRequest,
    AiPlanningCandidate,
    AiPlanningProposal,
    AiProviderKind,
)
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

    def decide_next_action(self, request: AiNextActionRequest) -> AiNextActionDecision:
        memory = request.memory
        if memory.proxy_event_count > memory.last_deterministic_event_count and memory.deterministic_planning_runs < request.max_planning_passes:
            return AiNextActionDecision(
                next_action=AiNextAction.DETERMINISTIC_PLANNER,
                confidence=88,
                rationale="New runtime observations arrived after the last deterministic planning pass.",
                supporting_observations=[
                    f"proxy_event_count={memory.proxy_event_count}",
                    f"last_deterministic_event_count={memory.last_deterministic_event_count}",
                ],
            )

        if (
            request.use_ai_planner
            and memory.last_deterministic_candidate_count > memory.last_ai_candidate_count
            and memory.ai_planning_runs < request.max_ai_planning_passes
        ):
            return AiNextActionDecision(
                next_action=AiNextAction.AI_PLANNER,
                confidence=82,
                rationale="Deterministic planning produced new backlog that has not yet been prioritized by AI assistance.",
                supporting_observations=[
                    f"last_deterministic_candidate_count={memory.last_deterministic_candidate_count}",
                    f"last_ai_candidate_count={memory.last_ai_candidate_count}",
                ],
            )

        if memory.pending_verifier_jobs > 0 and memory.completed_verifier_cycles < request.max_verifier_cycles:
            return AiNextActionDecision(
                next_action=AiNextAction.VERIFIER_CYCLE,
                confidence=90,
                rationale="Queued verifier work remains and replay confirmation should continue before declaring the session complete.",
                supporting_observations=[
                    f"pending_verifier_jobs={memory.pending_verifier_jobs}",
                    f"completed_verifier_cycles={memory.completed_verifier_cycles}",
                ],
            )

        if memory.finding_count > 0 and memory.remediation_backlog:
            return AiNextActionDecision(
                next_action=AiNextAction.REMEDIATION,
                confidence=87,
                rationale="Confirmed findings still need remediation follow-up before the session is complete.",
                supporting_observations=[
                    f"finding_count={memory.finding_count}",
                    f"remediation_backlog={len(memory.remediation_backlog)}",
                ],
            )

        if memory.finding_count > 0 and memory.report_backlog:
            return AiNextActionDecision(
                next_action=AiNextAction.REPORT,
                confidence=86,
                rationale="Confirmed findings still need report follow-up before the session is complete.",
                supporting_observations=[
                    f"finding_count={memory.finding_count}",
                    f"report_backlog={len(memory.report_backlog)}",
                ],
            )

        return AiNextActionDecision(
            next_action=AiNextAction.SUMMARY,
            confidence=95,
            rationale="No higher-priority action remains in memory, so the autonomous session can summarize current results.",
            supporting_observations=[
                f"candidate_backlog={len(memory.candidate_backlog)}",
                f"pending_verifier_jobs={memory.pending_verifier_jobs}",
            ],
        )

    def select_hypothesis(self, request: AiHypothesisSelectionRequest) -> AiHypothesisSelectionDecision:
        if not request.hypotheses:
            raise ValueError("No hypotheses are available for selection.")

        def rank(candidate):
            severity_score = _severity_score(candidate.severity)
            payload_bonus = 5 if candidate.available_payload_variant_ids else 0
            signal_bonus = min(8, len(candidate.matched_signals) * 2)
            return severity_score + candidate.confidence + payload_bonus + signal_bonus

        selected = max(request.hypotheses, key=rank)
        selected_variant = selected.available_payload_variant_ids[0] if selected.available_payload_variant_ids else None
        return AiHypothesisSelectionDecision(
            selected_hypothesis_id=selected.hypothesis_id,
            selected_source_path_id=selected.source_path_id,
            selected_verifier_strategy=selected.verifier_strategy,
            selected_payload_variant_id=selected_variant,
            confidence=min(100, rank(selected)),
            rationale="Mock selector prioritized the highest-confidence unresolved hypothesis with the strongest severity and available payload options.",
            supporting_observations=[
                f"severity={selected.severity}",
                f"confidence={selected.confidence}",
                f"available_variants={len(selected.available_payload_variant_ids)}",
            ],
        )
