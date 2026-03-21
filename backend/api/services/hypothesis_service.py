from __future__ import annotations

from api.schemas.hypotheses import HypothesisDetail, HypothesisSummary
from api.schemas.planner import PlannerCandidateSummary, VerifierStrategy
from api.services.store import audit_store


class HypothesisService:
    def list_hypotheses(self, scan_id: str) -> list[HypothesisSummary]:
        return audit_store.list_hypotheses(scan_id)

    def get_hypothesis(self, hypothesis_id: str) -> HypothesisDetail | None:
        return audit_store.get_hypothesis(hypothesis_id)

    def sync_hypotheses(
        self,
        *,
        scan_id: str,
        session_id: str | None,
        planning_run_id: str | None,
        candidates: list[PlannerCandidateSummary],
        decision_source: str,
    ) -> list[HypothesisSummary]:
        return audit_store.sync_hypotheses_from_candidates(
            scan_id=scan_id,
            session_id=session_id,
            planning_run_id=planning_run_id,
            candidates=candidates,
            decision_source=decision_source,
        )

    def select_hypothesis(
        self,
        *,
        hypothesis_id: str,
        decision_source: str,
        selected_verifier_strategy: VerifierStrategy,
        selected_payload_variant_id: str | None,
    ) -> HypothesisDetail | None:
        return audit_store.select_hypothesis(
            hypothesis_id=hypothesis_id,
            decision_source=decision_source,
            selected_verifier_strategy=selected_verifier_strategy.value,
            selected_payload_variant_id=selected_payload_variant_id,
        )


hypothesis_service = HypothesisService()
