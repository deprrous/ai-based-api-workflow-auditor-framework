from __future__ import annotations

from urllib import parse

from api.schemas.artifacts import ArtifactRiskIndicatorSummary
from api.schemas.events import ScanEvent
from orchestrator.planners.vulnerability_rules import CoverageObservation, evaluate_rule_packs
from tools.workflow.worker import WorkflowObservedStep, WorkflowPathFindingCandidate


def _observation_from_event(
    event: ScanEvent,
    *,
    route_risk_lookup: dict[tuple[str, str], list[ArtifactRiskIndicatorSummary]] | None = None,
) -> CoverageObservation | None:
    if event.event_type != "proxy.http_observed" or event.payload is None:
        return None

    payload = event.payload
    actor = str(payload.get("actor") or "client:unknown")
    method = str(payload.get("method") or "GET").upper()
    path = str(payload.get("path") or "/")
    host = str(payload.get("host") or "")
    request_fingerprint = str(payload.get("request_fingerprint") or event.id)
    replay_artifact_id = str(payload.get("replay_artifact_id")) if payload.get("replay_artifact_id") else None
    route_indicators = []
    if route_risk_lookup is not None:
        stripped_path = parse.urlsplit(path).path or path
        route_indicators = route_risk_lookup.get((method.upper(), path), []) or route_risk_lookup.get((method.upper(), stripped_path), [])

    if not path or not host:
        return None

    return CoverageObservation(
        event_id=event.id,
        actor=actor,
        method=method,
        path=path,
        host=host,
        request_fingerprint=request_fingerprint,
        replay_artifact_id=replay_artifact_id,
        node_id=f"event-node-{event.id}",
        label=f"{method} {path}",
        phase="action" if method in {"POST", "PUT", "PATCH", "DELETE"} else "read",
        detail=f"Observed {method} {path} on {host} from actor {actor}.",
        artifact_risk_categories=tuple(indicator.category for indicator in route_indicators),
        artifact_signal_labels=tuple(indicator.summary for indicator in route_indicators),
    )


def _build_path_id(scan_id: str, fingerprints: list[str]) -> str:
    import hashlib

    joined = "|".join([scan_id, *fingerprints])
    return f"planned-path-{hashlib.sha1(joined.encode('utf-8')).hexdigest()[:12]}"


def _build_steps(observations: list[CoverageObservation]) -> list[WorkflowObservedStep]:
    return [
        WorkflowObservedStep(
            node_id=observation.node_id,
            label=observation.label,
            phase=observation.phase,
            detail=observation.detail,
            host=observation.host,
            path=observation.path,
            method=observation.method,
            actor=observation.actor,
            request_fingerprint=observation.request_fingerprint,
            replay_artifact_id=observation.replay_artifact_id,
        )
        for observation in observations
    ]


def build_candidates_from_proxy_events(
    scan_id: str,
    events: list[ScanEvent],
    *,
    route_risk_lookup: dict[tuple[str, str], list[ArtifactRiskIndicatorSummary]] | None = None,
) -> list[WorkflowPathFindingCandidate]:
    observations = [
        observation
        for event in events
        if (observation := _observation_from_event(event, route_risk_lookup=route_risk_lookup)) is not None
    ]
    by_actor: dict[str, list[CoverageObservation]] = {}
    for observation in observations:
        by_actor.setdefault(observation.actor, []).append(observation)

    candidates: list[WorkflowPathFindingCandidate] = []
    seen_path_ids: set[str] = set()

    for actor, actor_observations in by_actor.items():
        ordered = sorted(actor_observations, key=lambda item: item.event_id)
        for index in range(len(ordered)):
            window = ordered[max(0, index - 3) : index + 1]
            if len(window) < 2:
                continue

            rule_match = evaluate_rule_packs(window, actor=actor)
            if rule_match is None:
                continue

            fingerprints = [item.request_fingerprint for item in window]
            path_id = _build_path_id(scan_id, fingerprints)
            if path_id in seen_path_ids:
                continue

            seen_path_ids.add(path_id)
            candidates.append(
                WorkflowPathFindingCandidate(
                    scan_id=scan_id,
                    path_id=path_id,
                    title=rule_match.title,
                    rationale=rule_match.rationale,
                    severity=rule_match.severity,
                    vulnerability_class=rule_match.vulnerability_class,
                    confidence=rule_match.confidence,
                    matched_rule=rule_match.rule_id,
                    verifier_strategy=rule_match.verifier_strategy,
                    matched_signals=list(rule_match.matched_signals),
                    steps=_build_steps(window),
                    actor=actor,
                    flagged_paths_increment=1,
                )
            )

    return candidates
