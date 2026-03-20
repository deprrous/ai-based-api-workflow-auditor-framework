from __future__ import annotations

from dataclasses import dataclass
import hashlib

from api.schemas.events import ScanEvent
from api.schemas.findings import FindingSeverity
from tools.workflow.worker import WorkflowObservedStep, WorkflowPathFindingCandidate

DESTRUCTIVE_PATH_KEYWORDS = (
    "delete",
    "destroy",
    "remove",
    "revoke",
)
SENSITIVE_PATH_KEYWORDS = (
    "key",
    "keys",
    "secret",
    "secrets",
    "token",
    "tokens",
    "admin",
    "permission",
    "permissions",
    "role",
    "roles",
)
PRIVILEGE_TRANSITION_KEYWORDS = (
    "member",
    "members",
    "invite",
    "invites",
    "role",
    "roles",
    "permission",
    "permissions",
)


@dataclass(frozen=True, slots=True)
class ProxyObservation:
    event_id: int
    actor: str
    method: str
    path: str
    host: str
    request_fingerprint: str
    node_id: str
    label: str
    phase: str
    detail: str


def _path_tokens(path: str) -> set[str]:
    normalized = path.replace("{", "/").replace("}", "/").replace("-", "/").replace("_", "/")
    return {token for token in normalized.lower().split("/") if token}


def _severity_for_observation(observation: ProxyObservation) -> FindingSeverity | None:
    tokens = _path_tokens(observation.path)
    method = observation.method.upper()

    if method == "DELETE":
        return FindingSeverity.CRITICAL
    if method in {"POST", "PATCH", "PUT"} and tokens & set(DESTRUCTIVE_PATH_KEYWORDS):
        return FindingSeverity.CRITICAL
    if tokens & set(SENSITIVE_PATH_KEYWORDS):
        return FindingSeverity.HIGH
    return None


def _looks_like_privilege_transition(observation: ProxyObservation) -> bool:
    tokens = _path_tokens(observation.path)
    return bool(tokens & set(PRIVILEGE_TRANSITION_KEYWORDS))


def _observation_from_event(event: ScanEvent) -> ProxyObservation | None:
    if event.event_type != "proxy.http_observed" or event.payload is None:
        return None

    payload = event.payload
    actor = str(payload.get("actor") or "client:unknown")
    method = str(payload.get("method") or "GET").upper()
    path = str(payload.get("path") or "/")
    host = str(payload.get("host") or "")
    request_fingerprint = str(payload.get("request_fingerprint") or event.id)

    if not path or not host:
        return None

    return ProxyObservation(
        event_id=event.id,
        actor=actor,
        method=method,
        path=path,
        host=host,
        request_fingerprint=request_fingerprint,
        node_id=f"event-node-{event.id}",
        label=f"{method} {path}",
        phase="action" if method in {"POST", "PUT", "PATCH", "DELETE"} else "read",
        detail=f"Observed {method} {path} on {host} from actor {actor}.",
    )


def _build_path_id(scan_id: str, fingerprints: list[str]) -> str:
    joined = "|".join([scan_id, *fingerprints])
    return f"planned-path-{hashlib.sha1(joined.encode('utf-8')).hexdigest()[:12]}"


def _build_steps(observations: list[ProxyObservation]) -> list[WorkflowObservedStep]:
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
        )
        for observation in observations
    ]


def build_candidates_from_proxy_events(scan_id: str, events: list[ScanEvent]) -> list[WorkflowPathFindingCandidate]:
    observations = [observation for event in events if (observation := _observation_from_event(event)) is not None]
    by_actor: dict[str, list[ProxyObservation]] = {}
    for observation in observations:
        by_actor.setdefault(observation.actor, []).append(observation)

    candidates: list[WorkflowPathFindingCandidate] = []
    seen_path_ids: set[str] = set()

    for actor, actor_observations in by_actor.items():
        ordered = sorted(actor_observations, key=lambda item: item.event_id)
        for index, observation in enumerate(ordered):
            severity = _severity_for_observation(observation)
            if severity is None:
                continue

            prior_window = ordered[max(0, index - 3) : index]
            if not prior_window:
                continue

            transition_observations = [item for item in prior_window if _looks_like_privilege_transition(item)]
            context = transition_observations[-2:] if transition_observations else prior_window[-2:]
            selected = [*context, observation]
            fingerprints = [item.request_fingerprint for item in selected]
            path_id = _build_path_id(scan_id, fingerprints)
            if path_id in seen_path_ids:
                continue

            seen_path_ids.add(path_id)
            title = f"{actor} reaches risky path {observation.method} {observation.path}"
            rationale = (
                f"Observed actor {actor} traverse {len(selected)} related steps before reaching "
                f"the risky endpoint {observation.method} {observation.path}."
            )
            candidates.append(
                WorkflowPathFindingCandidate(
                    scan_id=scan_id,
                    path_id=path_id,
                    title=title,
                    rationale=rationale,
                    severity=severity,
                    steps=_build_steps(selected),
                    actor=actor,
                    flagged_paths_increment=1,
                )
            )

    return candidates
