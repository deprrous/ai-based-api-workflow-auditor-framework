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
TENANT_BOUNDARY_KEYWORDS = (
    "tenant",
    "project",
    "organization",
    "invoice",
    "account",
)
MASS_ASSIGNMENT_KEYWORDS = (
    "role",
    "permission",
    "permissions",
    "profile",
    "settings",
    "user",
    "users",
    "member",
    "members",
)


@dataclass(frozen=True, slots=True)
class ProxyObservation:
    event_id: int
    actor: str
    method: str
    path: str
    host: str
    request_fingerprint: str
    replay_artifact_id: str | None
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
    if method in {"PUT", "PATCH"} and tokens & set(MASS_ASSIGNMENT_KEYWORDS):
        return FindingSeverity.HIGH
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
    replay_artifact_id = str(payload.get("replay_artifact_id")) if payload.get("replay_artifact_id") else None

    if not path or not host:
        return None

    return ProxyObservation(
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
            replay_artifact_id=observation.replay_artifact_id,
        )
        for observation in observations
    ]


def _classify_candidate(observations: list[ProxyObservation], *, actor: str) -> tuple[str, str, FindingSeverity]:
    final_observation = observations[-1]
    tokens = _path_tokens(final_observation.path)
    methods = {item.method.upper() for item in observations}
    has_transition = any(_looks_like_privilege_transition(item) for item in observations[:-1])

    if final_observation.method.upper() == "DELETE" and has_transition:
        return (
            f"{actor} reaches destructive delete path",
            "Observed a privilege transition before a destructive endpoint, suggesting possible broken function-level authorization.",
            FindingSeverity.CRITICAL,
        )
    if methods & {"PUT", "PATCH"} and tokens & set(MASS_ASSIGNMENT_KEYWORDS):
        return (
            f"{actor} reaches possible mass-assignment path",
            "Observed a writable profile/role-style endpoint that may allow unsafe field updates or privilege mutation.",
            FindingSeverity.HIGH,
        )
    if tokens & set(SENSITIVE_PATH_KEYWORDS) and has_transition:
        return (
            f"{actor} reaches sensitive path after role transition",
            "Observed a transition through member/role-style operations before a sensitive read endpoint, suggesting privilege escalation or excessive exposure.",
            FindingSeverity.HIGH,
        )
    if tokens & set(TENANT_BOUNDARY_KEYWORDS) and any(char.isdigit() for char in final_observation.path):
        return (
            f"{actor} reaches direct object path on tenant-boundary resource",
            "Observed direct-object access on a tenant-scoped resource, suggesting a possible BOLA or tenant-isolation issue.",
            FindingSeverity.HIGH,
        )

    return (
        f"{actor} reaches risky path {final_observation.method} {final_observation.path}",
        f"Observed actor {actor} traverse {len(observations)} related steps before reaching the risky endpoint {final_observation.method} {final_observation.path}.",
        _severity_for_observation(final_observation) or FindingSeverity.REVIEW,
    )


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
            title, rationale, classified_severity = _classify_candidate(selected, actor=actor)
            candidates.append(
                WorkflowPathFindingCandidate(
                    scan_id=scan_id,
                    path_id=path_id,
                    title=title,
                    rationale=rationale,
                    severity=classified_severity,
                    steps=_build_steps(selected),
                    actor=actor,
                    flagged_paths_increment=1,
                )
            )

    return candidates
