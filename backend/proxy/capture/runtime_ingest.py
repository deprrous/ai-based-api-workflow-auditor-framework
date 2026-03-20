from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import json
import re
from types import SimpleNamespace
from typing import Any, Callable, Mapping
from urllib import error, parse, request

from api.schemas.replay_artifacts import ReplayArtifactInput

STATIC_EXTENSIONS = (
    ".css",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".map",
    ".png",
    ".svg",
    ".woff",
    ".woff2",
)
UUID_SEGMENT = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.IGNORECASE)
HEX_SEGMENT = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)
NUMERIC_SEGMENT = re.compile(r"^\d+$")
LONG_TOKEN_SEGMENT = re.compile(r"^[A-Za-z0-9_-]{20,}$")


@dataclass(frozen=True, slots=True)
class RuntimeIngestOptions:
    backend_url: str
    scan_id: str
    ingest_token: str
    include_hosts: tuple[str, ...] = ()
    include_path_prefixes: tuple[str, ...] = ("/",)
    ignore_methods: tuple[str, ...] = ("CONNECT", "OPTIONS")
    timeout_seconds: float = 3.0


def split_csv(value: str | None) -> tuple[str, ...]:
    if not value:
        return tuple()

    return tuple(item.strip() for item in value.split(",") if item.strip())


def normalize_path(raw_path: str) -> str:
    path = parse.urlsplit(raw_path).path or "/"
    parts = [part for part in path.split("/") if part]

    normalized: list[str] = []
    for part in parts:
        lowered = part.lower()
        if NUMERIC_SEGMENT.match(part):
            normalized.append("{id}")
        elif UUID_SEGMENT.match(lowered):
            normalized.append("{uuid}")
        elif HEX_SEGMENT.match(lowered) or LONG_TOKEN_SEGMENT.match(part):
            normalized.append("{token}")
        else:
            normalized.append(part)

    if not normalized:
        return "/"

    return "/" + "/".join(normalized)


def classify_phase(method: str, normalized_path: str) -> str:
    lowered_path = normalized_path.lower()
    auth_markers = ("/auth", "/login", "/logout", "/session", "/token")

    if any(marker in lowered_path for marker in auth_markers):
        return "auth"
    if method.upper() in {"GET", "HEAD"}:
        return "read"
    return "action"


def _stable_bucket(value: str, *, size: int, offset: int = 0) -> int:
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest()
    return offset + (int(digest[:6], 16) % size)


def _hash_label(value: str, *, prefix: str, length: int = 10) -> str:
    return f"{prefix}:{hashlib.sha256(value.encode('utf-8')).hexdigest()[:length]}"


def _extract_headers(raw_headers: Any) -> dict[str, str]:
    if raw_headers is None:
        return {}

    if isinstance(raw_headers, Mapping):
        return {str(key).lower(): str(value) for key, value in raw_headers.items()}

    if hasattr(raw_headers, "items"):
        return {str(key).lower(): str(value) for key, value in raw_headers.items()}

    return {}


def _extract_body_bytes(value: Any) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    return None


def _to_base64(value: bytes | None) -> str | None:
    if value is None:
        return None
    return base64.b64encode(value).decode("ascii")


def build_replay_artifact(request_obj: Any, response_obj: Any) -> ReplayArtifactInput:
    request_headers = _extract_headers(getattr(request_obj, "headers", None))
    response_headers = _extract_headers(getattr(response_obj, "headers", None)) if response_obj is not None else {}
    request_body = _extract_body_bytes(getattr(request_obj, "raw_content", None) or getattr(request_obj, "content", None))
    response_body = _extract_body_bytes(
        getattr(response_obj, "raw_content", None) if response_obj is not None else None
    )
    response_excerpt = None
    if response_body is not None:
        try:
            response_excerpt = response_body.decode("utf-8", errors="ignore")[:4000]
        except Exception:  # pragma: no cover
            response_excerpt = None

    return ReplayArtifactInput(
        request_headers=request_headers,
        request_body_base64=_to_base64(request_body),
        request_content_type=request_headers.get("content-type"),
        response_status_code=getattr(response_obj, "status_code", None),
        response_headers=response_headers,
        response_body_excerpt=response_excerpt,
    )


def derive_actor(headers: Mapping[str, str], client_id: str | None) -> str:
    authorization = headers.get("authorization")
    if authorization:
        scheme, _, value = authorization.partition(" ")
        if value:
            return _hash_label(value.strip(), prefix=scheme.lower() or "auth")

    for header_name in ("x-api-key", "api-key", "x-auth-token"):
        header_value = headers.get(header_name)
        if header_value:
            return _hash_label(header_value, prefix=header_name)

    cookie_header = headers.get("cookie")
    if cookie_header:
        parsed = parse.parse_qsl(cookie_header.replace("; ", "&"), keep_blank_values=False)
        for key, value in parsed:
            if any(marker in key.lower() for marker in ("session", "auth", "token", "jwt")):
                return _hash_label(value, prefix=key.lower())

    if client_id:
        return f"client:{client_id}"

    return "client:unknown"


def build_request_fingerprint(method: str, host: str, normalized_path: str, raw_path: str) -> str:
    query_keys = sorted(parse.parse_qs(parse.urlsplit(raw_path).query, keep_blank_values=False).keys())
    fingerprint_input = "|".join([method.upper(), host.lower(), normalized_path, ",".join(query_keys)])
    return hashlib.sha1(fingerprint_input.encode("utf-8")).hexdigest()[:16]


def build_endpoint_node(method: str, host: str, normalized_path: str, status_code: int | None) -> dict[str, Any]:
    phase = classify_phase(method, normalized_path)
    node_key = f"{method.upper()}|{host.lower()}|{normalized_path}"
    node_id = f"endpoint-{hashlib.sha1(node_key.encode('utf-8')).hexdigest()[:12]}"
    status = "active"
    if status_code is not None and status_code >= 500:
        status = "review"

    phase_columns = {
        "auth": 180.0,
        "read": 580.0,
        "action": 980.0,
    }

    return {
        "id": node_id,
        "label": f"{method.upper()} {normalized_path}",
        "type": "endpoint",
        "phase": phase,
        "detail": f"Observed on {host} with status {status_code if status_code is not None else 'unknown'}.",
        "status": status,
        "x": phase_columns.get(phase, 580.0),
        "y": float(120 + (_stable_bucket(node_key, size=7) * 110)),
    }


def build_edge(previous_node_id: str | None, node_id: str) -> dict[str, Any] | None:
    if previous_node_id is None or previous_node_id == node_id:
        return None

    return {
        "source": previous_node_id,
        "target": node_id,
        "label": "observed target flow",
        "style": "solid",
        "animated": True,
    }


def should_capture_request(options: RuntimeIngestOptions, host: str, method: str, raw_path: str) -> bool:
    parsed_backend = parse.urlsplit(options.backend_url)
    raw_path_only = parse.urlsplit(raw_path).path or "/"

    if options.include_hosts and host not in options.include_hosts:
        return False
    if method.upper() in options.ignore_methods:
        return False
    if raw_path_only.lower().endswith(STATIC_EXTENSIONS):
        return False
    if options.include_path_prefixes and not any(raw_path_only.startswith(prefix) for prefix in options.include_path_prefixes):
        return False
    if host == parsed_backend.hostname and raw_path_only.startswith(parsed_backend.path or "/"):
        return False

    return True


def build_proxy_http_observed_event(
    flow: Any,
    options: RuntimeIngestOptions,
    previous_node_id: str | None = None,
) -> tuple[dict[str, Any], str]:
    request_obj = flow.request
    response_obj = getattr(flow, "response", None)

    method = str(getattr(request_obj, "method", "GET")).upper()
    host = str(getattr(request_obj, "host", ""))
    raw_path = str(getattr(request_obj, "path", "/"))
    normalized_path = normalize_path(raw_path)
    status_code = getattr(response_obj, "status_code", None)
    headers = _extract_headers(getattr(request_obj, "headers", None))
    client_address = getattr(getattr(flow, "client_conn", None), "peername", None)
    client_id = None
    if isinstance(client_address, tuple) and client_address:
        client_id = ":".join(str(part) for part in client_address if part is not None)

    actor = derive_actor(headers, client_id)
    request_fingerprint = build_request_fingerprint(method, host, normalized_path, raw_path)
    node = build_endpoint_node(method, host, normalized_path, status_code)
    edge = build_edge(previous_node_id, node["id"])
    request_id = str(getattr(flow, "id", request_fingerprint))

    event = {
        "contract_version": "v1",
        "source": "proxy",
        "event_type": "proxy.http_observed",
        "stage": "ingestion",
        "severity": "info",
        "message": f"Observed {method} {raw_path} from target traffic.",
        "producer_contract": {
            "kind": "proxy.http_observed",
            "request_id": request_id,
            "request_fingerprint": request_fingerprint,
            "method": method,
            "host": host,
            "path": raw_path,
            "status_code": status_code,
            "actor": actor,
            "node": node,
            "edge": edge,
            "replay_artifact": build_replay_artifact(request_obj, response_obj).model_dump(mode="json"),
        },
    }
    return event, actor


def post_ingest_event(options: RuntimeIngestOptions, event: dict[str, Any]) -> int:
    endpoint = f"{options.backend_url.rstrip('/')}/scans/{options.scan_id}/events"
    payload = json.dumps(event, ensure_ascii=True).encode("utf-8")
    http_request = request.Request(
        endpoint,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-Auditor-Ingest-Token": options.ingest_token,
        },
        method="POST",
    )

    try:
        with request.urlopen(http_request, timeout=options.timeout_seconds) as response:
            return int(response.status)
    except error.HTTPError as exc:
        return int(exc.code)


@dataclass(slots=True)
class RuntimeIngestEmitter:
    options: RuntimeIngestOptions
    sender: Callable[[RuntimeIngestOptions, dict[str, Any]], int] = post_ingest_event
    logger: Callable[[str], None] | None = None
    _last_node_by_actor: dict[str, str] = field(init=False, default_factory=dict)

    def process_flow(self, flow: Any) -> bool:
        request_obj = getattr(flow, "request", None)
        if request_obj is None:
            return False

        method = str(getattr(request_obj, "method", "GET")).upper()
        host = str(getattr(request_obj, "host", ""))
        raw_path = str(getattr(request_obj, "path", "/"))
        if not should_capture_request(self.options, host, method, raw_path):
            return False

        flow_headers = _extract_headers(getattr(request_obj, "headers", None))
        client_address = getattr(getattr(flow, "client_conn", None), "peername", None)
        client_id = None
        if isinstance(client_address, tuple) and client_address:
            client_id = ":".join(str(part) for part in client_address if part is not None)
        actor = derive_actor(flow_headers, client_id)
        previous_node_id = self._last_node_by_actor.get(actor)

        event, actor_key = build_proxy_http_observed_event(flow, self.options, previous_node_id=previous_node_id)
        status_code = self.sender(self.options, event)
        if 200 <= status_code < 300:
            node_id = event["producer_contract"]["node"]["id"]
            self._last_node_by_actor[actor_key] = node_id
            return True

        if self.logger is not None:
            self.logger(f"runtime ingest failed with status {status_code} for {event['producer_contract']['path']}")
        return False


def fake_flow(
    *,
    flow_id: str,
    method: str,
    host: str,
    path: str,
    status_code: int | None,
    headers: Mapping[str, str] | None = None,
    request_body: bytes | str | None = None,
    response_headers: Mapping[str, str] | None = None,
    response_body: bytes | str | None = None,
    client_ip: str = "127.0.0.1",
    client_port: int = 50000,
) -> Any:
    return SimpleNamespace(
        id=flow_id,
        request=SimpleNamespace(method=method, host=host, path=path, headers=headers or {}, raw_content=request_body, content=request_body),
        response=SimpleNamespace(status_code=status_code, headers=response_headers or {}, raw_content=response_body),
        client_conn=SimpleNamespace(peername=(client_ip, client_port)),
    )
