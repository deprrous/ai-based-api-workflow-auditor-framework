from __future__ import annotations

from typing import Any, cast

from proxy.capture.runtime_ingest import (
    RuntimeIngestEmitter,
    RuntimeIngestOptions,
    build_proxy_http_observed_event,
    fake_flow,
    normalize_path,
    should_capture_request,
)


def test_normalize_path_replaces_ids_and_tokens() -> None:
    assert normalize_path("/v1/projects/123/users/550e8400-e29b-41d4-a716-446655440000") == "/v1/projects/{id}/users/{uuid}"
    assert normalize_path("/api/keys/4f3d2c1b0a99887766554433221100aa") == "/api/keys/{token}"


def test_build_proxy_contract_contains_node_and_edge() -> None:
    options = RuntimeIngestOptions(
        backend_url="http://127.0.0.1:8000/api/v1",
        scan_id="bootstrap-scan",
        ingest_token="token",
        include_path_prefixes=("/v1",),
    )
    flow = fake_flow(
        flow_id="flow-1",
        method="DELETE",
        host="qa.example.internal",
        path="/v1/projects/123",
        status_code=204,
        headers={"Authorization": "Bearer secret-token"},
    )

    event, actor = build_proxy_http_observed_event(flow, options, previous_node_id="endpoint-previous")
    contract = cast(dict[str, Any], event["producer_contract"])

    assert actor.startswith("bearer:")
    assert event["event_type"] == "proxy.http_observed"
    assert cast(dict[str, Any], contract["node"])["type"] == "endpoint"
    assert cast(dict[str, Any], contract["node"])["phase"] == "action"
    assert cast(dict[str, Any], contract["edge"])["source"] == "endpoint-previous"
    assert contract["request_fingerprint"]
    assert cast(dict[str, Any], contract["replay_artifact"])["request_headers"]["authorization"] == "Bearer secret-token"


def test_emitter_posts_flow_and_tracks_actor_sequence() -> None:
    sent_events: list[dict[str, object]] = []

    def sender(_: RuntimeIngestOptions, event: dict[str, object]) -> int:
        sent_events.append(event)
        return 202

    options = RuntimeIngestOptions(
        backend_url="http://127.0.0.1:8000/api/v1",
        scan_id="bootstrap-scan",
        ingest_token="token",
        include_hosts=("qa.example.internal",),
        include_path_prefixes=("/v1",),
    )
    emitter = RuntimeIngestEmitter(options=options, sender=sender)

    first_flow = fake_flow(
        flow_id="flow-1",
        method="GET",
        host="qa.example.internal",
        path="/v1/projects",
        status_code=200,
        headers={"Cookie": "session=abc123"},
    )
    second_flow = fake_flow(
        flow_id="flow-2",
        method="DELETE",
        host="qa.example.internal",
        path="/v1/projects/123",
        status_code=204,
        headers={"Cookie": "session=abc123"},
        request_body=b'{"delete":true}',
    )

    assert emitter.process_flow(first_flow) is True
    assert emitter.process_flow(second_flow) is True
    assert len(sent_events) == 2
    first_contract = cast(dict[str, Any], sent_events[0]["producer_contract"])
    second_contract = cast(dict[str, Any], sent_events[1]["producer_contract"])
    assert first_contract["edge"] is None
    assert cast(dict[str, Any], second_contract["edge"])["label"] == "observed target flow"


def test_capture_filters_skip_static_and_backend_paths() -> None:
    options = RuntimeIngestOptions(
        backend_url="http://127.0.0.1:8000/api/v1",
        scan_id="scan-1",
        ingest_token="token",
        include_path_prefixes=("/",),
    )

    assert should_capture_request(options, "assets.example.internal", "GET", "/app.js") is False
    assert should_capture_request(options, "127.0.0.1", "POST", "/api/v1/scans/scan-1/events") is False
    assert should_capture_request(options, "qa.example.internal", "GET", "/v1/projects") is True
