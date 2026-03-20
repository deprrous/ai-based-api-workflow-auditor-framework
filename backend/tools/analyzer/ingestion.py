from __future__ import annotations

import hashlib
import json
import re
from typing import Iterable

import yaml

from api.schemas.artifacts import (
    ArtifactKind,
    ArtifactMatchReference,
    ArtifactRiskCategory,
    ArtifactRiskIndicatorSummary,
    ArtifactTaintFlowSummary,
    ArtifactRouteSummary,
    ArtifactSummary,
)

FASTAPI_DECORATOR = re.compile(r"@(app|router)\.(get|post|put|patch|delete|options|head)\(\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
EXPRESS_ROUTE = re.compile(r"(?<!@)\b(app|router)\.(get|post|put|patch|delete|options|head)\(\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
FLASK_ROUTE = re.compile(r"@(?:app|blueprint)\.route\(\s*[\"']([^\"']+)[\"'](?:,\s*methods\s*=\s*\[([^\]]+)\])?", re.IGNORECASE)
SOURCE_SQLI_PATTERNS = (
    re.compile(r"(?:cursor|db|engine|session|conn(?:ection)?)\.(?:execute|query)\([^\n]*(?:\+|f[\"'])", re.IGNORECASE),
    re.compile(r"(?:SELECT|UPDATE|DELETE|INSERT)\s+.+\{.+\}", re.IGNORECASE),
)
SOURCE_SSRF_PATTERNS = (
    re.compile(r"(?:requests|httpx|aiohttp|axios|urllib\.request|fetch)\.(?:get|post|request|urlopen)\([^\n]*url", re.IGNORECASE),
    re.compile(r"(?:requests|httpx|aiohttp|axios|urllib\.request|fetch)\.(?:get|post|request|urlopen)\([^\n]*(?:redirect|callback|webhook|target)", re.IGNORECASE),
)
SOURCE_XSS_PATTERNS = (
    re.compile(r"dangerouslySetInnerHTML", re.IGNORECASE),
    re.compile(r"innerHTML\s*=", re.IGNORECASE),
    re.compile(r"render_template_string\(", re.IGNORECASE),
    re.compile(r"res\.send\([^\n]*html", re.IGNORECASE),
)
URL_LIKE_FIELDS = {"url", "uri", "target", "callback", "callback_url", "redirect", "redirect_url", "webhook", "endpoint", "image_url"}
QUERY_LIKE_FIELDS = {"q", "query", "search", "filter", "sort", "order", "where", "id", "ids"}
HTML_LIKE_FIELDS = {"html", "content", "body", "message", "comment", "description", "bio", "markdown", "template"}
INPUT_SOURCE_PATTERNS = (
    re.compile(r"request\.(?:args|get_json|json|form|query_params|path_params|headers|data)", re.IGNORECASE),
    re.compile(r"req\.(?:query|body|params|headers)", re.IGNORECASE),
    re.compile(r"(?:query|payload|params|body|data)\s*=", re.IGNORECASE),
)
FUNCTION_DEFINITION = re.compile(r"def\s+\w+\(([^)]*)\)")


def _checksum(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _excerpt(value: str, *, limit: int = 2000) -> str:
    compact = value.strip()
    return compact[:limit]


def _iter_lines(content: str) -> Iterable[tuple[int, str]]:
    for index, line in enumerate(content.splitlines(), start=1):
        yield index, line


def _build_indicator(
    *,
    category: ArtifactRiskCategory,
    summary: str,
    location: str,
    confidence: int,
    route_method: str | None = None,
    route_path: str | None = None,
    tags: list[str] | None = None,
) -> dict[str, object]:
    return ArtifactRiskIndicatorSummary(
        category=category,
        summary=summary,
        location=location,
        confidence=confidence,
        route_method=route_method,
        route_path=route_path,
        tags=tags or [],
    ).model_dump(mode="json")


def _route_entries(content: str) -> list[dict[str, str]]:
    routes: list[dict[str, str]] = []

    for match in FASTAPI_DECORATOR.finditer(content):
        routes.append({"method": match.group(2).upper(), "path": match.group(3), "source": "decorator"})

    for match in EXPRESS_ROUTE.finditer(content):
        routes.append({"method": match.group(2).upper(), "path": match.group(3), "source": "express"})

    for match in FLASK_ROUTE.finditer(content):
        methods = match.group(2)
        if methods:
            extracted_methods = [token.strip(" ' \"") for token in methods.split(",") if token.strip()]
        else:
            extracted_methods = ["GET"]
        for method in extracted_methods:
            routes.append({"method": method.upper(), "path": match.group(1), "source": "flask"})

    unique_routes = []
    seen = set()
    for route in routes:
        key = (route["method"], route["path"], route["source"])
        if key in seen:
            continue
        seen.add(key)
        unique_routes.append(route)
    return unique_routes


def _parse_source_risk_indicators(content: str, routes: list[dict[str, str]]) -> list[dict[str, object]]:
    route_method = routes[0]["method"] if routes else None
    route_path = routes[0]["path"] if routes else None
    indicators: list[dict[str, object]] = []

    for line_number, line in _iter_lines(content):
        location = f"line {line_number}"
        if any(pattern.search(line) for pattern in SOURCE_SQLI_PATTERNS):
            indicators.append(
                _build_indicator(
                    category=ArtifactRiskCategory.SQLI,
                    summary="Detected raw SQL execution pattern with possible string interpolation or concatenation.",
                    location=location,
                    confidence=88,
                    route_method=route_method,
                    route_path=route_path,
                    tags=["raw-sql", "dynamic-query"],
                )
            )
        if any(pattern.search(line) for pattern in SOURCE_SSRF_PATTERNS):
            indicators.append(
                _build_indicator(
                    category=ArtifactRiskCategory.SSRF,
                    summary="Detected outbound HTTP request sink that may consume user-controlled URLs or callbacks.",
                    location=location,
                    confidence=84,
                    route_method=route_method,
                    route_path=route_path,
                    tags=["outbound-http", "url-sink"],
                )
            )
        if any(pattern.search(line) for pattern in SOURCE_XSS_PATTERNS):
            indicators.append(
                _build_indicator(
                    category=ArtifactRiskCategory.REFLECTED_XSS,
                    summary="Detected direct HTML rendering or unsafe DOM sink that may enable XSS.",
                    location=location,
                    confidence=82,
                    route_method=route_method,
                    route_path=route_path,
                    tags=["html-sink", "unsafe-render"],
                )
            )

    return indicators


def _source_category_from_line(line: str) -> ArtifactRiskCategory | None:
    lowered = line.lower()
    if any(pattern.search(line) for pattern in SOURCE_SQLI_PATTERNS):
        return ArtifactRiskCategory.SQLI
    if any(pattern.search(line) for pattern in SOURCE_SSRF_PATTERNS):
        return ArtifactRiskCategory.SSRF
    if any(pattern.search(line) for pattern in SOURCE_XSS_PATTERNS):
        if "dangerouslysetinnerhtml" in lowered or "inn" in lowered or "template" in lowered:
            return ArtifactRiskCategory.REFLECTED_XSS
        return ArtifactRiskCategory.STORED_XSS
    return None


def _parse_taint_flows(content: str, routes: list[dict[str, str]]) -> list[dict[str, object]]:
    route_method = routes[0]["method"] if routes else None
    route_path = routes[0]["path"] if routes else None
    sources: list[tuple[int, str]] = []
    sinks: list[tuple[int, ArtifactRiskCategory, str]] = []

    for line_number, line in _iter_lines(content):
        if any(pattern.search(line) for pattern in INPUT_SOURCE_PATTERNS):
            sources.append((line_number, line.strip()))
        if match := FUNCTION_DEFINITION.search(line):
            parameters = [item.strip().split("=")[0].strip() for item in match.group(1).split(",") if item.strip()]
            if parameters:
                sources.append((line_number, f"route parameters: {', '.join(parameters)}"))
        sink_category = _source_category_from_line(line)
        if sink_category is not None:
            sinks.append((line_number, sink_category, line.strip()))

    taint_flows: list[dict[str, object]] = []
    for source_line, source_text in sources:
        for sink_line, sink_category, sink_text in sinks:
            if sink_line < source_line:
                continue
            taint_flows.append(
                ArtifactTaintFlowSummary(
                    category=sink_category,
                    source_summary="Detected request-derived input source",
                    source_location=f"line {source_line}",
                    sink_summary=f"Detected {sink_category.value.replace('_', ' ')} sink",
                    sink_location=f"line {sink_line}",
                    route_method=route_method,
                    route_path=route_path,
                    confidence=90 if sink_line - source_line < 12 else 78,
                    rationale="A request-derived input source appears in the same route context before a dangerous sink, suggesting taint-style exploitability.",
                    tags=["taint-flow", sink_category.value],
                ).model_dump(mode="json")
            )

    deduped: list[dict[str, object]] = []
    seen = set()
    for flow in taint_flows:
        key = (flow["category"], flow["source_location"], flow["sink_location"], flow.get("route_path"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(flow)
    return deduped


def _extract_properties(schema: object) -> set[str]:
    property_names: set[str] = set()
    if not isinstance(schema, dict):
        return property_names
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for name, value in properties.items():
            if isinstance(name, str):
                property_names.add(name)
                property_names.update(_extract_properties(value))
    items = schema.get("items")
    if isinstance(items, dict):
        property_names.update(_extract_properties(items))
    for branch_key in ("allOf", "anyOf", "oneOf"):
        branch = schema.get(branch_key)
        if isinstance(branch, list):
            for item in branch:
                property_names.update(_extract_properties(item))
    return property_names


def _parse_spec_indicators(path: str, method: str, operation: dict[str, object]) -> list[dict[str, object]]:
    indicators: list[dict[str, object]] = []
    method_upper = method.upper()
    parameters = operation.get("parameters", [])
    if isinstance(parameters, list):
        for parameter in parameters:
            if not isinstance(parameter, dict):
                continue
            name = str(parameter.get("name") or "").lower()
            if name in URL_LIKE_FIELDS:
                indicators.append(
                    _build_indicator(
                        category=ArtifactRiskCategory.SSRF,
                        summary=f"API spec exposes URL-like parameter '{name}' that may drive outbound requests.",
                        location=f"{method_upper} {path}",
                        confidence=73,
                        route_method=method_upper,
                        route_path=path,
                        tags=["spec-parameter", name],
                    )
                )
            if name in QUERY_LIKE_FIELDS:
                indicators.append(
                    _build_indicator(
                        category=ArtifactRiskCategory.SQLI,
                        summary=f"API spec exposes query-like parameter '{name}' that may be used in backend filtering or query construction.",
                        location=f"{method_upper} {path}",
                        confidence=66,
                        route_method=method_upper,
                        route_path=path,
                        tags=["spec-parameter", name],
                    )
                )
            if name in HTML_LIKE_FIELDS:
                indicators.append(
                    _build_indicator(
                        category=ArtifactRiskCategory.REFLECTED_XSS,
                        summary=f"API spec exposes content-like parameter '{name}' that may be reflected or rendered unsafely.",
                        location=f"{method_upper} {path}",
                        confidence=68,
                        route_method=method_upper,
                        route_path=path,
                        tags=["spec-parameter", name],
                    )
                )

    request_body = operation.get("requestBody")
    schema = None
    if isinstance(request_body, dict):
        content = request_body.get("content")
        if isinstance(content, dict):
            for media_type in content.values():
                if isinstance(media_type, dict) and isinstance(media_type.get("schema"), dict):
                    schema = media_type["schema"]
                    break
    property_names = _extract_properties(schema)
    if property_names & URL_LIKE_FIELDS:
        indicators.append(
            _build_indicator(
                category=ArtifactRiskCategory.SSRF,
                summary="API spec request body includes URL-like fields that may drive outbound requests.",
                location=f"{method_upper} {path}",
                confidence=74,
                route_method=method_upper,
                route_path=path,
                tags=["request-body", *sorted(property_names & URL_LIKE_FIELDS)],
            )
        )
    if property_names & QUERY_LIKE_FIELDS:
        indicators.append(
            _build_indicator(
                category=ArtifactRiskCategory.SQLI,
                summary="API spec request body includes query-like fields that may feed backend query construction.",
                location=f"{method_upper} {path}",
                confidence=67,
                route_method=method_upper,
                route_path=path,
                tags=["request-body", *sorted(property_names & QUERY_LIKE_FIELDS)],
            )
        )
    if property_names & HTML_LIKE_FIELDS:
        category = ArtifactRiskCategory.STORED_XSS if method_upper in {"POST", "PUT", "PATCH"} else ArtifactRiskCategory.REFLECTED_XSS
        indicators.append(
            _build_indicator(
                category=category,
                summary="API spec request body includes renderable HTML/content-style fields that may enable XSS if unsafely stored or reflected.",
                location=f"{method_upper} {path}",
                confidence=72,
                route_method=method_upper,
                route_path=path,
                tags=["request-body", *sorted(property_names & HTML_LIKE_FIELDS)],
            )
        )

    return indicators


def parse_source_artifact(language: str, content: str) -> dict[str, object]:
    unique_routes = _route_entries(content)
    risk_indicators = _parse_source_risk_indicators(content, unique_routes)
    taint_flows = _parse_taint_flows(content, unique_routes)
    for flow in taint_flows:
        risk_indicators.append(
            _build_indicator(
                category=ArtifactRiskCategory(flow["category"]),
                summary=f"Taint-style source-to-sink correlation for {flow['category'].replace('_', ' ')}.",
                location=f"{flow['source_location']} -> {flow['sink_location']}",
                confidence=int(flow["confidence"]),
                route_method=flow.get("route_method"),
                route_path=flow.get("route_path"),
                tags=[*flow.get("tags", []), "taint-correlation"],
            )
        )

    return {
        "language": language,
        "route_count": len(unique_routes),
        "routes": unique_routes,
        "risk_indicator_count": len(risk_indicators),
        "risk_indicators": risk_indicators,
        "taint_flow_count": len(taint_flows),
        "taint_flows": taint_flows,
    }


def parse_api_spec_artifact(format_name: str, content: str) -> dict[str, object]:
    parsed = yaml.safe_load(content)
    if not isinstance(parsed, dict):
        raise ValueError("API spec content must parse into an object.")

    paths = parsed.get("paths", {})
    route_entries: list[dict[str, str]] = []
    risk_indicators: list[dict[str, object]] = []
    if isinstance(paths, dict):
        for path, operations in paths.items():
            if not isinstance(path, str) or not isinstance(operations, dict):
                continue
            for method, operation in operations.items():
                if not isinstance(method, str):
                    continue
                if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                    continue
                summary = None
                if isinstance(operation, dict):
                    summary = operation.get("summary") or operation.get("operationId") or method.upper()
                    risk_indicators.extend(_parse_spec_indicators(path, method, operation))
                route_entries.append({"method": method.upper(), "path": path, "source": str(summary or method.upper())})

    components = parsed.get("components", {})
    auth_schemes: list[str] = []
    if isinstance(components, dict):
        security_schemes = components.get("securitySchemes", {})
        if isinstance(security_schemes, dict):
            auth_schemes = [str(key) for key in security_schemes.keys() if isinstance(key, str)]

    return {
        "format": format_name,
        "route_count": len(route_entries),
        "routes": route_entries,
        "auth_scheme_count": len(auth_schemes),
        "auth_schemes": auth_schemes,
        "risk_indicator_count": len(risk_indicators),
        "risk_indicators": risk_indicators,
        "openapi_version": parsed.get("openapi") or parsed.get("swagger"),
    }


def artifact_route_summaries(parsed_summary: dict[str, object]) -> list[ArtifactRouteSummary]:
    routes = parsed_summary.get("routes", [])
    if not isinstance(routes, list):
        return []
    return [ArtifactRouteSummary.model_validate(route) for route in routes if isinstance(route, dict)]


def build_artifact_match_references(
    *,
    artifact_id: str,
    artifact_name: str,
    kind: ArtifactKind,
    parsed_summary: dict[str, object],
    method: str,
    path: str,
) -> list[ArtifactMatchReference]:
    matches: list[ArtifactMatchReference] = []
    normalized_method = method.upper()
    for route in artifact_route_summaries(parsed_summary):
        if route.method.upper() != normalized_method:
            continue
        if route.path != path:
            continue
        indicators = []
        raw_indicators = parsed_summary.get("risk_indicators", [])
        if isinstance(raw_indicators, list):
            for raw_indicator in raw_indicators:
                if not isinstance(raw_indicator, dict):
                    continue
                route_method = raw_indicator.get("route_method")
                route_path = raw_indicator.get("route_path")
                if route_method and str(route_method).upper() != normalized_method:
                    continue
                if route_path and str(route_path) != path:
                    continue
                indicators.append(ArtifactRiskIndicatorSummary.model_validate(raw_indicator))
        matches.append(
            ArtifactMatchReference(
                kind=kind,
                artifact_id=artifact_id,
                artifact_name=artifact_name,
                route=route,
                rationale=f"Matched {normalized_method} {path} in ingested {kind.value.replace('_', ' ')} artifact {artifact_name}.",
                risk_indicators=indicators,
            )
        )
    return matches


def summarize_artifact(
    *,
    artifact_id: str,
    scan_id: str,
    kind: ArtifactKind,
    name: str,
    path: str | None,
    language: str | None,
    format_name: str | None,
    content: str,
    parsed_summary: dict[str, object],
    created_at,
    updated_at,
) -> ArtifactSummary:
    def _coerce_count(value: object) -> int:
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
        return 0

    route_count_value = parsed_summary.get("route_count", 0)
    auth_scheme_count_value = parsed_summary.get("auth_scheme_count", 0)
    risk_indicator_count_value = parsed_summary.get("risk_indicator_count", 0)
    taint_flow_count_value = parsed_summary.get("taint_flow_count", 0)
    return ArtifactSummary(
        id=artifact_id,
        scan_id=scan_id,
        kind=kind,
        name=name,
        path=path,
        language=language,
        format=format_name,
        checksum=_checksum(content),
        route_count=_coerce_count(route_count_value),
        auth_scheme_count=_coerce_count(auth_scheme_count_value),
        risk_indicator_count=_coerce_count(risk_indicator_count_value),
        taint_flow_count=_coerce_count(taint_flow_count_value),
        created_at=created_at,
        updated_at=updated_at,
    )


def content_checksum(content: str) -> str:
    return _checksum(content)


def content_excerpt(content: str) -> str:
    return _excerpt(content)


def serialize_summary(parsed_summary: dict[str, object]) -> dict[str, object]:
    json.dumps(parsed_summary)
    return parsed_summary
