from __future__ import annotations

import hashlib
import json
import re

import yaml

from api.schemas.artifacts import ArtifactMatchReference, ArtifactRouteSummary, ArtifactSummary, ArtifactKind

FASTAPI_DECORATOR = re.compile(r"@(app|router)\.(get|post|put|patch|delete|options|head)\(\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
EXPRESS_ROUTE = re.compile(r"(?<!@)\b(app|router)\.(get|post|put|patch|delete|options|head)\(\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
FLASK_ROUTE = re.compile(r"@(?:app|blueprint)\.route\(\s*[\"']([^\"']+)[\"'](?:,\s*methods\s*=\s*\[([^\]]+)\])?", re.IGNORECASE)


def _checksum(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _excerpt(value: str, *, limit: int = 2000) -> str:
    compact = value.strip()
    return compact[:limit]


def parse_source_artifact(language: str, content: str) -> dict[str, object]:
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

    return {
        "language": language,
        "route_count": len(unique_routes),
        "routes": unique_routes,
    }


def parse_api_spec_artifact(format_name: str, content: str) -> dict[str, object]:
    parsed = yaml.safe_load(content)
    if not isinstance(parsed, dict):
        raise ValueError("API spec content must parse into an object.")

    paths = parsed.get("paths", {})
    route_entries: list[dict[str, str]] = []
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
        matches.append(
            ArtifactMatchReference(
                kind=kind,
                artifact_id=artifact_id,
                artifact_name=artifact_name,
                route=route,
                rationale=f"Matched {normalized_method} {path} in ingested {kind.value.replace('_', ' ')} artifact {artifact_name}.",
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
