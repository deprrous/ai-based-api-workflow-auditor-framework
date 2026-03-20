from __future__ import annotations

import hashlib
import ipaddress
import re

from api.schemas.callbacks import CallbackEventAnalysis, CallbackSourceClass

METADATA_MARKERS = {
    "latest/meta-data": 35,
    "instance-id": 30,
    "ami-id": 25,
    "metadata-flavor": 20,
    "metadata/instance": 25,
    "computeMetadata": 20,
    "169.254.169.254": 30,
    "kubernetes.default.svc": 20,
    "serviceaccount": 15,
    "localhost": 15,
    "127.0.0.1": 15,
}


def classify_source_ip(source_ip: str | None) -> CallbackSourceClass:
    if not source_ip:
        return CallbackSourceClass.UNKNOWN
    try:
        ip = ipaddress.ip_address(source_ip)
    except ValueError:
        return CallbackSourceClass.UNKNOWN

    if ip.is_loopback:
        return CallbackSourceClass.LOOPBACK
    if ip.is_link_local:
        return CallbackSourceClass.LINK_LOCAL
    if ip.is_private:
        return CallbackSourceClass.PRIVATE
    if ip.is_reserved:
        return CallbackSourceClass.RESERVED
    return CallbackSourceClass.PUBLIC


def build_callback_fingerprint(*, method: str, path: str, query_string: str | None, body_excerpt: str | None, user_agent: str | None) -> str:
    basis = "|".join([method.upper(), path, query_string or "", body_excerpt or "", user_agent or ""])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def analyze_callback_event(
    *,
    method: str,
    path: str,
    query_string: str | None,
    headers: dict[str, str],
    body_excerpt: str | None,
    source_ip: str | None,
    user_agent: str | None,
) -> CallbackEventAnalysis:
    source_class = classify_source_ip(source_ip)
    haystack = " ".join(
        [
            method,
            path,
            query_string or "",
            body_excerpt or "",
            user_agent or "",
            *[f"{key}:{value}" for key, value in headers.items()],
        ]
    )
    lowered = haystack.lower()
    matched_markers = [marker for marker in METADATA_MARKERS if marker.lower() in lowered]
    metadata_score = min(100, sum(METADATA_MARKERS[marker] for marker in matched_markers))
    browser_like = bool(re.search(r"(?i)(mozilla|chrome|chromium|safari|headless|playwright)", user_agent or ""))
    return CallbackEventAnalysis(
        fingerprint=build_callback_fingerprint(
            method=method,
            path=path,
            query_string=query_string,
            body_excerpt=body_excerpt,
            user_agent=user_agent,
        ),
        source_classification=source_class,
        metadata_score=metadata_score,
        matched_markers=matched_markers,
        browser_like=browser_like,
    )
