from __future__ import annotations

from api.schemas.planner import VerifierStrategy, VulnerabilityClass
from api.schemas.verifier_jobs import ReplayRequestSpec
from tools.verifier.payload_library import build_payload_variants


def _requests() -> list[ReplayRequestSpec]:
    return [
        ReplayRequestSpec(
            artifact_id="artifact-one",
            request_fingerprint="fp-one",
            method="GET",
            host="qa.example.internal",
            path="/v1/projects",
            actor="partner-member",
        ),
        ReplayRequestSpec(
            artifact_id="artifact-two",
            request_fingerprint="fp-two",
            method="POST",
            host="qa.example.internal",
            path="/v1/projects/123/members",
            actor="partner-member",
        ),
        ReplayRequestSpec(
            artifact_id="artifact-three",
            request_fingerprint="fp-three",
            method="GET",
            host="qa.example.internal",
            path="/v1/projects/123/preview",
            actor="partner-member",
        ),
    ]


def test_payload_library_returns_sqli_variants() -> None:
    variants = build_payload_variants(VulnerabilityClass.SQLI, _requests())
    assert len(variants) >= 3
    assert any(variant.id == "sqli-time-query" for variant in variants)


def test_payload_library_returns_ssrf_callback_variant() -> None:
    variants = build_payload_variants(VulnerabilityClass.SSRF, _requests())
    callback_variant = next(variant for variant in variants if variant.id == "ssrf-oob-callback")
    assert callback_variant.assertions[0].callback_label == "ssrf_oob"


def test_payload_library_returns_browser_variant_for_reflected_xss() -> None:
    variants = build_payload_variants(VulnerabilityClass.REFLECTED_XSS, _requests())
    browser_variant = next(variant for variant in variants if variant.id == "reflected-xss-browser-callback")
    assert browser_variant.browser_plan is not None
    assert browser_variant.browser_plan.visits[0].callback_labels == ["reflected_xss_oob"]


def test_payload_library_returns_authz_variant() -> None:
    variants = build_payload_variants(VulnerabilityClass.BFLA, _requests())
    labels = {variant.id for variant in variants}
    assert {"bfla-actor-switch", "bfla-header-escalation"}.issubset(labels)
