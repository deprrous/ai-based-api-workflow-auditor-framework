from __future__ import annotations

from api.schemas.callbacks import CallbackSourceClass
from api.schemas.planner import VulnerabilityClass
from api.schemas.verifier_jobs import (
    BrowserPlan,
    BrowserVisitSpec,
    ReplayAssertionSpec,
    ReplayAssertionType,
    ReplayMutationSpec,
    ReplayMutationType,
    ReplayPayloadVariant,
    ReplayRequestSpec,
)


def _final_request(requests: list[ReplayRequestSpec]) -> ReplayRequestSpec:
    return requests[-1]


def _base_browser_plan(request: ReplayRequestSpec, *, callback_label: str) -> BrowserPlan:
    return BrowserPlan(
        visits=[
            BrowserVisitSpec(
                path=request.path,
                actor=request.actor,
                wait_seconds=2,
                callback_labels=[callback_label],
            )
        ]
    )


def build_payload_variants(
    vulnerability_class: VulnerabilityClass,
    replay_requests: list[ReplayRequestSpec],
) -> list[ReplayPayloadVariant]:
    final_request = _final_request(replay_requests)

    if vulnerability_class == VulnerabilityClass.SQLI:
        return [
            ReplayPayloadVariant(
                id="sqli-error-query",
                label="Error-based SQLi via query parameter",
                description="Inject a classic quote-breaking payload into query-style parameters and look for SQL errors.",
                mutations=[
                    ReplayMutationSpec(
                        type=ReplayMutationType.QUERY_SET,
                        target_request_fingerprint=final_request.request_fingerprint,
                        query_param="q",
                        value="' OR '1'='1' --",
                    )
                ],
                assertions=[
                    ReplayAssertionSpec(
                        type=ReplayAssertionType.BODY_REGEX,
                        target_request_fingerprint=final_request.request_fingerprint,
                        description="Error-based SQLi should return a database-style error string.",
                        regex_pattern=r"(?i)(sql syntax|mysql|postgres|sqlite|unterminated quoted string|syntax error)",
                    )
                ],
            ),
            ReplayPayloadVariant(
                id="sqli-time-query",
                label="Time-based SQLi via query parameter",
                description="Inject a sleep-based payload to detect time-driven SQL execution.",
                mutations=[
                    ReplayMutationSpec(
                        type=ReplayMutationType.QUERY_SET,
                        target_request_fingerprint=final_request.request_fingerprint,
                        query_param="q",
                        value="' OR pg_sleep(3)--",
                    )
                ],
                assertions=[
                    ReplayAssertionSpec(
                        type=ReplayAssertionType.DURATION_MS_GTE,
                        target_request_fingerprint=final_request.request_fingerprint,
                        description="Time-based SQLi payload should delay the response.",
                        threshold_ms=2500,
                    )
                ],
            ),
            ReplayPayloadVariant(
                id="sqli-body-union",
                label="Body-based SQLi via JSON field",
                description="Inject a UNION-style payload into request bodies that look query-driven.",
                mutations=[
                    ReplayMutationSpec(
                        type=ReplayMutationType.BODY_JSON_SET,
                        target_request_fingerprint=final_request.request_fingerprint,
                        body_field="query",
                        value="' UNION SELECT 1 --",
                    )
                ],
                assertions=[
                    ReplayAssertionSpec(
                        type=ReplayAssertionType.BODY_REGEX,
                        target_request_fingerprint=final_request.request_fingerprint,
                        description="Body-based SQLi should leak a database error or query parsing fault.",
                        regex_pattern=r"(?i)(sql syntax|query failed|database error|sqlite|postgres)",
                    )
                ],
            ),
        ]

    if vulnerability_class == VulnerabilityClass.SSRF:
        return [
            ReplayPayloadVariant(
                id="ssrf-metadata-query",
                label="Cloud metadata SSRF via query URL",
                description="Point a URL parameter to cloud metadata and look for metadata indicators.",
                mutations=[
                    ReplayMutationSpec(
                        type=ReplayMutationType.QUERY_SET,
                        target_request_fingerprint=final_request.request_fingerprint,
                        query_param="url",
                        value="http://169.254.169.254/latest/meta-data/",
                    )
                ],
                assertions=[
                    ReplayAssertionSpec(
                        type=ReplayAssertionType.BODY_REGEX,
                        target_request_fingerprint=final_request.request_fingerprint,
                        description="Metadata SSRF should expose cloud metadata markers in the response.",
                        regex_pattern=r"(?i)(instance-id|ami-id|latest/meta-data|metadata-flavor)",
                    )
                ],
            ),
            ReplayPayloadVariant(
                id="ssrf-loopback-query",
                label="Loopback SSRF via query URL",
                description="Point a URL parameter at loopback targets and wait for OOB evidence or metadata signals.",
                mutations=[
                    ReplayMutationSpec(
                        type=ReplayMutationType.QUERY_SET,
                        target_request_fingerprint=final_request.request_fingerprint,
                        query_param="url",
                        value="http://127.0.0.1:80/",
                    )
                ],
                assertions=[
                    ReplayAssertionSpec(
                        type=ReplayAssertionType.BODY_REGEX,
                        target_request_fingerprint=final_request.request_fingerprint,
                        description="Loopback SSRF should leak loopback-style indicators.",
                        regex_pattern=r"(?i)(127\.0\.0\.1|localhost|connection refused|nginx|apache)",
                    )
                ],
            ),
            ReplayPayloadVariant(
                id="ssrf-oob-callback",
                label="Out-of-band SSRF callback",
                description="Use a framework callback URL to confirm blind SSRF through an external callback hit.",
                mutations=[
                    ReplayMutationSpec(
                        type=ReplayMutationType.QUERY_SET,
                        target_request_fingerprint=final_request.request_fingerprint,
                        query_param="url",
                        value="{{callback_url:ssrf_oob}}",
                    )
                ],
                assertions=[
                    ReplayAssertionSpec(
                        type=ReplayAssertionType.CALLBACK_RECEIVED,
                        target_request_fingerprint=final_request.request_fingerprint,
                        description="Blind SSRF should trigger an out-of-band callback.",
                        callback_label="ssrf_oob",
                        wait_seconds=2,
                    ),
                    ReplayAssertionSpec(
                        type=ReplayAssertionType.CALLBACK_SOURCE_CLASS_IN,
                        target_request_fingerprint=final_request.request_fingerprint,
                        description="SSRF callback should come from a non-public target or controlled probe path.",
                        callback_label="ssrf_oob",
                        source_classes=[CallbackSourceClass.PRIVATE, CallbackSourceClass.LOOPBACK, CallbackSourceClass.LINK_LOCAL, CallbackSourceClass.PUBLIC],
                        wait_seconds=2,
                    ),
                ],
            ),
        ]

    if vulnerability_class == VulnerabilityClass.STORED_XSS:
        return [
            ReplayPayloadVariant(
                id="stored-xss-script-tag",
                label="Stored XSS script marker",
                description="Store a script-like marker and confirm later retrieval contains the payload.",
                mutations=[
                    ReplayMutationSpec(
                        type=ReplayMutationType.BODY_JSON_SET,
                        target_request_fingerprint=final_request.request_fingerprint,
                        body_field="content",
                        value="<script>auditor-stored-xss-marker</script>",
                    )
                ],
                assertions=[
                    ReplayAssertionSpec(
                        type=ReplayAssertionType.BODY_CONTAINS,
                        target_request_fingerprint=final_request.request_fingerprint,
                        description="Stored XSS marker should be visible when the content is read back.",
                        expected_text="auditor-stored-xss-marker",
                    )
                ],
            ),
            ReplayPayloadVariant(
                id="stored-xss-browser-callback",
                label="Stored XSS browser callback",
                description="Store a browser-callback payload and confirm a later browser visit triggers the callback.",
                mutations=[
                    ReplayMutationSpec(
                        type=ReplayMutationType.BODY_JSON_SET,
                        target_request_fingerprint=final_request.request_fingerprint,
                        body_field="content",
                        value="{{xss_callback:stored_xss_oob}}",
                    )
                ],
                assertions=[
                    ReplayAssertionSpec(
                        type=ReplayAssertionType.CALLBACK_RECEIVED,
                        target_request_fingerprint=final_request.request_fingerprint,
                        description="Stored XSS should trigger a browser callback after rendering.",
                        callback_label="stored_xss_oob",
                        wait_seconds=2,
                    )
                ],
                browser_plan=_base_browser_plan(final_request, callback_label="stored_xss_oob"),
            ),
        ]

    if vulnerability_class == VulnerabilityClass.REFLECTED_XSS:
        return [
            ReplayPayloadVariant(
                id="reflected-xss-marker",
                label="Reflected XSS marker",
                description="Inject a reflected marker and look for it in the same response body.",
                mutations=[
                    ReplayMutationSpec(
                        type=ReplayMutationType.QUERY_SET,
                        target_request_fingerprint=final_request.request_fingerprint,
                        query_param="q",
                        value="auditor-reflected-xss-marker",
                    )
                ],
                assertions=[
                    ReplayAssertionSpec(
                        type=ReplayAssertionType.BODY_CONTAINS,
                        target_request_fingerprint=final_request.request_fingerprint,
                        description="Reflected XSS marker should appear in the response body.",
                        expected_text="auditor-reflected-xss-marker",
                    )
                ],
            ),
            ReplayPayloadVariant(
                id="reflected-xss-browser-callback",
                label="Reflected XSS browser callback",
                description="Inject a browser-callback payload and confirm it triggers when rendered in a browser context.",
                mutations=[
                    ReplayMutationSpec(
                        type=ReplayMutationType.QUERY_SET,
                        target_request_fingerprint=final_request.request_fingerprint,
                        query_param="q",
                        value="{{xss_callback:reflected_xss_oob}}",
                    )
                ],
                assertions=[
                    ReplayAssertionSpec(
                        type=ReplayAssertionType.CALLBACK_RECEIVED,
                        target_request_fingerprint=final_request.request_fingerprint,
                        description="Reflected XSS should trigger a browser callback when rendered.",
                        callback_label="reflected_xss_oob",
                        wait_seconds=2,
                    )
                ],
                browser_plan=_base_browser_plan(final_request, callback_label="reflected_xss_oob"),
            ),
        ]

    if vulnerability_class == VulnerabilityClass.BOLA_IDOR:
        return [
            ReplayPayloadVariant(
                id="bola-direct-object",
                label="Direct object ID replay",
                description="Swap the terminal object id and compare the response against the baseline actor.",
                mutations=[
                    ReplayMutationSpec(
                        type=ReplayMutationType.PATH_REPLACE,
                        target_request_fingerprint=final_request.request_fingerprint,
                        from_value="123",
                        to_value="999999",
                    )
                ],
                assertions=[
                    ReplayAssertionSpec(
                        type=ReplayAssertionType.STATUS_DIFFERS_FROM_BASELINE,
                        target_request_fingerprint=final_request.request_fingerprint,
                        description="IDOR replay should change the authorization outcome or resource response.",
                    )
                ],
            )
        ]

    if vulnerability_class == VulnerabilityClass.BFLA:
        return [
            ReplayPayloadVariant(
                id="bfla-actor-switch",
                label="Low-privilege actor replay",
                description="Switch to a lower-privilege actor and compare privileged endpoint behavior.",
                mutations=[
                    ReplayMutationSpec(
                        type=ReplayMutationType.ACTOR_SWITCH,
                        target_request_fingerprint=final_request.request_fingerprint,
                        actor="low-privilege-actor",
                    )
                ],
                assertions=[
                    ReplayAssertionSpec(
                        type=ReplayAssertionType.STATUS_DIFFERS_FROM_BASELINE,
                        target_request_fingerprint=final_request.request_fingerprint,
                        description="Low-privilege actor should not retain the same endpoint access as baseline.",
                    )
                ],
            ),
            ReplayPayloadVariant(
                id="bfla-header-escalation",
                label="Privilege header override replay",
                description="Inject a permission override header and observe whether the server trusts caller-controlled role state.",
                mutations=[
                    ReplayMutationSpec(
                        type=ReplayMutationType.HEADER_SET,
                        target_request_fingerprint=final_request.request_fingerprint,
                        header_name="X-Permission-Override",
                        value="admin",
                    )
                ],
                assertions=[
                    ReplayAssertionSpec(
                        type=ReplayAssertionType.BODY_DIFFERS_FROM_BASELINE,
                        target_request_fingerprint=final_request.request_fingerprint,
                        description="Caller-controlled privilege headers should not change the response behavior.",
                    )
                ],
            ),
        ]

    if vulnerability_class == VulnerabilityClass.MASS_ASSIGNMENT:
        return [
            ReplayPayloadVariant(
                id="mass-assignment-role",
                label="Mass assignment role field",
                description="Set a role field directly in the request body to test unsafe writable model fields.",
                mutations=[
                    ReplayMutationSpec(
                        type=ReplayMutationType.BODY_JSON_SET,
                        target_request_fingerprint=final_request.request_fingerprint,
                        body_field="role",
                        value="admin",
                    )
                ],
                assertions=[
                    ReplayAssertionSpec(
                        type=ReplayAssertionType.BODY_DIFFERS_FROM_BASELINE,
                        target_request_fingerprint=final_request.request_fingerprint,
                        description="Mass-assignment role changes should alter the response or authorization behavior if exploitable.",
                    )
                ],
            ),
            ReplayPayloadVariant(
                id="mass-assignment-permissions",
                label="Mass assignment permissions array",
                description="Inject a permissions array to test broad privilege mutation through request bodies.",
                mutations=[
                    ReplayMutationSpec(
                        type=ReplayMutationType.BODY_JSON_SET,
                        target_request_fingerprint=final_request.request_fingerprint,
                        body_field="permissions",
                        value=["admin"],
                    )
                ],
                assertions=[
                    ReplayAssertionSpec(
                        type=ReplayAssertionType.BODY_DIFFERS_FROM_BASELINE,
                        target_request_fingerprint=final_request.request_fingerprint,
                        description="Permission array injection should not change the server response if mass assignment is safely handled.",
                    )
                ],
            ),
        ]

    if vulnerability_class == VulnerabilityClass.EXCESSIVE_DATA_EXPOSURE:
        return [
            ReplayPayloadVariant(
                id="data-exposure-baseline",
                label="Sensitive read replay",
                description="Replay the sensitive read path and inspect the response body for overexposed data markers.",
                mutations=[],
                assertions=[
                    ReplayAssertionSpec(
                        type=ReplayAssertionType.BODY_REGEX,
                        target_request_fingerprint=final_request.request_fingerprint,
                        description="Sensitive read replay should expose key, token, billing, or secret-style markers when excessive data is returned.",
                        regex_pattern=r"(?i)(secret|token|api[_-]?key|invoice|billing|permission|role)",
                    )
                ],
            )
        ]

    if vulnerability_class == VulnerabilityClass.UNSAFE_DESTRUCTIVE_ACTION:
        return [
            ReplayPayloadVariant(
                id="destructive-confirmation-bypass",
                label="Destructive confirmation bypass",
                description="Inject a destructive-action confirmation header to test whether the endpoint trusts caller-controlled confirmation state.",
                mutations=[
                    ReplayMutationSpec(
                        type=ReplayMutationType.HEADER_SET,
                        target_request_fingerprint=final_request.request_fingerprint,
                        header_name="X-Confirm-Destructive-Action",
                        value="true",
                    )
                ],
                assertions=[
                    ReplayAssertionSpec(
                        type=ReplayAssertionType.STATUS_IN,
                        target_request_fingerprint=final_request.request_fingerprint,
                        description="Unsafe destructive action may succeed when only caller-controlled confirmation is required.",
                        status_codes=[200, 202, 204],
                    )
                ],
            )
        ]

    return []
