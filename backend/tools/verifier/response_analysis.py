from __future__ import annotations

import re
from typing import TYPE_CHECKING

from api.schemas.callbacks import CallbackExpectationDetail
from api.schemas.verifier_jobs import ReplayAssertionSpec, ReplayAssertionType

if TYPE_CHECKING:
    from api.services.verifier_runtime_service import ReplayHttpResult


def _matches_request(assertion: ReplayAssertionSpec, result: ReplayHttpResult) -> bool:
    return assertion.target_request_fingerprint is None or assertion.target_request_fingerprint == result.request.request_fingerprint


def evaluate_assertions(
    assertions: list[ReplayAssertionSpec],
    results: list[ReplayHttpResult],
    *,
    baseline_results: dict[str, ReplayHttpResult] | None = None,
    callback_details: dict[str, CallbackExpectationDetail] | None = None,
) -> tuple[bool, list[str]]:
    if not assertions:
        return True, []

    explanation_lines: list[str] = []
    for assertion in assertions:
        matching_results = [result for result in results if _matches_request(assertion, result)]
        if not matching_results:
            explanation_lines.append(f"Assertion '{assertion.description}' could not be evaluated because no matching replay result was found.")
            return False, explanation_lines

        if assertion.type == ReplayAssertionType.BODY_CONTAINS:
            if assertion.expected_text and any(assertion.expected_text in result.body_excerpt for result in matching_results):
                explanation_lines.append(f"Assertion satisfied: {assertion.description}")
                continue
            explanation_lines.append(f"Assertion failed: expected text '{assertion.expected_text}' was not found.")
            return False, explanation_lines

        if assertion.type == ReplayAssertionType.BODY_REGEX:
            if assertion.regex_pattern and any(re.search(assertion.regex_pattern, result.body_excerpt) for result in matching_results):
                explanation_lines.append(f"Assertion satisfied: {assertion.description}")
                continue
            explanation_lines.append(f"Assertion failed: regex '{assertion.regex_pattern}' did not match the response body excerpt.")
            return False, explanation_lines

        if assertion.type == ReplayAssertionType.HEADER_CONTAINS:
            if assertion.header_name and assertion.expected_text and any(assertion.expected_text in result.response_headers.get(assertion.header_name, "") for result in matching_results):
                explanation_lines.append(f"Assertion satisfied: {assertion.description}")
                continue
            explanation_lines.append(f"Assertion failed: header '{assertion.header_name}' did not contain '{assertion.expected_text}'.")
            return False, explanation_lines

        if assertion.type == ReplayAssertionType.STATUS_IN:
            if assertion.status_codes and any(result.status_code in assertion.status_codes for result in matching_results):
                explanation_lines.append(f"Assertion satisfied: {assertion.description}")
                continue
            explanation_lines.append(f"Assertion failed: status code was not in {assertion.status_codes}.")
            return False, explanation_lines

        if assertion.type == ReplayAssertionType.DURATION_MS_GTE:
            if assertion.threshold_ms is not None and any(result.duration_ms >= assertion.threshold_ms for result in matching_results):
                explanation_lines.append(f"Assertion satisfied: {assertion.description}")
                continue
            explanation_lines.append(f"Assertion failed: response duration did not reach {assertion.threshold_ms} ms.")
            return False, explanation_lines

        if assertion.type == ReplayAssertionType.STATUS_DIFFERS_FROM_BASELINE:
            baseline_results = baseline_results or {}
            comparison = [
                (result, baseline_results.get(result.request.request_fingerprint))
                for result in matching_results
            ]
            if any(baseline is not None and baseline.status_code != result.status_code for result, baseline in comparison):
                explanation_lines.append(f"Assertion satisfied: {assertion.description}")
                continue
            explanation_lines.append("Assertion failed: mutated status did not differ from baseline status.")
            return False, explanation_lines

        if assertion.type == ReplayAssertionType.BODY_DIFFERS_FROM_BASELINE:
            baseline_results = baseline_results or {}
            comparison = [
                (result, baseline_results.get(result.request.request_fingerprint))
                for result in matching_results
            ]
            if any(baseline is not None and baseline.body_excerpt != result.body_excerpt for result, baseline in comparison):
                explanation_lines.append(f"Assertion satisfied: {assertion.description}")
                continue
            explanation_lines.append("Assertion failed: mutated response body did not differ from baseline body.")
            return False, explanation_lines

        if assertion.type == ReplayAssertionType.CALLBACK_RECEIVED:
            callback_details = callback_details or {}
            detail = callback_details.get(assertion.callback_label or "")
            if assertion.callback_label and detail is not None and detail.status.value == "received":
                explanation_lines.append(f"Assertion satisfied: {assertion.description}")
                continue
            explanation_lines.append(f"Assertion failed: callback '{assertion.callback_label}' was not received.")
            return False, explanation_lines

        if assertion.type == ReplayAssertionType.CALLBACK_METADATA_SCORE_GTE:
            callback_details = callback_details or {}
            detail = callback_details.get(assertion.callback_label or "")
            if detail is not None and detail.events and assertion.threshold_ms is not None:
                best_score = max(event.analysis.metadata_score for event in detail.events)
                if best_score >= assertion.threshold_ms:
                    explanation_lines.append(f"Assertion satisfied: {assertion.description}")
                    continue
            explanation_lines.append(f"Assertion failed: callback '{assertion.callback_label}' metadata score was below the threshold.")
            return False, explanation_lines

        if assertion.type == ReplayAssertionType.CALLBACK_SOURCE_CLASS_IN:
            callback_details = callback_details or {}
            detail = callback_details.get(assertion.callback_label or "")
            if detail is not None and detail.events and assertion.source_classes:
                observed = {event.analysis.source_classification for event in detail.events}
                if any(source_class in observed for source_class in assertion.source_classes):
                    explanation_lines.append(f"Assertion satisfied: {assertion.description}")
                    continue
            explanation_lines.append(f"Assertion failed: callback '{assertion.callback_label}' did not match the expected source classification.")
            return False, explanation_lines

    return True, explanation_lines
