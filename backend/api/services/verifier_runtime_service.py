from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
import hashlib
import json
import time
from typing import Callable, Protocol
from urllib import parse
import re

import httpx

from api.app.config import Settings
from api.schemas.events import EventSeverity, EventSource, RecordScanEventRequest
from api.schemas.callbacks import CallbackExpectationDetail, CallbackExpectationStatus, CallbackKind
from api.schemas.findings import FindingEvidence, FindingSeverity
from api.schemas.replay_artifacts import ReplayArtifactMaterial
from api.schemas.verifier_jobs import (
    BrowserPlan,
    BrowserVisitSpec,
    ReplayPayloadVariant,
    ReplayAssertionSpec,
    ReplayAssertionType,
    ReplayMutationSpec,
    ReplayMutationType,
    ReplayPlan,
    ReplayRefreshRequestSpec,
    ReplayRequestSpec,
)
from api.schemas.verifier_jobs import ClaimVerifierJobRequest, CompleteVerifierJobRequest, FailVerifierJobRequest, VerifierJobDetail
from api.services.event_service import event_service
from api.services.callback_service import callback_service
from api.services.replay_artifact_service import replay_artifact_service
from api.services.verifier_job_service import verifier_job_service
from tools.verifier.browser_execution import BrowserExecutor, PlaywrightBrowserExecutor
from tools.verifier.response_analysis import evaluate_assertions
from tools.verifier.worker import VerifierReplayResult, build_ingest_request


def _stable_suffix(value: str, *, length: int = 12) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest()[:length]


def _category_from_job(job: VerifierJobDetail) -> str:
    lowered = f"{job.title} {job.rationale}".lower()
    if "delete" in lowered or "admin" in lowered or "role" in lowered:
        return "bfla"
    if "key" in lowered or "secret" in lowered or "tenant" in lowered:
        return "tenant_isolation"
    return "business_logic"


def _endpoint_from_job(job: VerifierJobDetail) -> str | None:
    for node in reversed(job.payload.workflow_nodes):
        if node.type in {"endpoint", "action"}:
            return node.label
    return None


class VerifierJobExecutor(Protocol):
    def execute(self, job: VerifierJobDetail) -> VerifierExecutionOutcome: ...


@dataclass(frozen=True, slots=True)
class VerifierExecutionOutcome:
    confirmed: bool
    replay_result: VerifierReplayResult | None
    note: str


@dataclass(frozen=True, slots=True)
class ReplayHttpResult:
    request: ReplayRequestSpec
    url: str
    status_code: int
    body_excerpt: str
    response_headers: dict[str, str]
    duration_ms: int


@dataclass(frozen=True, slots=True)
class DeterministicDevVerifierExecutor:
    def execute(self, job: VerifierJobDetail) -> VerifierExecutionOutcome:
        endpoint = _endpoint_from_job(job)
        status_code = 204 if endpoint and endpoint.startswith("DELETE ") else 200
        result = VerifierReplayResult(
            verifier_run_id=f"verify-{job.id}",
            scan_id=job.scan_id,
            finding_id=f"finding-{job.id}",
            title=job.title,
            category=_category_from_job(job),
            severity=job.severity,
            confidence=92 if job.severity == FindingSeverity.CRITICAL else 84,
            endpoint=endpoint,
            actor=(job.payload.replay_plan.actor if job.payload.replay_plan else None) or (job.payload.workflow_nodes[0].label if job.payload.workflow_nodes else None),
            request_fingerprint=f"auto-{_stable_suffix(job.source_path_id)}",
            request_summary=f"Deterministic dev executor processed queued path {job.source_path_id}.",
            response_status_code=status_code,
            message=f"Automatic verifier worker confirmed queued job {job.id}.",
            impact_summary=f"Auto-run verifier marked the queued path '{job.title}' as confirmed for development workflow testing.",
            remediation_summary="Replace the deterministic development executor with a real replay executor before production usage.",
            description=(
                "The deterministic development executor converted a queued verifier job into a confirmed replay result. "
                "This is intended to exercise the backend orchestration pipeline, not to represent a production-grade exploit engine."
            ),
            impact="The queued path remains high-risk and should be re-verified by a real replay executor before being trusted in production.",
            remediation="Attach a real replay backend and keep deterministic development execution disabled outside local testing.",
            workflow_node_ids=list(job.payload.workflow_node_ids),
            evidence=[
                FindingEvidence(
                    label="Deterministic executor output",
                    detail=(
                        f"The backend auto-runner processed verifier job {job.id} for path {job.source_path_id} "
                        f"and produced a development confirmation artifact."
                    ),
                    source="verifier",
                )
            ],
            tags=["dev-autorun", job.severity.value, *{node.phase for node in job.payload.workflow_nodes}],
        )
        return VerifierExecutionOutcome(
            confirmed=True,
            replay_result=result,
            note="Deterministic development executor confirmed the queued verifier job.",
        )


def _response_excerpt(text: str, *, limit: int = 240) -> str:
    compact = " ".join(text.split())
    return compact[:limit]


def _evidence_label(method: str, path: str, *, limit: int = 96) -> str:
    compact_path = path if len(path) <= limit else f"{path[: limit - 3]}..."
    return f"Replay {method.upper()} {compact_path}"


def _request_url(base_url: str | None, request_spec: ReplayRequestSpec) -> str:
    if request_spec.path.startswith("http://") or request_spec.path.startswith("https://"):
        return request_spec.path
    if base_url:
        return f"{base_url.rstrip('/')}{request_spec.path}"
    return f"https://{request_spec.host}{request_spec.path}"


def _decode_body(base64_value: str | None) -> bytes | None:
    if not base64_value:
        return None
    return base64.b64decode(base64_value.encode("ascii"))


def _merge_headers(base_headers: dict[str, str], override_headers: dict[str, str]) -> dict[str, str]:
    merged = {key: value for key, value in base_headers.items() if key.lower() not in {"host", "content-length"}}
    merged.update({key: value for key, value in override_headers.items() if key.lower() != "host"})
    return merged


def _default_http_transport(
    request_spec: ReplayRequestSpec,
    *,
    base_url: str | None,
    timeout_seconds: float,
    verify_tls: bool,
    headers: dict[str, str],
    body: bytes | None,
) -> ReplayHttpResult:
    url = _request_url(base_url, request_spec)
    started_at = time.monotonic()
    response = httpx.request(
        request_spec.method.upper(),
        url,
        headers=headers,
        content=body,
        timeout=timeout_seconds,
        verify=verify_tls,
        follow_redirects=True,
    )
    return ReplayHttpResult(
        request=request_spec,
        url=str(response.url),
        status_code=response.status_code,
        body_excerpt=_response_excerpt(response.text),
        response_headers={str(key): str(value) for key, value in response.headers.items()},
        duration_ms=int((time.monotonic() - started_at) * 1000),
    )


def _normalize_header_keys(headers: dict[str, str]) -> dict[str, str]:
    return {str(key): str(value) for key, value in headers.items()}


def _apply_set_cookie(dynamic_headers: dict[str, str], response_headers: dict[str, str]) -> None:
    cookie_header = None
    for key, value in response_headers.items():
        if key.lower() == "set-cookie":
            cookie_header = value
            break
    if cookie_header is None:
        return

    cookie_pairs = []
    for part in cookie_header.split(","):
        cookie = part.split(";", maxsplit=1)[0].strip()
        if cookie:
            cookie_pairs.append(cookie)
    if cookie_pairs:
        dynamic_headers["Cookie"] = "; ".join(cookie_pairs)


def _browser_base_url(base_url: str | None) -> str:
    if not base_url:
        raise RuntimeError("A replay base URL is required for headless browser verification.")
    split = parse.urlsplit(base_url)
    if split.scheme and split.netloc:
        return f"{split.scheme}://{split.netloc}"
    return base_url


def _set_json_path(document: dict[str, object], dotted_path: str, value: object) -> None:
    segments = [segment for segment in dotted_path.split(".") if segment]
    if not segments:
        return
    current: dict[str, object] = document
    for segment in segments[:-1]:
        next_value = current.get(segment)
        if not isinstance(next_value, dict):
            next_value = {}
            current[segment] = next_value
        current = next_value
    current[segments[-1]] = value


def _set_query_param(path: str, query_param: str, value: object) -> str:
    split = parse.urlsplit(path)
    params = parse.parse_qs(split.query, keep_blank_values=True)
    params[query_param] = [str(value)]
    updated_query = parse.urlencode(params, doseq=True)
    return parse.urlunsplit((split.scheme, split.netloc, split.path, updated_query, split.fragment)) if split.scheme else (
        f"{split.path}?{updated_query}" if updated_query else split.path
    )


CALLBACK_URL_PLACEHOLDER = re.compile(r"^\{\{callback_url:([a-zA-Z0-9._-]+)\}\}$")
XSS_CALLBACK_PLACEHOLDER = re.compile(r"^\{\{xss_callback:([a-zA-Z0-9._-]+)\}\}$")


def _resolve_dynamic_value(value: object, callback_urls: dict[str, str]) -> object:
    if not isinstance(value, str):
        return value
    if match := CALLBACK_URL_PLACEHOLDER.match(value):
        return callback_urls.get(match.group(1), value)
    if match := XSS_CALLBACK_PLACEHOLDER.match(value):
        callback_url = callback_urls.get(match.group(1), "")
        if not callback_url:
            return value
        return f'<img src="{callback_url}" style="display:none" />auditor-{match.group(1)}'
    return value


def _apply_mutations(
    request_spec: ReplayRequestSpec,
    *,
    plan_actor: str | None,
    path: str,
    headers: dict[str, str],
    body: bytes | None,
    mutations: list[ReplayMutationSpec],
    callback_urls: dict[str, str],
) -> tuple[str, dict[str, str], bytes | None, str | None]:
    updated_path = path
    updated_headers = dict(headers)
    updated_body = body
    request_actor = request_spec.actor or plan_actor

    for mutation in mutations:
        if mutation.target_request_fingerprint is not None and mutation.target_request_fingerprint != request_spec.request_fingerprint:
            continue

        if mutation.type == ReplayMutationType.PATH_REPLACE and mutation.from_value and mutation.to_value:
            updated_path = updated_path.replace(mutation.from_value, mutation.to_value)
        elif mutation.type == ReplayMutationType.QUERY_SET and mutation.query_param:
            updated_path = _set_query_param(updated_path, mutation.query_param, _resolve_dynamic_value(mutation.value, callback_urls))
        elif mutation.type == ReplayMutationType.HEADER_SET and mutation.header_name:
            resolved_value = _resolve_dynamic_value(mutation.value if mutation.value is not None else mutation.to_value or "", callback_urls)
            updated_headers[mutation.header_name] = str(resolved_value)
        elif mutation.type == ReplayMutationType.ACTOR_SWITCH and mutation.actor:
            request_actor = mutation.actor
        elif mutation.type == ReplayMutationType.BODY_JSON_SET and mutation.body_field:
            try:
                parsed = json.loads(updated_body.decode("utf-8")) if updated_body else {}
                if not isinstance(parsed, dict):
                    parsed = {}
            except Exception:
                parsed = {}
            _set_json_path(parsed, mutation.body_field, _resolve_dynamic_value(mutation.value, callback_urls))
            updated_body = json.dumps(parsed, ensure_ascii=True).encode("utf-8")
            updated_headers.setdefault("Content-Type", "application/json")

    return updated_path, updated_headers, updated_body, request_actor


def _build_refresh_request_spec(refresh_request: ReplayRefreshRequestSpec) -> ReplayRequestSpec:
    return ReplayRequestSpec(
        request_fingerprint=f"refresh:{refresh_request.method.upper()}:{refresh_request.path}",
        method=refresh_request.method,
        host=refresh_request.host,
        path=refresh_request.path,
        actor=refresh_request.actor,
    )


@dataclass(frozen=True, slots=True)
class HttpReplayVerifierExecutor:
    base_url: str | None
    actor_headers: dict[str, dict[str, str]]
    timeout_seconds: float = 5.0
    verify_tls: bool = True
    transport: Callable[..., ReplayHttpResult] = _default_http_transport
    browser_executor: BrowserExecutor | None = None

    def _artifact_for_request(self, request_spec: ReplayRequestSpec) -> ReplayArtifactMaterial | None:
        if request_spec.artifact_id is None:
            return None
        return replay_artifact_service.get_replay_artifact_material(request_spec.artifact_id)

    def execute(self, job: VerifierJobDetail) -> VerifierExecutionOutcome:
        replay_plan = self._normalized_replay_plan(job.payload.replay_plan)
        if replay_plan is None or not replay_plan.requests:
            return VerifierExecutionOutcome(
                confirmed=False,
                replay_result=None,
                note="No replay plan is attached to the verifier job.",
            )
        variants = replay_plan.variants or [
            ReplayPayloadVariant(
                id="default",
                label="Default replay",
                description="Use the base replay plan mutations and assertions.",
                mutations=list(replay_plan.mutations),
                assertions=list(replay_plan.assertions),
                browser_plan=replay_plan.browser_plan,
            )
        ]

        variant_failures: list[str] = []
        for variant in variants:
            outcome = self._execute_variant(job, replay_plan, variant)
            if outcome.confirmed:
                return outcome
            variant_failures.append(f"{variant.id}: {outcome.note}")

        return VerifierExecutionOutcome(
            confirmed=False,
            replay_result=None,
            note=" | ".join(variant_failures) if variant_failures else "Replay variants did not confirm the path.",
        )

    def _execute_variant(
        self,
        job: VerifierJobDetail,
        replay_plan: ReplayPlan,
        variant: ReplayPayloadVariant,
    ) -> VerifierExecutionOutcome:
        callback_context = self._prepare_callback_context(job, variant=variant)
        callback_urls = {label: expectation.callback_url for label, expectation in callback_context.items()}
        default_actor = replay_plan.actor or (replay_plan.requests[-1].actor if replay_plan.requests else None)
        dynamic_headers: dict[str, str] = {}
        response_results: list[ReplayHttpResult] = []
        baseline_results: dict[str, ReplayHttpResult] = {}
        for request_spec in replay_plan.requests:
            artifact = self._artifact_for_request(request_spec)
            if request_spec.artifact_id is not None and artifact is not None and not artifact.replayable:
                return VerifierExecutionOutcome(
                    confirmed=False,
                    replay_result=None,
                    note=(
                        f"Replay artifact {artifact.id} expired under retention policy before the verifier job could be replayed."
                    ),
                )
            if request_spec.artifact_id is not None and artifact is None:
                return VerifierExecutionOutcome(
                    confirmed=False,
                    replay_result=None,
                    note=(
                        f"Replay artifact {request_spec.artifact_id} is missing for request fingerprint {request_spec.request_fingerprint}."
                    ),
                )

            baseline_result, response_result = self._execute_request(
                request_spec,
                artifact=artifact,
                plan_actor=default_actor,
                mutations=variant.mutations,
                dynamic_headers=dynamic_headers,
                callback_urls=callback_urls,
            )
            if response_result.status_code in replay_plan.refresh_on_status_codes and replay_plan.refresh_requests and replay_plan.retry_after_refresh:
                refresh_succeeded = self._execute_refresh_requests(
                    replay_plan.refresh_requests,
                    plan_actor=default_actor,
                    dynamic_headers=dynamic_headers,
                )
                if refresh_succeeded:
                    baseline_result, response_result = self._execute_request(
                        request_spec,
                        artifact=artifact,
                        plan_actor=default_actor,
                        mutations=variant.mutations,
                        dynamic_headers=dynamic_headers,
                        callback_urls=callback_urls,
                    )

            response_results.append(response_result)
            if baseline_result is not None:
                baseline_results[response_result.request.request_fingerprint] = baseline_result
            _apply_set_cookie(dynamic_headers, response_result.response_headers)
        self._run_browser_plan(variant.browser_plan, callback_context=callback_context, dynamic_headers=dynamic_headers, default_actor=default_actor)
        final_result = response_results[-1]
        assertions_passed, assertion_explanations = evaluate_assertions(
            variant.assertions,
            response_results,
            baseline_results=baseline_results,
            callback_details=self._collect_callback_assertion_results(variant.assertions, callback_context=callback_context),
        )
        if variant.assertions and not assertions_passed:
            return VerifierExecutionOutcome(
                confirmed=False,
                replay_result=None,
                note=" ".join(assertion_explanations),
            )
        if not variant.assertions and final_result.status_code not in replay_plan.success_status_codes:
            return VerifierExecutionOutcome(
                confirmed=False,
                replay_result=None,
                note=(
                    f"Replay executor did not confirm the path because the final request returned "
                    f"HTTP {final_result.status_code} instead of one of {replay_plan.success_status_codes}."
                ),
            )

        evidence = [
            FindingEvidence(
                label=_evidence_label(result.request.method, result.request.path),
                detail=(
                    f"{result.url} returned HTTP {result.status_code} in {result.duration_ms} ms. "
                    f"Response excerpt: {result.body_excerpt or '<empty>'}"
                ),
                source="verifier",
            )
            for result in response_results
        ]
        evidence.extend(
            FindingEvidence(
                label="Replay assertion result",
                detail=message,
                source="verifier",
            )
            for message in assertion_explanations
        )
        replay_result = VerifierReplayResult(
            verifier_run_id=f"verify-{job.id}",
            scan_id=job.scan_id,
            finding_id=f"finding-{job.id}",
            title=job.title,
            category=_category_from_job(job),
            severity=job.severity,
            confidence=95 if job.severity == FindingSeverity.CRITICAL else 87,
            endpoint=f"{final_result.request.method.upper()} {final_result.request.path}",
            actor=default_actor,
            request_fingerprint=final_result.request.request_fingerprint,
            request_summary=(
                f"Replayed {len(response_results)} requests for path {job.source_path_id}; "
                f"final response was HTTP {final_result.status_code}."
            ),
            response_status_code=final_result.status_code,
            message=f"HTTP replay verifier confirmed queued job {job.id}.",
            impact_summary=f"HTTP replay reproduced the risky path '{job.title}' with the provided actor credentials.",
            remediation_summary="Tighten authorization around the replayed path and add regression tests for the affected actor permissions.",
            description=(
                "The HTTP replay executor issued real requests against the configured target using the supplied actor headers "
                "and confirmed that the risky path remains reachable."
            ),
            impact="A low-privilege or externally scoped actor can execute the replayed path successfully against the live target.",
            remediation="Review the authorization checks for each replayed step and block the actor from reaching the final high-risk endpoint.",
            workflow_node_ids=list(job.payload.workflow_node_ids),
            evidence=evidence,
            tags=["http-replay", variant.id, job.severity.value, *{node.phase for node in job.payload.workflow_nodes}],
        )
        return VerifierExecutionOutcome(
            confirmed=True,
            replay_result=replay_result,
            note=f"HTTP replay executor confirmed the queued verifier job with variant {variant.id}.",
        )

    def _normalized_replay_plan(self, replay_plan: ReplayPlan | None) -> ReplayPlan | None:
        if replay_plan is None:
            return None

        replay_plan.mutations = [
            mutation if isinstance(mutation, ReplayMutationSpec) else ReplayMutationSpec.model_validate(mutation)
            for mutation in replay_plan.mutations
        ]
        replay_plan.assertions = [
            assertion if isinstance(assertion, ReplayAssertionSpec) else ReplayAssertionSpec.model_validate(assertion)
            for assertion in replay_plan.assertions
        ]
        replay_plan.variants = [
            variant if isinstance(variant, ReplayPayloadVariant) else ReplayPayloadVariant.model_validate(variant)
            for variant in replay_plan.variants
        ]
        replay_plan.refresh_requests = [
            refresh if isinstance(refresh, ReplayRefreshRequestSpec) else ReplayRefreshRequestSpec.model_validate(refresh)
            for refresh in replay_plan.refresh_requests
        ]
        return replay_plan

    def _prepare_callback_context(self, job: VerifierJobDetail, *, variant: ReplayPayloadVariant) -> dict[str, CallbackExpectationDetail]:
        labels: set[str] = set()
        for assertion in variant.assertions:
            if assertion.callback_label:
                labels.add(assertion.callback_label)

        if variant.browser_plan is not None:
            for visit in variant.browser_plan.visits:
                labels.update(visit.callback_labels)

        for mutation in variant.mutations:
            values_to_scan = [mutation.value, mutation.to_value]
            for raw_value in values_to_scan:
                if not isinstance(raw_value, str):
                    continue
                for regex in (CALLBACK_URL_PLACEHOLDER, XSS_CALLBACK_PLACEHOLDER):
                    match = regex.match(raw_value)
                    if match:
                        labels.add(match.group(1))

        callback_context: dict[str, CallbackExpectationDetail] = {}
        for label in labels:
            kind = CallbackKind.SSRF if job.payload.vulnerability_class == "ssrf" else CallbackKind.XSS
            expectation = callback_service.create_expectation(
                scan_id=job.scan_id,
                verifier_job_id=job.id,
                kind=kind,
                label=label,
            )
            if expectation is not None:
                callback_context[label] = expectation
        return callback_context

    def _collect_callback_assertion_results(
        self,
        assertions: list[ReplayAssertionSpec],
        *,
        callback_context: dict[str, CallbackExpectationDetail],
    ) -> dict[str, CallbackExpectationDetail]:
        results: dict[str, CallbackExpectationDetail] = {}
        for assertion in assertions:
            if assertion.type not in {
                ReplayAssertionType.CALLBACK_RECEIVED,
                ReplayAssertionType.CALLBACK_METADATA_SCORE_GTE,
                ReplayAssertionType.CALLBACK_SOURCE_CLASS_IN,
            } or not assertion.callback_label:
                continue
            expectation = callback_context.get(assertion.callback_label)
            if expectation is None:
                continue
            deadline = time.monotonic() + assertion.wait_seconds
            current = expectation
            while True:
                refreshed = callback_service.get_expectation_by_token(expectation.token)
                if refreshed is not None:
                    current = refreshed
                if current.status == CallbackExpectationStatus.RECEIVED:
                    break
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.1)
            results[assertion.callback_label] = current
        return results

    def _run_browser_plan(
        self,
        browser_plan: BrowserPlan | None,
        *,
        callback_context: dict[str, CallbackExpectationDetail],
        dynamic_headers: dict[str, str],
        default_actor: str | None,
    ) -> None:
        if browser_plan is None or not browser_plan.visits:
            return
        if self.browser_executor is None:
            return
        if self.base_url is None:
            return

        for visit in browser_plan.visits:
            actor_key = visit.actor or default_actor
            headers = self.actor_headers.get(actor_key or "", {})
            merged_headers = _merge_headers(headers, dynamic_headers)
            self.browser_executor.visit(visit, base_url=_browser_base_url(self.base_url), headers=merged_headers)

    def _execute_request(
        self,
        request_spec: ReplayRequestSpec,
        *,
        artifact: ReplayArtifactMaterial | None,
        plan_actor: str | None,
        mutations: list[ReplayMutationSpec],
        dynamic_headers: dict[str, str],
        callback_urls: dict[str, str],
    ) -> tuple[ReplayHttpResult | None, ReplayHttpResult]:
        base_headers = dict(artifact.request_headers) if artifact is not None else {}
        base_body = _decode_body(artifact.request_body_base64) if artifact is not None else None
        base_path = artifact.path if artifact is not None else request_spec.path
        has_actor_switch = any(
            mutation.type == ReplayMutationType.ACTOR_SWITCH
            and (mutation.target_request_fingerprint is None or mutation.target_request_fingerprint == request_spec.request_fingerprint)
            for mutation in mutations
        )
        baseline_result = None
        if has_actor_switch:
            baseline_headers = self.actor_headers.get(request_spec.actor or plan_actor or "", {})
            merged_baseline_headers = _merge_headers(base_headers, baseline_headers)
            merged_baseline_headers = _merge_headers(merged_baseline_headers, dynamic_headers)
            baseline_result = self.transport(
                request_spec,
                base_url=self.base_url,
                timeout_seconds=self.timeout_seconds,
                verify_tls=self.verify_tls,
                headers=merged_baseline_headers,
                body=base_body,
            )
        request_path, interim_headers, body, actor_key = _apply_mutations(
            request_spec,
            plan_actor=plan_actor,
            path=base_path,
            headers=base_headers,
            body=base_body,
            mutations=mutations,
            callback_urls=callback_urls,
        )
        actor_headers = self.actor_headers.get(actor_key or "", {})
        merged_headers = _merge_headers(interim_headers, actor_headers)
        merged_headers = _merge_headers(merged_headers, dynamic_headers)
        mutated_request = request_spec.model_copy(update={"path": request_path, "actor": actor_key})
        return baseline_result, self.transport(
            mutated_request,
            base_url=self.base_url,
            timeout_seconds=self.timeout_seconds,
            verify_tls=self.verify_tls,
            headers=merged_headers,
            body=body,
        )

    def _execute_refresh_requests(
        self,
        refresh_requests: list[ReplayRefreshRequestSpec],
        *,
        plan_actor: str | None,
        dynamic_headers: dict[str, str],
    ) -> bool:
        for refresh_request in refresh_requests:
            request_spec = _build_refresh_request_spec(refresh_request)
            actor_key = refresh_request.actor or plan_actor
            actor_headers = self.actor_headers.get(actor_key or "", {})
            merged_headers = _merge_headers(_normalize_header_keys(refresh_request.headers), actor_headers)
            merged_headers = _merge_headers(merged_headers, dynamic_headers)
            body = _decode_body(refresh_request.body_base64)
            if refresh_request.content_type:
                merged_headers.setdefault("Content-Type", refresh_request.content_type)
            result = self.transport(
                request_spec,
                base_url=self.base_url,
                timeout_seconds=self.timeout_seconds,
                verify_tls=self.verify_tls,
                headers=merged_headers,
                body=body,
            )
            _apply_set_cookie(dynamic_headers, result.response_headers)
            if result.status_code >= 400:
                return False

        return True


@dataclass(slots=True)
class VerifierRuntimeService:
    executor: VerifierJobExecutor
    worker_id: str
    poll_interval_seconds: float = 2.0
    _stop_event: asyncio.Event | None = None

    def run_once(self, *, scan_id: str | None = None) -> bool:
        job = verifier_job_service.claim_verifier_job(
            ClaimVerifierJobRequest(
                scan_id=scan_id,
                worker_id=self.worker_id,
            )
        )
        if job is None:
            return False

        try:
            outcome = self.executor.execute(job)
            if outcome.confirmed:
                result = outcome.replay_result
                if result is None:
                    raise RuntimeError("Executor reported confirmation without a replay result.")

                envelope = event_service.ingest_scan_event(job.scan_id, build_ingest_request(result))
                if envelope is None:
                    raise RuntimeError("Failed to ingest verifier finding into the backend runtime store.")

                finding_id = envelope.event.payload.get("finding_id") if envelope.event.payload else None
                verifier_job_service.complete_verifier_job(
                    job.id,
                    CompleteVerifierJobRequest(
                        verifier_run_id=result.verifier_run_id,
                        finding_id=str(finding_id) if finding_id is not None else result.finding_id,
                        note=outcome.note,
                    ),
                )
                event_service.record_scan_event(
                    job.scan_id,
                    RecordScanEventRequest(
                        source=EventSource.SYSTEM,
                        event_type="verifier_runtime.completed",
                        stage="reporting",
                        severity=EventSeverity.INFO,
                        message=f"Automatic verifier runtime completed job {job.id}.",
                        payload={"job_id": job.id, "verifier_run_id": result.verifier_run_id},
                    ),
                )
            else:
                verifier_job_service.complete_verifier_job(
                    job.id,
                    CompleteVerifierJobRequest(note=outcome.note),
                )
                event_service.record_scan_event(
                    job.scan_id,
                    RecordScanEventRequest(
                        source=EventSource.SYSTEM,
                        event_type="verifier_runtime.unconfirmed",
                        stage="verification",
                        severity=EventSeverity.INFO,
                        message=f"Automatic verifier runtime completed job {job.id} without confirmation.",
                        payload={"job_id": job.id, "note": outcome.note},
                    ),
                )
            return True
        except Exception as exc:
            verifier_job_service.fail_verifier_job(
                job.id,
                FailVerifierJobRequest(
                    error_message=str(exc),
                    retryable=True,
                    retry_delay_seconds=0,
                ),
            )
            event_service.record_scan_event(
                job.scan_id,
                RecordScanEventRequest(
                    source=EventSource.SYSTEM,
                    event_type="verifier_runtime.failed",
                    stage="verification",
                    severity=EventSeverity.WARNING,
                    message=f"Automatic verifier runtime failed job {job.id}.",
                    payload={"job_id": job.id, "error": str(exc)},
                ),
            )
            return False

    async def run_forever(self) -> None:
        if self._stop_event is None:
            self._stop_event = asyncio.Event()

        while not self._stop_event.is_set():
            processed = self.run_once()
            if not processed:
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=self.poll_interval_seconds)
                except TimeoutError:
                    continue

    def stop(self) -> None:
        if self._stop_event is not None:
            self._stop_event.set()


def build_runtime_service(*, settings: Settings) -> VerifierRuntimeService | None:
    mode = settings.verifier_autorun_mode
    worker_id = settings.verifier_autorun_worker_id
    poll_interval_seconds = settings.verifier_autorun_poll_interval
    normalized_mode = mode.strip().lower()
    if normalized_mode in {"", "disabled", "manual"}:
        return None
    if normalized_mode == "deterministic-dev":
        return VerifierRuntimeService(
            executor=DeterministicDevVerifierExecutor(),
            worker_id=worker_id,
            poll_interval_seconds=poll_interval_seconds,
        )
    if normalized_mode == "http-replay":
        if settings.verifier_replay_base_url is None:
            raise ValueError("AUDITOR_VERIFIER_REPLAY_BASE_URL must be configured for http-replay mode.")
        browser_executor = None
        if settings.browser_execution_enabled:
            browser_executor = PlaywrightBrowserExecutor(
                headless=settings.browser_headless,
                timeout_seconds=settings.browser_timeout_seconds,
                browser_name=settings.browser_engine,
            )
        return VerifierRuntimeService(
            executor=HttpReplayVerifierExecutor(
                base_url=settings.verifier_replay_base_url,
                actor_headers=settings.verifier_replay_actor_headers,
                timeout_seconds=settings.verifier_replay_timeout,
                verify_tls=settings.verifier_replay_verify_tls,
                browser_executor=browser_executor,
            ),
            worker_id=worker_id,
            poll_interval_seconds=poll_interval_seconds,
        )

    raise ValueError(f"Unsupported verifier autorun mode: {mode}")
