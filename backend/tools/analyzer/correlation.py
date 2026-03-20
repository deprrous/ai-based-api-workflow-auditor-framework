from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re

from pydantic import BaseModel, Field

from api.schemas.findings import ContextReference, ContextReferenceKind


def _tokenize(value: str) -> set[str]:
    return {token for token in re.split(r"[^a-zA-Z0-9]+", value.lower()) if token}


def _stable_id(prefix: str, value: str) -> str:
    return f"{prefix}-{hashlib.sha1(value.encode('utf-8')).hexdigest()[:10]}"


class CorrelationCandidate(BaseModel):
    label: str = Field(min_length=3, max_length=200)
    location: str = Field(min_length=1, max_length=300)
    excerpt: str = Field(min_length=3, max_length=2000)
    hint: str | None = Field(default=None, max_length=400)


class CorrelationInput(BaseModel):
    endpoint: str | None = Field(default=None, max_length=200)
    title: str = Field(min_length=3, max_length=200)
    category: str = Field(min_length=2, max_length=80)
    tags: list[str] = Field(default_factory=list)
    source_candidates: list[CorrelationCandidate] = Field(default_factory=list)
    spec_candidates: list[CorrelationCandidate] = Field(default_factory=list)


@dataclass(frozen=True, slots=True)
class _RankedCandidate:
    kind: ContextReferenceKind
    candidate: CorrelationCandidate
    score: int
    rationale: str


def _score_candidate(candidate: CorrelationCandidate, query_tokens: set[str], kind: ContextReferenceKind) -> _RankedCandidate:
    haystack = " ".join([candidate.label, candidate.location, candidate.excerpt, candidate.hint or ""])
    candidate_tokens = _tokenize(haystack)
    overlap = len(query_tokens & candidate_tokens)
    bonus = 2 if kind == ContextReferenceKind.API_SPEC and any(token in candidate.location.lower() for token in ("openapi", "swagger", ".yaml", ".json")) else 0
    bonus += 2 if kind == ContextReferenceKind.SOURCE_CODE and any(token in candidate.location.lower() for token in (".py", ".ts", ".js", "controller", "service")) else 0
    score = overlap + bonus
    rationale = f"Matched {overlap} shared tokens between the finding context and the {kind.value.replace('_', ' ')} candidate."
    return _RankedCandidate(kind=kind, candidate=candidate, score=score, rationale=rationale)


def build_context_references(correlation_input: CorrelationInput, *, limit_per_kind: int = 2) -> list[ContextReference]:
    query_text = " ".join(
        [correlation_input.title, correlation_input.category, correlation_input.endpoint or "", *correlation_input.tags]
    )
    query_tokens = _tokenize(query_text)
    references: list[ContextReference] = []

    for kind, candidates in (
        (ContextReferenceKind.SOURCE_CODE, correlation_input.source_candidates),
        (ContextReferenceKind.API_SPEC, correlation_input.spec_candidates),
    ):
        ranked = sorted(
            (_score_candidate(candidate, query_tokens, kind) for candidate in candidates),
            key=lambda item: (item.score, item.candidate.label),
            reverse=True,
        )
        for item in ranked[:limit_per_kind]:
            references.append(
                ContextReference(
                    id=_stable_id(kind.value, f"{item.candidate.location}|{item.candidate.label}"),
                    kind=kind,
                    label=item.candidate.label,
                    location=item.candidate.location,
                    excerpt=item.candidate.excerpt,
                    rationale=item.rationale,
                )
            )

    return references
