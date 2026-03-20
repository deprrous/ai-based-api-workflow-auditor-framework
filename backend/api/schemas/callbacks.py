from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class CallbackKind(StrEnum):
    SSRF = "ssrf"
    XSS = "xss"


class CallbackExpectationStatus(StrEnum):
    PENDING = "pending"
    RECEIVED = "received"
    EXPIRED = "expired"


class CallbackExpectationSummary(BaseModel):
    id: str
    scan_id: str
    verifier_job_id: str | None = None
    token: str
    kind: CallbackKind
    label: str
    status: CallbackExpectationStatus
    callback_url: str
    event_count: int
    created_at: datetime
    expires_at: datetime
    received_at: datetime | None = None


class CallbackEventDetail(BaseModel):
    id: int
    expectation_id: str
    method: str
    path: str
    query_string: str | None = None
    headers: dict[str, str]
    body_excerpt: str | None = None
    source_ip: str | None = None
    user_agent: str | None = None
    created_at: datetime


class CallbackExpectationDetail(CallbackExpectationSummary):
    events: list[CallbackEventDetail]
