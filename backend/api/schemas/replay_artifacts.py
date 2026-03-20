from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class ReplayArtifactInput(BaseModel):
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body_base64: str | None = None
    request_content_type: str | None = Field(default=None, max_length=160)
    response_status_code: int | None = Field(default=None, ge=100, le=599)
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body_excerpt: str | None = Field(default=None, max_length=4000)


class ReplayArtifactDetail(BaseModel):
    id: str
    scan_id: str
    request_fingerprint: str
    actor: str | None = None
    method: str
    host: str
    path: str
    request_headers: dict[str, str]
    request_body_base64: str | None = None
    request_content_type: str | None = None
    response_status_code: int | None = None
    response_headers: dict[str, str]
    response_body_excerpt: str | None = None
    created_at: datetime
