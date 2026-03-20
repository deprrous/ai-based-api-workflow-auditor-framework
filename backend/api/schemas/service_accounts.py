from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class ServiceAccountKind(StrEnum):
    WORKER = "worker"
    ADMIN = "admin"


class ServiceAccountScope(StrEnum):
    INGEST_EVENTS = "ingest:events"
    RUN_VERIFIER_JOBS = "run:verifier_jobs"
    MANAGE_SERVICE_ACCOUNTS = "manage:service_accounts"
    READ_REPORTS = "read:reports"


class ServiceAccountSummary(BaseModel):
    id: str
    name: str
    kind: ServiceAccountKind
    description: str | None = None
    scopes: list[ServiceAccountScope]
    token_prefix: str
    is_active: bool
    created_at: datetime
    updated_at: datetime
    rotated_at: datetime | None = None
    last_used_at: datetime | None = None


class ServiceAccountWithToken(BaseModel):
    account: ServiceAccountSummary
    token: str = Field(description="Raw token shown only at creation or rotation time.")


class CreateServiceAccountRequest(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    kind: ServiceAccountKind = ServiceAccountKind.WORKER
    description: str | None = Field(default=None, max_length=500)
    scopes: list[ServiceAccountScope] = Field(default_factory=list)


class RotateServiceAccountResponse(BaseModel):
    account: ServiceAccountSummary
    token: str
