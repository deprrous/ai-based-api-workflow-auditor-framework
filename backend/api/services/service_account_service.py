from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import secrets
from uuid import uuid4

from api.app.database import session_scope
from api.app.db_models import ServiceAccountRecord
from api.repositories.service_account_repository import ServiceAccountRepository
from api.schemas.service_accounts import (
    CreateServiceAccountRequest,
    RotateServiceAccountResponse,
    ServiceAccountKind,
    ServiceAccountScope,
    ServiceAccountSummary,
    ServiceAccountWithToken,
)


@dataclass(frozen=True, slots=True)
class ServiceAccountAuthResult:
    account: ServiceAccountSummary


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _token_prefix(token: str) -> str:
    return token[:12]


def _default_scopes(kind: ServiceAccountKind) -> list[ServiceAccountScope]:
    if kind == ServiceAccountKind.ADMIN:
        return [ServiceAccountScope.MANAGE_SERVICE_ACCOUNTS, ServiceAccountScope.READ_REPORTS]

    return [ServiceAccountScope.INGEST_EVENTS, ServiceAccountScope.RUN_VERIFIER_JOBS]


def _record_to_summary(record: ServiceAccountRecord) -> ServiceAccountSummary:
    return ServiceAccountSummary(
        id=record.id,
        name=record.name,
        kind=ServiceAccountKind(record.kind),
        description=record.description,
        scopes=[ServiceAccountScope(scope) for scope in record.scopes_json],
        token_prefix=record.token_prefix,
        is_active=record.is_active,
        created_at=record.created_at,
        updated_at=record.updated_at,
        rotated_at=record.rotated_at,
        last_used_at=record.last_used_at,
    )


class ServiceAccountService:
    def list_service_accounts(self) -> list[ServiceAccountSummary]:
        with session_scope() as session:
            records = ServiceAccountRepository(session).list()
            return [_record_to_summary(record) for record in records]

    def create_service_account(self, payload: CreateServiceAccountRequest) -> ServiceAccountWithToken:
        token = self._generate_token(payload.kind)
        now = _utc_now()
        scopes = payload.scopes or _default_scopes(payload.kind)

        with session_scope() as session:
            repository = ServiceAccountRepository(session)
            if repository.get_by_name(payload.name) is not None:
                raise ValueError("Service account name already exists.")

            record = ServiceAccountRecord(
                id=f"svc-{uuid4().hex[:12]}",
                name=payload.name,
                kind=payload.kind.value,
                description=payload.description,
                scopes_json=[scope.value for scope in scopes],
                token_hash=_hash_token(token),
                token_prefix=_token_prefix(token),
                is_active=True,
                created_at=now,
                updated_at=now,
                rotated_at=None,
                last_used_at=None,
            )
            repository.add(record)
            session.flush()
            session.refresh(record)

            return ServiceAccountWithToken(account=_record_to_summary(record), token=token)

    def rotate_service_account(self, service_account_id: str) -> RotateServiceAccountResponse | None:
        now = _utc_now()

        with session_scope() as session:
            repository = ServiceAccountRepository(session)
            record = repository.get(service_account_id)
            if record is None:
                return None

            token = self._generate_token(ServiceAccountKind(record.kind))
            record.token_hash = _hash_token(token)
            record.token_prefix = _token_prefix(token)
            record.updated_at = now
            record.rotated_at = now
            record.is_active = True

            return RotateServiceAccountResponse(account=_record_to_summary(record), token=token)

    def revoke_service_account(self, service_account_id: str) -> ServiceAccountSummary | None:
        now = _utc_now()

        with session_scope() as session:
            repository = ServiceAccountRepository(session)
            record = repository.get(service_account_id)
            if record is None:
                return None

            record.is_active = False
            record.updated_at = now
            return _record_to_summary(record)

    def authenticate_token(self, token: str, *, required_scope: ServiceAccountScope) -> ServiceAccountAuthResult | None:
        with session_scope() as session:
            repository = ServiceAccountRepository(session)
            record = repository.get_by_token_hash(_hash_token(token))
            if record is None or not record.is_active:
                return None

            if required_scope.value not in record.scopes_json:
                return None

            record.last_used_at = _utc_now()
            record.updated_at = record.last_used_at
            return ServiceAccountAuthResult(account=_record_to_summary(record))

    @staticmethod
    def _generate_token(kind: ServiceAccountKind) -> str:
        prefix = "auditor-admin" if kind == ServiceAccountKind.ADMIN else "auditor-worker"
        return f"{prefix}-{secrets.token_urlsafe(24)}"


service_account_service = ServiceAccountService()
