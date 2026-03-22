from __future__ import annotations

from api.schemas.scan_setup import ScanActorProfileDetail, ScanActorProfileInput
from api.schemas.scans import ScanRunSummary, ScanRuntimeConfig, StartScanRequest
from api.services.store import audit_store


class ScanService:
    def ensure_seed_data(self) -> None:
        audit_store.ensure_seed_data()

    def list_scans(self) -> list[ScanRunSummary]:
        return audit_store.list_scans()

    def get_scan(self, scan_id: str) -> ScanRunSummary | None:
        return audit_store.get_scan(scan_id)

    def list_scan_actor_profiles(self, scan_id: str) -> list[ScanActorProfileDetail]:
        return audit_store.list_scan_actor_profiles(scan_id)

    def upsert_scan_actor_profiles(self, scan_id: str, profiles: list[ScanActorProfileInput]) -> list[ScanActorProfileDetail]:
        return audit_store.upsert_scan_actor_profiles(scan_id, profiles)

    def get_scan_runtime_config(self, scan_id: str) -> ScanRuntimeConfig | None:
        return audit_store.get_scan_runtime_config(scan_id)

    def start_scan(self, payload: StartScanRequest) -> ScanRunSummary:
        return audit_store.start_scan(payload)


scan_service = ScanService()
