from __future__ import annotations

from api.schemas.scans import ScanRunSummary, StartScanRequest
from api.services.store import audit_store


class ScanService:
    def list_scans(self) -> list[ScanRunSummary]:
        return audit_store.list_scans()

    def get_scan(self, scan_id: str) -> ScanRunSummary | None:
        return audit_store.get_scan(scan_id)

    def start_scan(self, payload: StartScanRequest) -> ScanRunSummary:
        return audit_store.start_scan(payload)


scan_service = ScanService()
