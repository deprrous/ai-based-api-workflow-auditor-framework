from __future__ import annotations

from api.schemas.events import IngestScanEventRequest, RecordScanEventRequest, ScanEvent, ScanEventEnvelope, ScanStreamSnapshot
from api.services.producer_contract_service import producer_contract_service
from api.services.store import audit_store


class EventService:
    def list_scan_events(self, scan_id: str, *, after_id: int | None = None, limit: int = 40) -> list[ScanEvent]:
        return audit_store.list_scan_events(scan_id, after_id=after_id, limit=limit)

    def ingest_scan_event(self, scan_id: str, payload: IngestScanEventRequest) -> ScanEventEnvelope | None:
        normalized_payload = producer_contract_service.normalize_ingest_request(payload)
        return audit_store.ingest_scan_event(scan_id, normalized_payload)

    def get_runtime_snapshot(self, scan_id: str, *, event_limit: int = 25) -> ScanStreamSnapshot | None:
        return audit_store.get_runtime_snapshot(scan_id, event_limit=event_limit)

    def record_scan_event(self, scan_id: str, payload: RecordScanEventRequest) -> ScanEvent | None:
        return audit_store.record_scan_event(scan_id, payload)


event_service = EventService()
