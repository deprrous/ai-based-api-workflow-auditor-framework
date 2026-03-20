from __future__ import annotations

from api.schemas.findings import FindingDetail, FindingSeverity, FindingStatus, FindingSummary
from api.services.store import audit_store


class FindingService:
    def list_findings(
        self,
        *,
        scan_id: str | None = None,
        severity: FindingSeverity | None = None,
        status: FindingStatus | None = None,
    ) -> list[FindingSummary]:
        return audit_store.list_findings(scan_id=scan_id, severity=severity, status=status)

    def get_finding(self, finding_id: str) -> FindingDetail | None:
        return audit_store.get_finding(finding_id)


finding_service = FindingService()
