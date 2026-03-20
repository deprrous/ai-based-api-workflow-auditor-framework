from __future__ import annotations

from datetime import datetime, timezone

from api.schemas.findings import FindingSeverity, FindingStatus
from api.schemas.reports import ScanEvidenceBundle, ScanReport, SeverityBreakdown, StatusBreakdown, WorkflowReportSummary
from api.services.event_service import event_service
from api.services.finding_service import finding_service
from api.services.scan_service import scan_service
from api.services.workflow_service import workflow_service


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ReportService:
    def get_scan_report(self, scan_id: str) -> ScanReport | None:
        scan = scan_service.get_scan(scan_id)
        workflow = workflow_service.get_scan_workflow(scan_id)

        if scan is None or workflow is None:
            return None

        findings = finding_service.list_findings(scan_id=scan_id)
        recent_events = event_service.list_scan_events(scan_id, limit=10)

        severity_breakdown = SeverityBreakdown(
            review=sum(1 for finding in findings if finding.severity == FindingSeverity.REVIEW),
            high=sum(1 for finding in findings if finding.severity == FindingSeverity.HIGH),
            critical=sum(1 for finding in findings if finding.severity == FindingSeverity.CRITICAL),
        )
        status_breakdown = StatusBreakdown(
            candidate=sum(1 for finding in findings if finding.status == FindingStatus.CANDIDATE),
            confirmed=sum(1 for finding in findings if finding.status == FindingStatus.CONFIRMED),
            resolved=sum(1 for finding in findings if finding.status == FindingStatus.RESOLVED),
        )

        return ScanReport(
            generated_at=_utc_now(),
            scan=scan,
            workflow=WorkflowReportSummary(
                workflow_id=workflow.id,
                title=workflow.title,
                updated_at=workflow.updated_at,
                node_count=workflow.stats.node_count,
                edge_count=workflow.stats.edge_count,
                flagged_paths=workflow.stats.flagged_paths,
                critical_nodes=workflow.stats.critical_nodes,
            ),
            severity_breakdown=severity_breakdown,
            status_breakdown=status_breakdown,
            findings=findings,
            recent_events=recent_events,
        )

    def get_scan_evidence_bundle(self, scan_id: str) -> ScanEvidenceBundle | None:
        scan = scan_service.get_scan(scan_id)
        if scan is None:
            return None

        findings = [
            detail
            for summary in finding_service.list_findings(scan_id=scan_id)
            if (detail := finding_service.get_finding(summary.id)) is not None
        ]

        return ScanEvidenceBundle(
            exported_at=_utc_now(),
            scan=scan,
            findings=findings,
            total_evidence_items=sum(len(finding.evidence) for finding in findings),
        )


report_service = ReportService()
