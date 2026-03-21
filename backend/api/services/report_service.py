from __future__ import annotations

from datetime import datetime, timezone

from api.schemas.findings import FindingSeverity, FindingStatus
from api.schemas.reports import (
    FindingComparisonEntry,
    FindingDriftKind,
    ScanComparisonReport,
    ScanComparisonSummary,
    ScanEvidenceBundle,
    ScanReport,
    SeverityBreakdown,
    StatusBreakdown,
    WorkflowReportSummary,
)
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

    def compare_scans(self, baseline_scan_id: str, current_scan_id: str) -> ScanComparisonReport | None:
        baseline_scan = scan_service.get_scan(baseline_scan_id)
        current_scan = scan_service.get_scan(current_scan_id)
        if baseline_scan is None or current_scan is None:
            return None

        baseline_findings = finding_service.list_findings(scan_id=baseline_scan_id)
        current_findings = finding_service.list_findings(scan_id=current_scan_id)

        def comparison_key(finding) -> str:
            return "|".join([finding.category, finding.endpoint or "", finding.title])

        baseline_map = {comparison_key(finding): finding for finding in baseline_findings}
        current_map = {comparison_key(finding): finding for finding in current_findings}
        all_keys = sorted(set(baseline_map) | set(current_map))

        comparisons: list[FindingComparisonEntry] = []
        counts = {
            FindingDriftKind.NEW: 0,
            FindingDriftKind.RESOLVED: 0,
            FindingDriftKind.CHANGED: 0,
            FindingDriftKind.UNCHANGED: 0,
        }

        for key in all_keys:
            baseline = baseline_map.get(key)
            current = current_map.get(key)
            if baseline is None and current is not None:
                kind = FindingDriftKind.NEW
                changed_fields: list[str] = []
            elif current is None and baseline is not None:
                kind = FindingDriftKind.RESOLVED
                changed_fields = []
            elif baseline is not None and current is not None:
                changed_fields = []
                if baseline.severity != current.severity:
                    changed_fields.append("severity")
                if baseline.status != current.status:
                    changed_fields.append("status")
                if baseline.confidence != current.confidence:
                    changed_fields.append("confidence")
                if baseline.evidence_count != current.evidence_count:
                    changed_fields.append("evidence_count")
                if baseline.context_reference_count != current.context_reference_count:
                    changed_fields.append("context_reference_count")
                kind = FindingDriftKind.CHANGED if changed_fields else FindingDriftKind.UNCHANGED
            else:
                continue

            counts[kind] += 1
            comparisons.append(
                FindingComparisonEntry(
                    kind=kind,
                    comparison_key=key,
                    baseline_finding=baseline,
                    current_finding=current,
                    changed_fields=changed_fields,
                )
            )

        return ScanComparisonReport(
            generated_at=_utc_now(),
            baseline_scan=baseline_scan,
            current_scan=current_scan,
            summary=ScanComparisonSummary(
                baseline_scan_id=baseline_scan_id,
                current_scan_id=current_scan_id,
                new_findings=counts[FindingDriftKind.NEW],
                resolved_findings=counts[FindingDriftKind.RESOLVED],
                changed_findings=counts[FindingDriftKind.CHANGED],
                unchanged_findings=counts[FindingDriftKind.UNCHANGED],
            ),
            comparisons=comparisons,
        )


report_service = ReportService()
