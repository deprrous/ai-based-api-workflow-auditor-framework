from __future__ import annotations

from api.schemas.events import EventSeverity, IngestScanEventRequest, WorkflowGraphUpdate
from api.schemas.findings import FindingSeverity, FindingStatus
from api.schemas.producer_contracts import (
    OrchestratorHypothesisCreatedContract,
    ProducerContractCatalog,
    ProducerContractDefinition,
    ProxyHttpObservedContract,
    VerifierFindingConfirmedContract,
    WorkflowMapperPathFlaggedContract,
)
from api.schemas.scans import ScanRisk


def _risk_from_finding_severity(severity: FindingSeverity) -> ScanRisk:
    if severity == FindingSeverity.CRITICAL:
        return ScanRisk.CRITICAL
    if severity == FindingSeverity.HIGH:
        return ScanRisk.HIGH
    return ScanRisk.REVIEW


def _severity_from_finding_severity(severity: FindingSeverity) -> EventSeverity:
    if severity == FindingSeverity.CRITICAL:
        return EventSeverity.CRITICAL
    if severity == FindingSeverity.HIGH:
        return EventSeverity.HIGH
    return EventSeverity.WARNING


def _merge_graph_updates(current: WorkflowGraphUpdate | None, incoming: WorkflowGraphUpdate | None) -> WorkflowGraphUpdate | None:
    if current is None:
        return incoming
    if incoming is None:
        return current

    return WorkflowGraphUpdate(
        title=incoming.title or current.title,
        description=incoming.description or current.description,
        upsert_nodes=[*current.upsert_nodes, *incoming.upsert_nodes],
        upsert_edges=[*current.upsert_edges, *incoming.upsert_edges],
        remove_node_ids=[*current.remove_node_ids, *incoming.remove_node_ids],
        remove_edges=[*current.remove_edges, *incoming.remove_edges],
    )


class ProducerContractService:
    def normalize_ingest_request(self, payload: IngestScanEventRequest) -> IngestScanEventRequest:
        contract = payload.producer_contract
        if contract is None:
            return payload

        if isinstance(contract, ProxyHttpObservedContract):
            return self._normalize_proxy_http_observed(payload, contract)
        if isinstance(contract, OrchestratorHypothesisCreatedContract):
            return self._normalize_hypothesis(payload, contract)
        if isinstance(contract, WorkflowMapperPathFlaggedContract):
            return self._normalize_path_flagged(payload, contract)
        if isinstance(contract, VerifierFindingConfirmedContract):
            return self._normalize_finding_confirmed(payload, contract)

        return payload

    def get_catalog(self) -> ProducerContractCatalog:
        return ProducerContractCatalog(
            version="v1",
            definitions=[
                ProducerContractDefinition(
                    kind="proxy.http_observed",
                    source="proxy",
                    summary="Capture a target-derived HTTP action and map it into workflow graph nodes and edges.",
                    required_event_type="proxy.http_observed",
                ),
                ProducerContractDefinition(
                    kind="orchestrator.hypothesis_created",
                    source="orchestrator",
                    summary="Publish a reasoning hypothesis that should appear as a structured workflow action.",
                    required_event_type="orchestrator.hypothesis_created",
                ),
                ProducerContractDefinition(
                    kind="workflow_mapper.path_flagged",
                    source="workflow_mapper",
                    summary="Flag a risky or suspicious path and mark the related workflow nodes and edges consistently.",
                    required_event_type="workflow_mapper.path_flagged",
                ),
                ProducerContractDefinition(
                    kind="verifier.finding_confirmed",
                    source="verifier",
                    summary="Persist a confirmed finding and attach graph updates and evidence through one event contract.",
                    required_event_type="verifier.finding_confirmed",
                ),
            ],
        )

    def _normalize_proxy_http_observed(
        self,
        payload: IngestScanEventRequest,
        contract: ProxyHttpObservedContract,
    ) -> IngestScanEventRequest:
        graph_update = WorkflowGraphUpdate(
            upsert_nodes=[contract.node],
            upsert_edges=[contract.edge] if contract.edge is not None else [],
        )
        contract_payload = {
            "request_id": contract.request_id,
            "request_fingerprint": contract.request_fingerprint,
            "method": contract.method,
            "host": contract.host,
            "path": contract.path,
            "status_code": contract.status_code,
            "actor": contract.actor,
            "contract_kind": contract.kind,
        }
        return payload.model_copy(
            update={
                "payload": {**(payload.payload or {}), **contract_payload},
                "graph_update": _merge_graph_updates(payload.graph_update, graph_update),
                "current_stage": payload.current_stage or "ingestion",
            }
        )

    def _normalize_hypothesis(
        self,
        payload: IngestScanEventRequest,
        contract: OrchestratorHypothesisCreatedContract,
    ) -> IngestScanEventRequest:
        graph_update = WorkflowGraphUpdate(upsert_nodes=[contract.node], upsert_edges=list(contract.edges))
        contract_payload = {
            "hypothesis_id": contract.hypothesis_id,
            "category": contract.category,
            "title": contract.title,
            "confidence": contract.confidence,
            "rationale": contract.rationale,
            "contract_kind": contract.kind,
        }
        return payload.model_copy(
            update={
                "payload": {**(payload.payload or {}), **contract_payload},
                "graph_update": _merge_graph_updates(payload.graph_update, graph_update),
                "current_stage": payload.current_stage or "reasoning",
            }
        )

    def _normalize_path_flagged(
        self,
        payload: IngestScanEventRequest,
        contract: WorkflowMapperPathFlaggedContract,
    ) -> IngestScanEventRequest:
        graph_update = WorkflowGraphUpdate(upsert_nodes=list(contract.nodes), upsert_edges=list(contract.edges))
        contract_payload = {
            "path_id": contract.path_id,
            "title": contract.title,
            "severity": contract.severity.value,
            "rationale": contract.rationale,
            "contract_kind": contract.kind,
        }
        return payload.model_copy(
            update={
                "severity": _severity_from_finding_severity(contract.severity),
                "payload": {**(payload.payload or {}), **contract_payload},
                "graph_update": _merge_graph_updates(payload.graph_update, graph_update),
                "flagged_paths_increment": payload.flagged_paths_increment + contract.flagged_paths_increment,
                "risk": payload.risk or _risk_from_finding_severity(contract.severity),
                "current_stage": payload.current_stage or "verification",
            }
        )

    def _normalize_finding_confirmed(
        self,
        payload: IngestScanEventRequest,
        contract: VerifierFindingConfirmedContract,
    ) -> IngestScanEventRequest:
        graph_update = WorkflowGraphUpdate(
            upsert_nodes=[contract.finding_node] if contract.finding_node is not None else [],
            upsert_edges=list(contract.edges),
        )
        contract_payload = {
            "verifier_run_id": contract.verifier_run_id,
            "finding_id": contract.finding.id,
            "request_fingerprint": contract.request_fingerprint,
            "request_summary": contract.request_summary,
            "response_status_code": contract.response_status_code,
            "contract_kind": contract.kind,
        }
        severity = _severity_from_finding_severity(contract.finding.severity)
        return payload.model_copy(
            update={
                "severity": severity,
                "payload": {**(payload.payload or {}), **contract_payload},
                "graph_update": _merge_graph_updates(payload.graph_update, graph_update),
                "finding_updates": [*payload.finding_updates, contract.finding.model_copy(update={"status": FindingStatus.CONFIRMED})],
                "risk": payload.risk or _risk_from_finding_severity(contract.finding.severity),
                "current_stage": payload.current_stage or "reporting",
            }
        )


producer_contract_service = ProducerContractService()
