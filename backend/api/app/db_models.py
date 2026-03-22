from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class ScanRunRecord(Base):
    __tablename__ = "scan_runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    target: Mapped[str | None] = mapped_column(String(120), nullable=True)
    target_base_url: Mapped[str | None] = mapped_column(String(300), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    current_stage: Mapped[str] = mapped_column(String(64), nullable=False)
    findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    flagged_paths: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk: Mapped[str] = mapped_column(String(32), nullable=False)
    workflow_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    workflow: Mapped[WorkflowGraphRecord | None] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        uselist=False,
    )
    events: Mapped[list[ScanEventRecord]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="ScanEventRecord.id",
    )
    findings: Mapped[list[FindingRecord]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="FindingRecord.created_at",
    )


class ScanActorProfileRecord(Base):
    __tablename__ = "scan_actor_profiles"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    headers_json: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class WorkflowGraphRecord(Base):
    __tablename__ = "workflow_graphs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=True, unique=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    flagged_paths: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    nodes_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    edges_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    scan: Mapped[ScanRunRecord | None] = relationship(back_populates="workflow")


class ScanEventRecord(Base):
    __tablename__ = "scan_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    stage: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    payload_json: Mapped[dict[str, object] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    scan: Mapped[ScanRunRecord] = relationship(back_populates="events")


class ReplayArtifactRecord(Base):
    __tablename__ = "replay_artifacts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    request_fingerprint: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    actor: Mapped[str | None] = mapped_column(String(120), nullable=True)
    method: Mapped[str] = mapped_column(String(16), nullable=False)
    host: Mapped[str] = mapped_column(String(120), nullable=False)
    path: Mapped[str] = mapped_column(String(400), nullable=False)
    request_headers_json: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False)
    request_body_base64: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_content_type: Mapped[str | None] = mapped_column(String(160), nullable=True)
    response_status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_headers_json: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False)
    response_body_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    purged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)


class CallbackExpectationRecord(Base):
    __tablename__ = "callback_expectations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    verifier_job_id: Mapped[str | None] = mapped_column(ForeignKey("verifier_jobs.id", ondelete="SET NULL"), nullable=True, index=True)
    token: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CallbackEventRecord(Base):
    __tablename__ = "callback_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    expectation_id: Mapped[str] = mapped_column(ForeignKey("callback_expectations.id", ondelete="CASCADE"), nullable=False, index=True)
    method: Mapped[str] = mapped_column(String(16), nullable=False)
    path: Mapped[str] = mapped_column(String(400), nullable=False)
    query_string: Mapped[str | None] = mapped_column(Text, nullable=True)
    headers_json: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False)
    body_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(120), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(300), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)


class ScanArtifactRecord(Base):
    __tablename__ = "scan_artifacts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    path: Mapped[str | None] = mapped_column(String(300), nullable=True)
    language: Mapped[str | None] = mapped_column(String(60), nullable=True)
    format: Mapped[str | None] = mapped_column(String(40), nullable=True)
    checksum: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    content_text: Mapped[str] = mapped_column(Text, nullable=False)
    content_excerpt: Mapped[str] = mapped_column(Text, nullable=False)
    parsed_summary_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class FindingRecord(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False)
    endpoint: Mapped[str | None] = mapped_column(String(200), nullable=True)
    actor: Mapped[str | None] = mapped_column(String(120), nullable=True)
    impact_summary: Mapped[str] = mapped_column(Text, nullable=False)
    remediation_summary: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    impact: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    context_references_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    workflow_node_ids_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    tags_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    scan: Mapped[ScanRunRecord] = relationship(back_populates="findings")


class VerifierRunRecord(Base):
    __tablename__ = "verifier_runs"

    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    endpoint: Mapped[str | None] = mapped_column(String(200), nullable=True)
    actor: Mapped[str | None] = mapped_column(String(120), nullable=True)
    request_fingerprint: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    request_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    context_references_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    workflow_node_ids_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class VerifierJobRecord(Base):
    __tablename__ = "verifier_jobs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    source_path_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    payload_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    worker_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    verifier_run_id: Mapped[str | None] = mapped_column(ForeignKey("verifier_runs.id", ondelete="SET NULL"), nullable=True, index=True)
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class PlanningRunRecord(Base):
    __tablename__ = "planning_runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    mode: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    provider_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    apply: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    candidate_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    suggested_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    emitted_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    skipped_existing_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    queued_job_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    request_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    candidates_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    proposals_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class OrchestrationSessionRecord(Base):
    __tablename__ = "orchestration_sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    mode: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    provider_key: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    current_phase: Mapped[str] = mapped_column(String(64), nullable=False)
    max_verifier_cycles: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    completed_verifier_cycles: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    request_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    memory_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class OrchestrationStepRecord(Base):
    __tablename__ = "orchestration_steps"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("orchestration_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    payload_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    memory_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)


class OrchestrationHypothesisRecord(Base):
    __tablename__ = "orchestration_hypotheses"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    session_id: Mapped[str | None] = mapped_column(ForeignKey("orchestration_sessions.id", ondelete="SET NULL"), nullable=True, index=True)
    planning_run_id: Mapped[str | None] = mapped_column(ForeignKey("planning_runs.id", ondelete="SET NULL"), nullable=True, index=True)
    source_path_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    canonical_key: Mapped[str] = mapped_column(String(240), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    vulnerability_class: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False)
    matched_rule: Mapped[str] = mapped_column(String(120), nullable=False)
    verifier_strategy: Mapped[str] = mapped_column(String(64), nullable=False)
    matched_signals_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    selected_payload_variant_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    selected_verifier_strategy: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decision_source: Mapped[str | None] = mapped_column(String(32), nullable=True)
    verifier_job_id: Mapped[str | None] = mapped_column(ForeignKey("verifier_jobs.id", ondelete="SET NULL"), nullable=True, index=True)
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True)
    merged_into_hypothesis_id: Mapped[str | None] = mapped_column(ForeignKey("orchestration_hypotheses.id", ondelete="SET NULL"), nullable=True, index=True)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reopen_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    stale_cycles: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_transition_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ServiceAccountRecord(Base):
    __tablename__ = "service_accounts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    scopes_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    token_prefix: Mapped[str] = mapped_column(String(24), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
