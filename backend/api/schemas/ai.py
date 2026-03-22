from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from api.schemas.planner import VerifierStrategy, VulnerabilityClass


class AiProviderKind(StrEnum):
    MOCK = "mock"
    OPENAI_COMPATIBLE = "openai_compatible"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    LOCAL = "local"


class AiCapability(StrEnum):
    CHAT = "chat"
    TOOL_CALLING = "tool_calling"
    JSON_OUTPUT = "json_output"
    EMBEDDINGS = "embeddings"


class AiAuthMethod(StrEnum):
    NONE = "none"
    API_KEY = "api_key"
    OAUTH_BROWSER = "oauth_browser"
    CLOUD_CREDENTIALS = "cloud_credentials"


class AiProviderAuthStatus(StrEnum):
    CONFIGURED = "configured"
    VALID = "valid"
    INVALID = "invalid"
    EXPIRED = "expired"


class AiProviderAuthMethodDescriptor(BaseModel):
    method: AiAuthMethod
    label: str
    description: str
    required_fields: list[str] = Field(default_factory=list)


class AiProviderDescriptor(BaseModel):
    key: str
    kind: AiProviderKind
    display_name: str
    description: str
    capabilities: list[AiCapability]
    config_fields: list[str] = Field(default_factory=list)
    auth_methods: list[AiProviderAuthMethodDescriptor] = Field(default_factory=list)


class AiProviderConfigSummary(BaseModel):
    id: str
    provider_key: str
    provider_kind: AiProviderKind
    display_name: str
    enabled: bool
    is_default: bool
    default_model: str | None = None
    auth_method: AiAuthMethod | None = None
    auth_status: AiProviderAuthStatus | None = None
    redacted_summary: dict[str, object] = Field(default_factory=dict)


class AiProviderConfigDetail(AiProviderConfigSummary):
    validated_at: str | None = None
    last_error: str | None = None
    created_at: str
    updated_at: str


class AiProviderConfigCreateRequest(BaseModel):
    provider_key: str = Field(min_length=2, max_length=80)
    display_name: str | None = Field(default=None, max_length=160)
    default_model: str | None = Field(default=None, max_length=120)
    enabled: bool = True
    is_default: bool = False


class AiProviderAuthUpsertRequest(BaseModel):
    auth_method: AiAuthMethod
    secret: dict[str, object] = Field(default_factory=dict)


class AiProviderValidationResult(BaseModel):
    config_id: str
    provider_key: str
    auth_method: AiAuthMethod | None = None
    status: AiProviderAuthStatus
    message: str


class AiOAuthAuthorizationResponse(BaseModel):
    provider_key: str
    config_id: str
    authorization_url: str
    callback_url: str
    state: str


class AiProviderCatalog(BaseModel):
    version: str
    providers: list[AiProviderDescriptor]


class AiPlanningCandidate(BaseModel):
    path_id: str
    title: str
    severity: str
    vulnerability_class: VulnerabilityClass
    confidence: int = Field(ge=0, le=100)
    matched_rule: str
    verifier_strategy: VerifierStrategy
    rationale: str
    step_count: int = Field(ge=2)
    matched_signals: list[str] = Field(default_factory=list)
    workflow_node_ids: list[str] = Field(default_factory=list)


class AiPlanningProposal(BaseModel):
    path_id: str
    include_in_plan: bool = True
    priority_score: int = Field(ge=0, le=100)
    recommended_severity: str
    suggested_rationale: str
    explanation: str
    tags: list[str] = Field(default_factory=list)


class AiPlanningRunRequest(BaseModel):
    provider_key: str | None = None
    apply: bool = True
    candidate_limit: int = Field(default=8, ge=1, le=50)
    min_priority_score: int = Field(default=50, ge=0, le=100)


class AiPlanningRunResponse(BaseModel):
    planning_run_id: str
    scan_id: str
    provider_key: str
    candidate_count: int
    suggested_count: int
    emitted_count: int
    skipped_existing_count: int
    apply: bool
    proposals: list[AiPlanningProposal]


class AiNextAction(StrEnum):
    DETERMINISTIC_PLANNER = "deterministic_planner"
    AI_PLANNER = "ai_planner"
    VERIFIER_CYCLE = "verifier_cycle"
    REMEDIATION = "remediation"
    REPORT = "report"
    SUMMARY = "summary"


class AiBacklogCandidate(BaseModel):
    path_id: str
    title: str
    vulnerability_class: VulnerabilityClass
    severity: str
    confidence: int = Field(ge=0, le=100)
    verifier_strategy: VerifierStrategy
    status: str


class AiVerifierOutcome(BaseModel):
    job_id: str
    status: str
    finding_id: str | None = None
    verifier_run_id: str | None = None
    note: str | None = None


class AiOrchestrationMemory(BaseModel):
    proxy_event_count: int = 0
    finding_count: int = 0
    pending_verifier_jobs: int = 0
    deterministic_planning_runs: int = 0
    ai_planning_runs: int = 0
    last_deterministic_event_count: int = 0
    last_deterministic_candidate_count: int = 0
    last_ai_candidate_count: int = 0
    completed_verifier_cycles: int = 0
    candidate_backlog: list[AiBacklogCandidate] = Field(default_factory=list)
    unresolved_hypotheses: list[AiBacklogCandidate] = Field(default_factory=list)
    verifier_outcomes: list[AiVerifierOutcome] = Field(default_factory=list)
    remediation_backlog: list[str] = Field(default_factory=list)
    report_backlog: list[str] = Field(default_factory=list)


class AiNextActionRequest(BaseModel):
    scan_id: str
    use_ai_planner: bool = True
    max_planning_passes: int
    max_ai_planning_passes: int
    max_verifier_cycles: int
    memory: AiOrchestrationMemory


class AiNextActionDecision(BaseModel):
    next_action: AiNextAction
    confidence: int = Field(ge=0, le=100)
    rationale: str
    supporting_observations: list[str] = Field(default_factory=list)


class AiHypothesisCandidate(BaseModel):
    hypothesis_id: str
    source_path_id: str
    title: str
    vulnerability_class: VulnerabilityClass
    severity: str
    confidence: int = Field(ge=0, le=100)
    matched_rule: str
    verifier_strategy: VerifierStrategy
    status: str
    available_payload_variant_ids: list[str] = Field(default_factory=list)
    matched_signals: list[str] = Field(default_factory=list)


class AiHypothesisSelectionRequest(BaseModel):
    scan_id: str
    hypotheses: list[AiHypothesisCandidate] = Field(default_factory=list)


class AiHypothesisSelectionDecision(BaseModel):
    selected_hypothesis_id: str
    selected_source_path_id: str
    selected_verifier_strategy: VerifierStrategy
    selected_payload_variant_id: str | None = None
    confidence: int = Field(ge=0, le=100)
    rationale: str
    supporting_observations: list[str] = Field(default_factory=list)
