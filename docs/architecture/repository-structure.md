# Repository Structure

## Intended tree

```text
backend/
  orchestrator/
    agents/
    graph/
    memory/
    planners/
    prompts/
    policies/
  proxy/
    addons/
    capture/
    normalization/
    redaction/
    replay/
  tools/
    analyzer/
    workflow/
    verifier/
    remediation/
  api/
    app/
    routers/
    schemas/
    services/
    streaming/
frontend/
  app/
  features/
    dashboard/
    workflow/
    reports/
    realtime_logs/
    onboarding/
  components/
  lib/
  styles/
knowledge_base/
  owasp_api_top_10/
  detection_rules/
  prompt_assets/
shared/
  contracts/
  fixtures/
docs/
  architecture/
  adr/
deploy/
  docker/
  compose/
  kubernetes/
```

## Boundary rules

- `frontend/` consumes contracts from `shared/` and API surfaces from `backend/api/`.
- `backend/api/` orchestrates user-facing application flows and delegates audit work to backend modules.
- `backend/orchestrator/` does not own transport or UI state; it owns reasoning and tool selection.
- `backend/proxy/` does not own business logic; it owns capture, normalization, and replay preparation.
- `backend/tools/` performs deterministic analysis, workflow mapping, verification, and remediation support.
- `knowledge_base/` provides rules and reference material but should stay content-focused, not framework-focused.

## Why this structure fits the project brief

- It preserves the required module roles from `instruction.md` while using standard folder names.
- It leaves room for a basic FastAPI app and a frontend dashboard without reorganizing the repo later.
- It supports future multi-provider AI, multiple authentication methods, and self-hosted deployment assets.
- It separates powerful execution surfaces from user-facing control surfaces.

## Naming map to the project brief

- `backend/orchestrator/` corresponds to the AI orchestrator described in the brief.
- `backend/proxy/` corresponds to the proxy engine described in the brief.
- `backend/api/` corresponds to the FastAPI API server described in the brief.
- `frontend/` corresponds to the frontend client described in the brief.

## Evolution path

- Phase 1: scaffolded repository and architecture docs.
- Phase 2: FastAPI skeleton, frontend dashboard shell, and typed contracts.
- Phase 3: proxy capture ingestion, workflow mapper, and basic finding model.
- Phase 4: ReAct loop, verifier execution, and AI-generated remediation assistance.
