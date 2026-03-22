# API

This module hosts the FastAPI control plane exposed to the frontend.

## Planned internal areas

- `app/` - application bootstrap and dependency assembly.
- `routers/` - HTTP and WebSocket or SSE route groups.
- `schemas/` - request and response contracts.
- `services/` - application services used by the routes.
- `streaming/` - real-time run logs, scan events, and progress streams.

## Current scaffold

- `app/main.py` - FastAPI app factory and startup entrypoint.
- `routers/health.py` - health endpoint for basic service verification.
- `routers/scans.py` - scan listing, detail, creation, event ingestion, SSE, and scan-linked workflow endpoints.
- `routers/contracts.py` - runtime producer contract catalog endpoints.
- `routers/findings.py` - finding listing and detail endpoints.
- `routers/hypotheses.py` - persisted orchestration hypothesis listing and detail endpoints.
- `routers/ai.py` - provider catalog, provider config, auth, validation, and OAuth scaffolding endpoints.
- `routers/artifacts.py` - source-code and API-spec artifact ingestion and listing endpoints.
- `routers/orchestration.py` - autonomous orchestration session endpoints.
- `routers/planner.py` - deterministic workflow planner execution endpoints.
- `routers/reports.py` - scan report and evidence export endpoints.
- `routers/service_accounts.py` - service-account management endpoints for backend workers.
- `routers/verifier_jobs.py` - verifier job queue endpoints and lifecycle transitions.
- `routers/verifier_runs.py` - verifier-run listing and detail endpoints.
- `routers/workflows.py` - framework work-principle graph endpoints.
- `schemas/` - request and response models for current endpoints.
- `app/database.py` - SQLAlchemy engine and session management.
- `app/db_models.py` - relational persistence models for scans, graphs, and events.
- `services/finding_service.py` - finding retrieval and filtering facade.
- `services/hypothesis_service.py` - orchestration hypothesis retrieval and selection support.
- `services/ai_provider_service.py` - provider-neutral AI catalog and provider resolution service.
- `services/ai_auth_service.py` - provider auth/config management, validation, and OAuth state handling.
- `services/secret_service.py` - encrypted storage helper for provider credentials.
- `services/artifact_service.py` - source-code and OpenAPI ingestion service.
- `services/orchestration_service.py` - autonomous orchestration session lifecycle and trace persistence.
- `services/planner_service.py` - deterministic planner that derives flagged paths from proxy observations.
- `services/report_service.py` - scan report and evidence bundle builder.
- `services/service_account_service.py` - backend worker credential lifecycle and authentication support.
- `services/verifier_job_service.py` - queued verifier job retrieval and lifecycle transitions.
- `services/verifier_run_service.py` - verifier-run retrieval for replay-backed findings.
- `services/store.py` - Postgres-oriented persistence and graph mutation layer.
- `services/event_service.py` - scan event ingestion and runtime snapshot facade.
- `services/scan_service.py` - scan service facade over the persisted store.
- `services/workflow_service.py` - workflow service facade for framework and scan graphs.

## Run locally

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
cp .env.example .env
alembic upgrade head
uvicorn api.app.main:app --reload --env-file .env
```

## Database migrations

```bash
cd backend
source .venv/bin/activate
alembic upgrade head
```

Use Alembic for schema evolution instead of relying on ad hoc table creation when changing persisted backend models.

## Runtime ingest authentication

Worker-style runtime ingestion endpoints expect a token from `AUDITOR_INGEST_TOKENS`.

- send `X-Auditor-Ingest-Token: <token>`
- or send `Authorization: Bearer <token>`

This keeps proxy, orchestrator, mapper, and verifier producers separate from anonymous public API traffic.

Administrative service-account endpoints accept either:

- `X-Auditor-Admin-Token: <token>`
- or `Authorization: Bearer <token>`

Use those endpoints to create rotating worker credentials instead of relying only on long-lived environment tokens.

Verifier job worker endpoints accept either:

- `X-Auditor-Ingest-Token: <token>`
- or `Authorization: Bearer <token>`

Service accounts should include `run:verifier_jobs` when a worker must claim, retry, or complete queued verifier jobs.

## Autonomous orchestration

Autonomous sessions now persist first-class hypotheses with lifecycle states such as:

- `new`
- `prioritized`
- `downgraded`
- `verifying`
- `confirmed`
- `rejected`
- `abandoned`
- `merged`

The orchestration loop can also use the provider-neutral AI layer to:

- choose the next orchestration action from memory
- choose which unresolved hypothesis to pursue next
- choose which verifier strategy or payload variant to try first

The backend now also supports automatic hypothesis transitions from later evidence, including merge, reopen, downgrade, and abandonment behavior, plus remediation/report follow-up subloops after confirmations.

Deterministic fallback remains in place so orchestration stays resilient when AI is unavailable or makes a poor choice.

The backend also now supports a provider-auth abstraction for AI connectivity with:

- `api_key`
- `oauth_browser`
- `cloud_credentials`

Provider auth is stored separately from provider config, credentials are encrypted at rest, and normal API reads return only redacted summaries.

## Automatic verifier runner

The backend can also process queued verifier jobs automatically in the API process for development.

- `AUDITOR_VERIFIER_AUTORUN_ENABLED=true`
- `AUDITOR_VERIFIER_AUTORUN_MODE=deterministic-dev`
- `AUDITOR_VERIFIER_AUTORUN_POLL_INTERVAL=2.0`
- `AUDITOR_VERIFIER_AUTORUN_WORKER_ID=verifier-autorun`

`deterministic-dev` is for local pipeline testing only. It exercises the queue and finding lifecycle without pretending to be a production-grade replay engine.

For a real backend replay executor, configure:

- `AUDITOR_VERIFIER_AUTORUN_ENABLED=true`
- `AUDITOR_VERIFIER_AUTORUN_MODE=http-replay`
- `AUDITOR_VERIFIER_REPLAY_BASE_URL=https://target.example.com`
- `AUDITOR_VERIFIER_REPLAY_ACTOR_HEADERS_JSON={"actor-id":{"Authorization":"Bearer token"}}`

For browser-assisted XSS verification, also configure:

- `AUDITOR_BROWSER_EXECUTION_ENABLED=true`
- `AUDITOR_BROWSER_ENGINE=chromium`
- `AUDITOR_BROWSER_HEADLESS=true`
- `AUDITOR_BROWSER_TIMEOUT_SECONDS=8.0`

The `http-replay` executor uses replay plans attached to queued verifier jobs and performs real HTTP requests against the configured target.

Current replay mutation support includes:

- path and object-id mutation
- JSON body field mutation
- role and permission header mutation
- per-request actor switching
- token/session refresh retry logic
- structured payload variants per vulnerability class

Current replay assertion and response analysis support includes:

- SQL error and time-based indicators
- SSRF metadata or callback-style indicators
- stored/reflected XSS marker confirmation
- cross-actor authorization drift comparison

Out-of-band callback support is now available through callback expectations and public callback capture endpoints.

Callback events now include:

- request fingerprinting
- source IP classification
- metadata marker scoring
- browser-like signal detection

Raw replayable request artifacts are stored separately from scan event payloads so workers can reproduce captured POST, PATCH, cookie, and header state more accurately.

Retention policy is now built in:

- artifacts keep replayable raw material for a limited window
- public artifact APIs always return redacted headers and body previews
- expired artifacts are purged automatically and become non-replayable

Relevant settings:

- `AUDITOR_REPLAY_ARTIFACT_RETENTION_HOURS`
- `AUDITOR_REPLAY_ARTIFACT_RETENTION_AUTORUN_ENABLED`
- `AUDITOR_REPLAY_ARTIFACT_RETENTION_POLL_INTERVAL`
- `AUDITOR_REPLAY_ARTIFACT_REDACT_HEADERS`
- `AUDITOR_REPLAY_ARTIFACT_REDACT_BODY_KEYS`

## Producer contracts

Runtime producers should publish against `GET /api/v1/contracts/runtime-ingest`.

The backend currently codifies these producer contracts:

- `proxy.http_observed`
- `orchestrator.hypothesis_created`
- `workflow_mapper.path_flagged`
- `verifier.finding_confirmed`

Those contracts normalize target-derived runtime data into consistent graph updates, flagged paths, and findings.

Confirmed verifier findings can also persist:

- verifier run metadata
- evidence bundles
- correlated source-code and API-spec context references

High-risk workflow paths can now automatically queue verifier jobs so replay workers can process them asynchronously with retries.

The workflow planner can now consume persisted `proxy.http_observed` events and emit `workflow_mapper.path_flagged` contracts automatically.

It can also enrich planned paths with matching ingested source-code and OpenAPI artifact context.

Source-code artifacts now also expose taint-style source/sink correlation so runtime paths can be supported by stronger code-review hypotheses.

Current explicit coverage classes in the backend planner:

- `bola_idor`
- `bfla`
- `tenant_isolation`
- `mass_assignment`
- `excessive_data_exposure`
- `unsafe_destructive_action`
- `sqli`
- `ssrf`
- `stored_xss`
- `reflected_xss`

Planner outputs now carry:

- vulnerability class
- confidence score
- matched rule id
- verifier strategy
- matched signals and explanation

## Initial endpoints

- `GET /` - service metadata.
- `GET /api/v1/health` - health response.
- `GET /api/v1/scans` - list persisted scan runs.
- `GET /api/v1/scans/{scan_id}` - read one scan run.
- `GET /api/v1/scans/{scan_id}/events` - list persisted runtime events for the scan.
- `GET /api/v1/scans/{scan_id}/events/stream` - stream live scan updates over SSE.
- `GET /api/v1/scans/{scan_id}/actors` - list stored actor profiles for replay and browser execution.
- `POST /api/v1/artifacts/scan/{scan_id}/source` - ingest source code for analyzer and correlation use.
- `POST /api/v1/artifacts/scan/{scan_id}/api-spec` - ingest OpenAPI or Swagger content.
- `GET /api/v1/artifacts/scan/{scan_id}` - list ingested artifacts for a scan.
- `GET /api/v1/artifacts/{artifact_id}` - read artifact detail and parsed summary.
- `GET /api/v1/callbacks/scan/{scan_id}` - list callback expectations for a scan.
- `GET /api/v1/callbacks/token/{token}` - read callback expectation detail.
- `GET /api/v1/callbacks/public/{token}` - public callback endpoint for SSRF/XSS confirmation.
- `GET /api/v1/scans/{scan_id}/findings` - list findings for a single scan run.
- `GET /api/v1/scans/{scan_id}/report` - export a scan-level report payload.
- `GET /api/v1/scans/{scan_id}/evidence-bundle` - export detailed finding evidence for the scan.
- `GET /api/v1/scans/{scan_id}/verifier-runs` - list verifier runs linked to the scan.
- `GET /api/v1/scans/{scan_id}/verifier-jobs` - list queued or completed verifier jobs for the scan.
- `POST /api/v1/scans/{scan_id}/planner/run` - run the deterministic planner against persisted proxy observations.
- `POST /api/v1/scans/{scan_id}/planner/run-ai` - run the AI-assisted planner on deterministic candidates.
- `GET /api/v1/scans/{scan_id}/planner/history` - list planning runs for the scan.
- `GET /api/v1/scans/planner/runs/{planning_run_id}` - read planner run detail and compare decisions.
- `POST /api/v1/scans/{scan_id}/orchestration/start` - start an autonomous pentest orchestration session.
- `GET /api/v1/scans/{scan_id}/orchestration/sessions` - list orchestration sessions for the scan.
- `GET /api/v1/scans/orchestration/sessions/{session_id}` - read orchestration session detail and trace.
- `POST /api/v1/scans/{scan_id}/events` - ingest proxy, orchestrator, mapper, or verifier runtime output.
- `GET /api/v1/scans/{scan_id}/workflow` - read the persisted graph for that scan run.
- `POST /api/v1/scans` - queue a new scan run and seed its workflow graph.
- `POST /api/v1/scans/setup` - create a scan, store actor profiles, ingest artifacts, and optionally start orchestration in one request.
- `GET /api/v1/contracts/runtime-ingest` - list supported runtime producer contracts.
- `GET /api/v1/ai/providers/catalog` - list the provider-neutral AI catalog for future orchestration wiring.
- `GET /api/v1/ai/providers/configs` - list stored AI provider configs.
- `POST /api/v1/ai/providers/configs` - create an AI provider config.
- `GET /api/v1/ai/providers/configs/{config_id}` - read one AI provider config.
- `POST /api/v1/ai/providers/configs/{config_id}/auth` - upsert auth for a provider config.
- `POST /api/v1/ai/providers/configs/{config_id}/validate` - validate a provider config.
- `POST /api/v1/ai/providers/configs/{config_id}/activate` - activate a provider config as default.
- `POST /api/v1/ai/providers/{provider_key}/oauth/authorize` - start browser/OAuth auth for a provider.
- `GET /api/v1/ai/providers/{provider_key}/oauth/callback` - finalize browser/OAuth auth for a provider.
- `GET /api/v1/findings` - list findings with optional scan, severity, and status filters.
- `GET /api/v1/findings/{finding_id}` - read detailed finding data and evidence.
- `GET /api/v1/hypotheses/scan/{scan_id}` - list persisted orchestration hypotheses for a scan.
- `GET /api/v1/hypotheses/{hypothesis_id}` - read one orchestration hypothesis in detail.
- `GET /api/v1/replay-artifacts/{artifact_id}` - read a persisted replay artifact for worker execution.
- `GET /api/v1/replay-artifacts/scan/{scan_id}` - list persisted replay artifacts for a scan.
- `GET /api/v1/verifier-jobs/{verifier_job_id}` - read queued verifier job detail.
- `POST /api/v1/verifier-jobs/claim` - claim the next queued verifier job.
- `POST /api/v1/verifier-jobs/{verifier_job_id}/complete` - mark a verifier job as completed.
- `POST /api/v1/verifier-jobs/{verifier_job_id}/fail` - retry or fail a verifier job.
- `GET /api/v1/verifier-runs/{verifier_run_id}` - read persisted verifier replay detail.
- `GET /api/v1/service-accounts` - list backend service accounts.
- `POST /api/v1/service-accounts` - create a backend service account and return a raw token once.
- `POST /api/v1/service-accounts/{service_account_id}/rotate` - rotate a service-account token.
- `POST /api/v1/service-accounts/{service_account_id}/revoke` - revoke a service account.
- `GET /api/v1/workflows/framework-principle` - read the framework work-principle graph.

The API server stays thin and delegates audit behavior to the backend modules that own it.
