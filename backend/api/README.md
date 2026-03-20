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

## Initial endpoints

- `GET /` - service metadata.
- `GET /api/v1/health` - health response.
- `GET /api/v1/scans` - list persisted scan runs.
- `GET /api/v1/scans/{scan_id}` - read one scan run.
- `GET /api/v1/scans/{scan_id}/events` - list persisted runtime events for the scan.
- `GET /api/v1/scans/{scan_id}/events/stream` - stream live scan updates over SSE.
- `GET /api/v1/scans/{scan_id}/findings` - list findings for a single scan run.
- `GET /api/v1/scans/{scan_id}/report` - export a scan-level report payload.
- `GET /api/v1/scans/{scan_id}/evidence-bundle` - export detailed finding evidence for the scan.
- `GET /api/v1/scans/{scan_id}/verifier-runs` - list verifier runs linked to the scan.
- `GET /api/v1/scans/{scan_id}/verifier-jobs` - list queued or completed verifier jobs for the scan.
- `POST /api/v1/scans/{scan_id}/planner/run` - run the deterministic planner against persisted proxy observations.
- `POST /api/v1/scans/{scan_id}/events` - ingest proxy, orchestrator, mapper, or verifier runtime output.
- `GET /api/v1/scans/{scan_id}/workflow` - read the persisted graph for that scan run.
- `POST /api/v1/scans` - queue a new scan run and seed its workflow graph.
- `GET /api/v1/contracts/runtime-ingest` - list supported runtime producer contracts.
- `GET /api/v1/findings` - list findings with optional scan, severity, and status filters.
- `GET /api/v1/findings/{finding_id}` - read detailed finding data and evidence.
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
