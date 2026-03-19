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
- `routers/workflows.py` - framework work-principle graph endpoints.
- `schemas/` - request and response models for current endpoints.
- `app/database.py` - SQLAlchemy engine and session management.
- `app/db_models.py` - relational persistence models for scans, graphs, and events.
- `services/store.py` - Postgres-oriented persistence and graph mutation layer.
- `services/event_service.py` - scan event ingestion and runtime snapshot facade.
- `services/scan_service.py` - scan service facade over the persisted store.
- `services/workflow_service.py` - workflow service facade for framework and scan graphs.

## Run locally

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
cp .env.example .env
uvicorn api.app.main:app --reload --env-file .env
```

## Initial endpoints

- `GET /` - service metadata.
- `GET /api/v1/health` - health response.
- `GET /api/v1/scans` - list persisted scan runs.
- `GET /api/v1/scans/{scan_id}` - read one scan run.
- `GET /api/v1/scans/{scan_id}/events` - list persisted runtime events for the scan.
- `GET /api/v1/scans/{scan_id}/events/stream` - stream live scan updates over SSE.
- `POST /api/v1/scans/{scan_id}/events` - ingest proxy, orchestrator, mapper, or verifier runtime output.
- `GET /api/v1/scans/{scan_id}/workflow` - read the persisted graph for that scan run.
- `POST /api/v1/scans` - queue a new scan run and seed its workflow graph.
- `GET /api/v1/workflows/framework-principle` - read the framework work-principle graph.

The API server stays thin and delegates audit behavior to the backend modules that own it.
