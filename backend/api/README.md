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
- `routers/scans.py` - scan listing, detail, creation, and scan-linked workflow endpoints.
- `routers/workflows.py` - framework work-principle graph endpoints.
- `schemas/` - request and response models for current endpoints.
- `services/store.py` - in-memory persisted scan and workflow models shared across services.
- `services/scan_service.py` - scan service facade over the persisted store.
- `services/workflow_service.py` - workflow service facade for framework and scan graphs.

## Run locally

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
uvicorn api.app.main:app --reload
```

## Initial endpoints

- `GET /` - service metadata.
- `GET /api/v1/health` - health response.
- `GET /api/v1/scans` - list persisted scan runs.
- `GET /api/v1/scans/{scan_id}` - read one scan run.
- `GET /api/v1/scans/{scan_id}/workflow` - read the persisted graph for that scan run.
- `POST /api/v1/scans` - queue a new scan run and seed its workflow graph.
- `GET /api/v1/workflows/framework-principle` - read the framework work-principle graph.

The API server stays thin and delegates audit behavior to the backend modules that own it.
