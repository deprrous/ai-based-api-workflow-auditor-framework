# ai-based-api-workflow-auditor-framework

Architecture-first repository for an agentic AI API auditing framework focused on workflow reasoning, verification, and developer-friendly reporting.

## Current state

- `backend/` now has a working FastAPI control plane with relational persistence, scan-event ingestion, and live SSE updates.
- `frontend/` now has a Next.js dashboard wired to persisted scan-linked workflow graphs and live runtime feeds.
- framework-principle graphs and scan-run graphs are separated, so the UI can explain both how the framework works and what a real scan found from a target.

## Key routes

- `GET /api/v1/scans`
- `GET /api/v1/scans/{scan_id}`
- `GET /api/v1/scans/{scan_id}/events`
- `GET /api/v1/scans/{scan_id}/events/stream`
- `GET /api/v1/scans/{scan_id}/findings`
- `GET /api/v1/scans/{scan_id}/report`
- `GET /api/v1/scans/{scan_id}/evidence-bundle`
- `GET /api/v1/scans/{scan_id}/verifier-runs`
- `GET /api/v1/scans/{scan_id}/verifier-jobs`
- `POST /api/v1/scans/{scan_id}/planner/run`
- `POST /api/v1/scans/{scan_id}/events`
- `GET /api/v1/scans/{scan_id}/workflow`
- `POST /api/v1/scans`
- `GET /api/v1/contracts/runtime-ingest`
- `GET /api/v1/findings`
- `GET /api/v1/findings/{finding_id}`
- `GET /api/v1/verifier-jobs/{verifier_job_id}`
- `POST /api/v1/verifier-jobs/claim`
- `GET /api/v1/verifier-runs/{verifier_run_id}`
- `GET /api/v1/service-accounts`
- `POST /api/v1/service-accounts`
- `GET /api/v1/workflows/framework-principle`

## Key docs

- `instruction.md` - original project brief.
- `docs/architecture/tech-stack.md` - selected technology stack and near-term infrastructure choices.
- `docs/architecture/framework-principle.md` - framework work-principle diagram and explanation.
- `docs/architecture/overview.md` - high-level system overview.
- `docs/architecture/repository-structure.md` - repository boundaries and module roles.
- `docs/architecture/scan-lifecycle.md` - end-to-end audit lifecycle.

## Run locally

### One command

```bash
./scripts/dev.sh
```

Or with `make`:

```bash
make dev
```

The script will:

- create `backend/.env` and `frontend/.env.local` from examples if needed
- create the root `.venv` and install backend dependencies if needed
- install frontend dependencies if needed
- start Postgres, the FastAPI backend, and the Next.js frontend together
- pick the next free frontend or backend port automatically if `3000` or `8000` is busy

Useful make targets:

- `make dev` - run the stack in the current terminal
- `make dev-bg` - start the stack in the background
- `make logs` - follow saved backend and frontend logs
- `make stop` - stop the saved dev services
- `make status` - show saved runtime state

### Manual

```bash
docker compose -f deploy/compose/postgres.yaml up -d
cp backend/.env.example backend/.env
```

```bash
source .venv/bin/activate
alembic -c backend/alembic.ini upgrade head
uvicorn api.app.main:app --reload --app-dir backend --env-file backend/.env
```

```bash
cd frontend
npm install
cp .env.example .env.local
npm run dev
```
