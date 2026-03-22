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
- `GET /api/v1/scans/{scan_id}/actors`
- `GET /api/v1/scans/{scan_id}/findings`
- `GET /api/v1/scans/{scan_id}/report`
- `GET /api/v1/scans/{scan_id}/evidence-bundle`
- `GET /api/v1/scans/{scan_id}/verifier-runs`
- `GET /api/v1/scans/{scan_id}/verifier-jobs`
- `POST /api/v1/scans/{scan_id}/planner/run`
- `POST /api/v1/scans/{scan_id}/planner/run-ai`
- `GET /api/v1/scans/{scan_id}/planner/history`
- `POST /api/v1/scans/{scan_id}/events`
- `GET /api/v1/scans/{scan_id}/workflow`
- `POST /api/v1/scans`
- `POST /api/v1/scans/setup`
- `GET /api/v1/contracts/runtime-ingest`
- `GET /api/v1/findings`
- `GET /api/v1/findings/{finding_id}`
- `GET /api/v1/ai/providers/catalog`
- `GET /api/v1/scans/planner/runs/{planning_run_id}`
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

To exercise the queued verifier pipeline locally, you can enable the development autorunner in `backend/.env`:

```bash
AUDITOR_VERIFIER_AUTORUN_ENABLED=true
AUDITOR_VERIFIER_AUTORUN_MODE=deterministic-dev
```

To use the first real replay executor path instead, configure:

```bash
AUDITOR_VERIFIER_AUTORUN_ENABLED=true
AUDITOR_VERIFIER_AUTORUN_MODE=http-replay
AUDITOR_VERIFIER_REPLAY_BASE_URL=https://target.example.com
AUDITOR_VERIFIER_REPLAY_ACTOR_HEADERS_JSON={"actor-id":{"Authorization":"Bearer token"}}
```

Proxy-derived request artifacts are now persisted separately from scan events so replay executors can reuse stored request headers and bodies with higher fidelity.

Those replay artifacts now also have built-in retention and redaction controls so the backend can keep replay fidelity for a limited window without exposing raw secrets indefinitely.

The backend also now supports persisted source-code and OpenAPI artifact ingestion plus a provider-neutral AI catalog foundation.

It also now supports AI-assisted planning on top of deterministic candidates, with a no-key `mock` provider for local backend testing and an `openai-compatible` path for future real model integration.

The backend now also includes a provider-auth abstraction for AI connectivity with API key, browser/OAuth scaffolding, and cloud-credentials support.

That means the framework can be configured to use AI providers through:

- API keys
- browser/OAuth auth scaffolding where supported
- cloud credentials for providers like Google/Gemini

The deterministic backend planner now has explicit vulnerability coverage rules for:

- BOLA / IDOR
- BFLA
- tenant-isolation failures
- mass assignment
- excessive data exposure
- unsafe destructive actions
- SQL injection candidates
- SSRF candidates
- stored/reflected XSS candidates

The verifier now also supports out-of-band callback confirmation paths and taint-style source/sink correlation for stronger exploit hypotheses.

It now also has headless-browser execution hooks for DOM/XSS-style verification on top of HTTP replay.

The backend now also has a first autonomous pentest orchestration session layer that can plan, loop verifier work, and persist a step-by-step execution trace.

There is now also a one-shot scan setup flow so a user can provide core inputs like target base URL, actor headers, source code, and API specs, then let the backend bootstrap and start autonomous execution.

## Local Demo

An intentionally vulnerable local API for demo pentests lives in `examples/vulnerable_demo_api/`.

Run the target:

```bash
source .venv/bin/activate
uvicorn examples.vulnerable_demo_api.app:app --host 127.0.0.1 --port 9010
```

Then run the demo pentest script against a local backend:

```bash
python3 scripts/demo_pentest.py --backend-url http://127.0.0.1:8000/api/v1 --target-url http://127.0.0.1:9010
```

```bash
cd frontend
npm install
cp .env.example .env.local
npm run dev
```
