# ai-based-api-workflow-auditor-framework

Architecture-first repository for an agentic AI API auditing framework focused on workflow reasoning, verification, and developer-friendly reporting.

## Current state

- `backend/` now has a working FastAPI control plane with scan and workflow endpoints.
- `frontend/` now has a Next.js dashboard wired to persisted scan-linked workflow graphs.
- framework-principle graphs and scan-run graphs are separated, so the UI can explain both how the framework works and what a real scan found.

## Key routes

- `GET /api/v1/scans`
- `GET /api/v1/scans/{scan_id}`
- `GET /api/v1/scans/{scan_id}/workflow`
- `POST /api/v1/scans`
- `GET /api/v1/workflows/framework-principle`

## Key docs

- `instruction.md` - original project brief.
- `docs/architecture/framework-principle.md` - framework work-principle diagram and explanation.
- `docs/architecture/overview.md` - high-level system overview.
- `docs/architecture/repository-structure.md` - repository boundaries and module roles.
- `docs/architecture/scan-lifecycle.md` - end-to-end audit lifecycle.

## Run locally

```bash
source .venv/bin/activate
uvicorn api.app.main:app --reload --app-dir backend
```

```bash
cd frontend
npm install
cp .env.example .env.local
npm run dev
```
