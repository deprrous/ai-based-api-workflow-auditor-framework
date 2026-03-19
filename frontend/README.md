# Frontend

Next.js dashboard for the AI API Workflow Auditor.

## Current pages

- `/` - dashboard with live scan-run cards and framework-principle summary.
- `/framework` - framework work-principle graph.
- `/workflows/[scanId]` - persisted workflow graph for a specific scan run.

## Key areas

- `app/` - app router entrypoints and global styles.
- `features/dashboard/` - dashboard screen composition.
- `features/workflow/` - workflow graph screen composition.
- `components/` - reusable workflow graph renderer.
- `lib/` - API clients, formatters, and frontend types.

## Run locally

```bash
cd frontend
npm install
cp .env.example .env.local
npm run dev
```

The frontend expects the FastAPI backend to be available at `http://127.0.0.1:8000/api/v1` unless overridden by environment variables.
