# Codex Handoff

## Project Summary

This repository is a self-hosted, agentic AI API auditing framework.

Main goal:
- user gives target base URL, actor/auth context, source code, and OpenAPI/spec
- backend autonomously plans, verifies, iterates, and produces evidence-backed findings

Core backend abilities already present:
- scan setup and persistence
- source/spec ingestion
- workflow planning
- AI-assisted planning
- hypotheses with lifecycle
- verifier jobs and replay execution
- SSRF/XSS callback support
- browser-assisted XSS hooks
- findings, reports, evidence bundles, and scan comparison

## Current Branch State

- branch: `main`
- synced with: `origin/main`
- do not touch these personal untracked files:
  - `sess`
  - `understanding.mn`

Recent commits:
- `19820c5` add bola and bfla demo coverage
- `7dd4695` add scan inspection helper
- `4bc13c9` map verifier findings to real vuln categories
- `ee54f6e` fallback cleanly when ai planner is rate limited
- `70b610a` use local callback bridge for openai plus auth
- `556351e` allow demo runner to choose ai provider
- `f8d7757` add real openai plus browser auth path
- `6f31db0` add vulnerable demo target and pentest runner

## Important Backend Routes

- `POST /api/v1/scans/setup`
- `POST /api/v1/scans/{scan_id}/orchestration/start`
- `GET /api/v1/scans/{scan_id}/orchestration/sessions`
- `GET /api/v1/scans/orchestration/sessions/{session_id}`
- `GET /api/v1/hypotheses/scan/{scan_id}`
- `GET /api/v1/scans/{scan_id}/verifier-jobs`
- `GET /api/v1/scans/{scan_id}/findings`
- `GET /api/v1/scans/{scan_id}/report`
- `GET /api/v1/ai/providers/catalog`
- `POST /api/v1/ai/providers/configs`
- `POST /api/v1/ai/providers/openai/oauth/authorize`

## Detection Coverage

Current explicit backend coverage:
- BOLA / IDOR
- BFLA
- tenant isolation
- mass assignment
- excessive data exposure
- unsafe destructive actions
- SQLi
- SSRF
- stored XSS
- reflected XSS

## Local Run Instructions

### Backend

```bash
source .venv/bin/activate
alembic -c backend/alembic.ini upgrade head
uvicorn api.app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

### Full dev stack

```bash
make dev
```

### Vulnerable demo target

```bash
source .venv/bin/activate
uvicorn examples.vulnerable_demo_api.app:app --host 127.0.0.1 --port 9010
```

### Demo pentest

```bash
python3 scripts/demo_pentest.py \
  --backend-url http://127.0.0.1:8000/api/v1 \
  --target-url http://127.0.0.1:9010 \
  --ai-provider-key openai
```

### Inspect backend state after a run

```bash
python3 scripts/inspect_scan.py \
  --backend-url http://127.0.0.1:8000/api/v1 \
  --scan-id <scan-id>
```

## OpenAI Plus / Pro Browser Auth

Current state:
- browser auth flow is implemented enough to store and validate an OpenAI browser-auth config
- actual planning requests may still hit provider-side `429 Too Many Requests`
- orchestration falls back to deterministic logic when AI planning fails

Typical flow:

1. Create config
```bash
curl -s -X POST "http://127.0.0.1:8000/api/v1/ai/providers/configs" \
  -H "X-Auditor-Admin-Token: dev-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "provider_key": "openai",
    "display_name": "OpenAI Plus Browser Auth",
    "default_model": "gpt-5.1",
    "enabled": true,
    "is_default": true
  }' | python3 -m json.tool
```

2. Start auth
```bash
curl -s -X POST "http://127.0.0.1:8000/api/v1/ai/providers/openai/oauth/authorize?config_id=<config_id>" \
  -H "X-Auditor-Admin-Token: dev-admin-token" | python3 -m json.tool
```

3. Open the returned `authorization_url`

4. Validate
```bash
curl -s -X POST "http://127.0.0.1:8000/api/v1/ai/providers/configs/<config_id>/validate" \
  -H "X-Auditor-Admin-Token: dev-admin-token" | python3 -m json.tool
```

## Current Demo Status

The local vulnerable demo app currently produces strong signals for:
- SQLi
- SSRF
- reflected XSS
- BFLA

It now also contains BOLA / tenant-isolation style vulnerable routes, but that class still needs tuning to confirm reliably in every demo run.

## Highest-Priority Next Work

1. Make the BOLA / tenant-isolation demo confirm reliably.
2. Keep the autonomous backend loop focused on deadline-critical core features.
3. Continue improving demonstration quality and reliability of evidence.

## Suggested Prompt For Next Session

```text
Continue development on branch main.

Project: self-hosted, agentic AI API auditing framework.

Main current priority:
1. Make the BOLA / tenant-isolation demo confirm reliably in the local autonomous pentest demo.

Important context:
- Do not touch untracked personal files `sess` and `understanding.mn`.
- Local demo target lives in `examples/vulnerable_demo_api/`.
- Demo runner is `scripts/demo_pentest.py`.
- Backend inspection helper is `scripts/inspect_scan.py`.
- OpenAI browser auth exists, but real provider calls may hit 429, so deterministic fallback is expected.

Useful commands:
- backend: `source .venv/bin/activate && alembic -c backend/alembic.ini upgrade head && uvicorn api.app.main:app --app-dir backend --host 127.0.0.1 --port 8000`
- demo target: `uvicorn examples.vulnerable_demo_api.app:app --host 127.0.0.1 --port 9010`
- demo run: `python3 scripts/demo_pentest.py --backend-url http://127.0.0.1:8000/api/v1 --target-url http://127.0.0.1:9010 --ai-provider-key openai`
- inspect: `python3 scripts/inspect_scan.py --backend-url http://127.0.0.1:8000/api/v1 --scan-id <scan-id>`

Always commit and push after meaningful progress.
```
