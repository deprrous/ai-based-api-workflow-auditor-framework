# Verifier Tool

This package holds verifier-side workers and replay-result helpers.

## Current worker

- `worker.py` converts deterministic replay results into `verifier.finding_confirmed` producer contracts
- it requires evidence and workflow-node anchors before a confirmed finding can be emitted
- it publishes findings into `POST /api/v1/scans/{scan_id}/events`
- it can also claim, complete, and fail queued verifier jobs through the backend job APIs

## Development autorun

The backend can optionally start a development-only queued verifier runner.

- it claims queued verifier jobs automatically
- it uses a deterministic development executor
- it exists to validate the orchestration pipeline locally

Do not treat `deterministic-dev` as a production replay engine.

## HTTP replay mode

The verifier runtime also supports a real `http-replay` mode.

- it replays request sequences attached to queued verifier jobs
- it uses actor-specific headers from backend configuration
- it confirms findings only when the replayed target responses match the job success criteria
- it supports mutation strategies for path ids, body fields, role/permission headers, actor switching, and refresh-driven retries

This is the first real replay executor path in the backend.

## Why this matters

High-accuracy logic-flaw detection cannot rely on vague model output alone.

The verifier worker is the backend boundary where:

- exploit attempts become evidence-backed confirmations
- confirmed findings become normalized producer contracts
- the backend receives the same structure every time, regardless of which verifier implementation produced it
