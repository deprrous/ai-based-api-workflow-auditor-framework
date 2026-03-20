# Verifier Tool

This package holds verifier-side workers and replay-result helpers.

## Current worker

- `worker.py` converts deterministic replay results into `verifier.finding_confirmed` producer contracts
- it requires evidence and workflow-node anchors before a confirmed finding can be emitted
- it publishes findings into `POST /api/v1/scans/{scan_id}/events`
- it can also claim, complete, and fail queued verifier jobs through the backend job APIs

## Why this matters

High-accuracy logic-flaw detection cannot rely on vague model output alone.

The verifier worker is the backend boundary where:

- exploit attempts become evidence-backed confirmations
- confirmed findings become normalized producer contracts
- the backend receives the same structure every time, regardless of which verifier implementation produced it
