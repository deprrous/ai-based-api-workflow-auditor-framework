# Workflow Tool

This area is reserved for workflow mapping logic.

## Intended responsibilities

- correlate endpoint calls into ordered flows,
- build node and edge structures for the frontend,
- attach user, role, and object context to graph nodes,
- provide graph-friendly artifacts to the API and orchestrator.

This maps directly to the Workflow Mapper tool in the project architecture.

## Current worker

- `worker.py` turns observed endpoint sequences into `workflow_mapper.path_flagged` producer contracts
- it emits stable nodes and edges for suspicious business-flow paths
- it publishes flagged paths into `POST /api/v1/scans/{scan_id}/events`
- high-risk flagged paths are then turned into queued verifier jobs by the backend control plane
