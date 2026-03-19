# ADR 0002: Separate Control Plane from Powerful Execution Surfaces

## Status

Accepted.

## Context

This project must be powerful enough to capture traffic, replay workflows, verify hypotheses, and generate PoCs. At the same time, it must remain safe and operable for self-hosted users.

## Decision

Keep the repository unified, but treat the following as separate execution surfaces:

- `backend/api/` as the control-plane boundary,
- `backend/orchestrator/` as the reasoning boundary,
- `backend/proxy/` as the traffic boundary,
- `backend/tools/verifier/` as the active verification boundary.

The control plane should never directly absorb proxy capture or active PoC execution concerns.

## Consequences

### Positive

- reduces blast radius from replay and verification logic,
- makes future remote-runner or worker deployment possible,
- keeps the frontend-facing API stable even as powerful tooling grows.

### Negative

- requires clearer contracts between modules,
- introduces more orchestration work during implementation.
