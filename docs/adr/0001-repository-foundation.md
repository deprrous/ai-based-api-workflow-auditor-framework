# ADR 0001: Foundational Repository Shape

## Status

Accepted.

## Context

The project needs to start as an open-source, self-hosted full-stack system with both backend and frontend surfaces. The instruction file fixes the major module responsibilities, but the repository should still use standard folder names.

## Decision

Use a modular monorepo with these top-level areas:

- `backend/`
- `frontend/`
- `knowledge_base/`
- `shared/`
- `docs/`
- `deploy/`

Within `backend/`, preserve the required module roles with standard names:

- `orchestrator/`
- `proxy/`
- `tools/`
- `api/`

## Consequences

### Positive

- aligns directly with the existing project brief,
- keeps open-source navigation simple,
- allows incremental implementation without large refactors,
- gives self-hosting and documentation first-class places in the repository.

### Negative

- some runtime boundaries still need discipline because they coexist in one repo,
- cross-module contracts must be kept explicit to avoid tight coupling.
