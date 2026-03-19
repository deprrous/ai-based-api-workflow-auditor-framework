# Deploy

This directory is reserved for self-hosting assets and deployment guidance.

## Planned internal areas

- `docker/` - image-related assets.
- `compose/` - Docker Compose topology for local and small-team installs.
- `kubernetes/` - future cluster-ready deployment assets.

Self-hosting is a core requirement, so deployment guidance belongs in the repository from the start.

## Current compose asset

- `compose/postgres.yaml` - local Postgres service for the FastAPI control plane.
