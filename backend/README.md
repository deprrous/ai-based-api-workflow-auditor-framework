# Backend

The backend is split into four primary modules defined by the project brief.

## Selected stack

- Python 3.11+
- FastAPI and Pydantic for the control-plane API
- SQLAlchemy and psycopg for relational persistence
- PostgreSQL for durable scan, graph, and event data
- Server-Sent Events for live scan updates

- `orchestrator/` - ReAct-style reasoning, planning, and agent state.
- `proxy/` - live capture, traffic normalization, redaction, and replay preparation.
- `tools/` - semantic analysis, verification, and remediation support.
- `api/` - FastAPI-based control-plane API for the frontend.

This layout keeps user-facing API concerns separate from powerful scanning and verification concerns while still allowing a single open-source repository.
