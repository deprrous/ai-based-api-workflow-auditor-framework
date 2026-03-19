# Tech Stack

This document records the selected foundation stack for the repository so the implementation, docs, and deployment assets stay aligned.

## Backend

- **Language:** Python 3.11+
- **API framework:** FastAPI
- **Validation:** Pydantic v2
- **Persistence:** PostgreSQL
- **ORM / driver:** SQLAlchemy 2 and psycopg 3
- **Realtime transport:** Server-Sent Events

## Frontend

- **Framework:** Next.js 15
- **UI runtime:** React 19
- **Language:** TypeScript
- **Graph visualization:** React Flow
- **Styling:** custom CSS with shared design tokens

## AI and Security Tooling

- **Agent loop:** custom ReAct-style orchestrator
- **Provider strategy:** provider-neutral adapters for OpenAI, Anthropic, and OpenAI-compatible local models
- **Traffic capture:** mitmproxy
- **Knowledge source:** OWASP API Top 10 aligned knowledge base

## Local Self-Hosting

- **Process runner:** uvicorn for local backend development
- **Database bootstrap:** Docker Compose with PostgreSQL
- **Environment config:** `.env` files for backend and frontend

## What We Are Not Using Right Now

- Tailwind CSS is not part of the current frontend implementation.
- D3 is not part of the current graph implementation.
- LangChain is not part of the current backend foundation.

Those can be revisited later, but they are not the selected stack for the repository at this stage.
