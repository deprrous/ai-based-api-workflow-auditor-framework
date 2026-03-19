# System Overview

## Goal

Build a full-stack agentic AI API auditing platform that can:

- map API workflows visually,
- audit for business logic and authorization flaws,
- explain risk in plain English,
- suggest developer-friendly remediation,
- and remain practical for self-hosted open-source use.

## High-level shape

The system is organized as a modular monorepo with clear runtime boundaries and standard folder names.

- `frontend/` is the user-facing web application.
- `backend/api/` is the control-plane API exposed to the frontend.
- `backend/orchestrator/` owns the ReAct loop and scan planning logic.
- `backend/proxy/` captures, normalizes, redacts, and replays traffic.
- `backend/tools/` contains analyzers, verifiers, and remediation builders.
- `knowledge_base/` stores the security knowledge used during reasoning.
- `shared/` holds cross-stack contracts and reusable fixtures.

The naming is intentionally standard, but the module roles still map directly to the instruction brief.

## Primary user experience

The product is designed for developers, product engineers, and technical operators who are not deep security specialists.

- onboarding must accept practical inputs such as OpenAPI, traffic captures, and credentials,
- the dashboard must visualize workflows instead of showing only flat endpoint lists,
- findings must explain business impact in product language,
- remediation must be specific enough to hand to engineering without additional translation.

## Runtime components

### Web client

- dashboard shell,
- workflow graph viewer,
- finding and report surfaces,
- real-time activity and scan logs,
- onboarding and settings flows.

### API server

- project and environment management,
- scan run lifecycle,
- finding retrieval and filtering,
- event streaming to the UI,
- provider and authentication configuration surfaces.

### AI orchestrator

- fuses the four data pillars,
- forms audit hypotheses,
- chooses tools and verification actions,
- tracks agent state and reasoning artifacts,
- emits structured outputs for the dashboard.

### Proxy engine

- live HTTP capture,
- request and response normalization,
- token and secret redaction,
- replay preparation,
- workflow event extraction.

### Tooling layer

- semantic analysis of specs and source snippets,
- workflow mapping and graph assembly,
- active verification and PoC execution,
- remediation drafting,
- evidence assembly.

## Data pillars from the instruction

The architecture preserves the four-pillar fusion model from `instruction.md`.

1. Live HTTP traffic from the proxy engine.
2. Source code snippets for white-box context.
3. API specifications such as Swagger or OpenAPI.
4. A knowledge base mapped to OWASP API Top 10 concepts.

## Recommended platform dependencies

These are architectural placeholders for self-hosting, not implemented services yet.

- PostgreSQL for durable control-plane state.
- Object storage such as MinIO for captures, evidence, and artifacts.
- Redis or a workflow engine for transient coordination and long-running tasks.
- Mitmproxy for traffic interception.
- React Flow for workflow visualization.

## System qualities we optimize for

- usability for non-security users,
- modular growth without early microservice sprawl,
- safe execution boundaries for verification and replay,
- provider neutrality for AI and authentication,
- strong observability for scans and agent decisions.
