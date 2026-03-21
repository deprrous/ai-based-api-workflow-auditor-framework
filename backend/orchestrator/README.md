# Orchestrator

This module will contain the reasoning loop that correlates traffic, specs, source artifacts, and knowledge-base rules.

## Planned internal areas

- `agents/` - agent roles or orchestrated sub-agents.
- `graph/` - workflow graph assembly and correlation logic.
- `memory/` - run memory, context snapshots, and artifact references.
- `planners/` - hypothesis planning and tool selection.
- `prompts/` - prompt assets and templates.
- `policies/` - guardrails, model policy, and execution constraints.

The orchestrator should output structured hypotheses and actions, not hide everything in free-form text.

## Current planner progress

`planners/workflow_path_planner.py` is the first deterministic orchestration planner.

- it consumes persisted `proxy.http_observed` events
- it groups observations into actor-centered sequences
- it derives high-risk workflow candidates
- it emits `workflow_mapper.path_flagged` contracts through the backend service layer

This is the first step toward an automated scan pipeline where target observations feed planner output, then verifier jobs, then confirmed findings.

The next orchestration layer now also includes a provider-neutral AI catalog under `orchestrator/providers/` so future reasoning can target multiple hosted or local model backends without coupling business logic to one vendor.

The backend now also supports an AI-assisted planner mode that can rank deterministic candidates through a provider-neutral interface.

- `mock` provider works without API keys for local validation
- `openai-compatible` provider is scaffolded for real hosted or local gateways
- verifier replay remains the source of truth even when AI assists planning

## Current orchestration session progress

The backend now has a first autonomous orchestration session layer.

- it can prepare scan context
- run deterministic planning
- optionally run AI-assisted planning
- loop verifier cycles automatically
- maintain first-class hypotheses across cycles
- prioritize or downgrade hypotheses as evidence changes
- trigger remediation and report follow-up after confirmations
- persist steps and memory snapshots for later review

This is not yet a fully self-improving agent, but it is the first real persisted pentest loop instead of isolated planner or verifier calls.
