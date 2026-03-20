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
