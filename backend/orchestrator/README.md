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
