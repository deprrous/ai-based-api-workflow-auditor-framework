# Tools

This module contains the deterministic and semi-deterministic execution helpers used by the orchestrator.

## Planned internal areas

- `analyzer/` - source and spec understanding, endpoint semantics, and rule matching.
- `workflow/` - workflow mapping, graph assembly, and frontend-ready graph artifacts.
- `verifier/` - PoC generation, controlled execution, and evidence capture.
- `remediation/` - developer-facing fix guidance and future auto-patch helpers.

## Current verifier progress

The verifier package now includes a worker that turns deterministic replay results into `verifier.finding_confirmed` contracts before sending them to the backend control plane.

## Current workflow progress

The workflow package now includes a worker that turns observed endpoint sequences into `workflow_mapper.path_flagged` contracts.

## Current analyzer progress

The analyzer package now includes a correlation helper that attaches source-code and API-spec references to verifier-backed findings.

The tooling layer should remain reusable so the orchestrator can call it without taking ownership of every implementation detail.
