# Tools

This module contains the deterministic and semi-deterministic execution helpers used by the orchestrator.

## Planned internal areas

- `analyzer/` - source and spec understanding, endpoint semantics, and rule matching.
- `workflow/` - workflow mapping, graph assembly, and frontend-ready graph artifacts.
- `verifier/` - PoC generation, controlled execution, and evidence capture.
- `remediation/` - developer-facing fix guidance and future auto-patch helpers.

The tooling layer should remain reusable so the orchestrator can call it without taking ownership of every implementation detail.
