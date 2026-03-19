# Scan Lifecycle

## Core loop

The system follows the ReAct shape described in `instruction.md`, but anchors it in explicit artifacts and module boundaries.

1. Ingest.
2. Correlate.
3. Reason.
4. Act.
5. Observe.
6. Explain.
7. Report.

## Detailed flow

### 1. Ingest

- `backend/proxy/` captures live HTTP traffic.
- `backend/tools/analyzer/` ingests source snippets and API specifications.
- `backend/tools/workflow/` converts related calls into graph-friendly workflow structure.
- `knowledge_base/` provides rules, heuristics, and OWASP mappings.

### 2. Correlate

- endpoints, users, tokens, resources, and relationships are normalized,
- workflow edges are derived from sequential behavior,
- object references and role assumptions are attached to the run context.

### 3. Reason

- `backend/orchestrator/` forms hypotheses about broken ownership, role bypass, unsafe flows, and suspicious transitions,
- the orchestrator chooses tool actions instead of directly performing every operation.

### 4. Act

- the workflow mapper generates graph-ready structures for the frontend,
- the verifier builds PoC candidates and replay plans,
- the proxy engine prepares requests for controlled execution,
- runtime events from the proxy, orchestrator, mapper, and verifier can mutate the persisted scan graph as the audit progresses.

### 5. Observe

- verification results are recorded as evidence,
- failed attempts refine future hypotheses,
- successful exploit paths raise finding confidence,
- persisted scan events can be streamed to the frontend over SSE for live workflow updates.

### 6. Explain

- AI turns technical evidence into plain-English summaries,
- remediation guidance is attached to code or policy patterns when possible,
- the system keeps evidence and explanation distinct.

### 7. Report

- the API server streams run progress and final findings to the frontend,
- the dashboard highlights risky nodes and edges,
- reports expose impact, evidence, confidence, and remediation,
- scan runs persist their own workflow graphs so the UI can render real run context instead of a generic demo.

## Main artifacts

- project
- environment
- scan run
- traffic artifact
- source artifact
- spec artifact
- workflow graph
- hypothesis
- verifier action
- evidence bundle
- finding
- remediation draft

## Safety constraints

- active verification must remain isolated from the control-plane API process,
- raw secrets should be redacted before long-term storage,
- AI output must not be treated as a confirmed finding without evidence,
- replay and PoC execution must be observable and cancellable.
