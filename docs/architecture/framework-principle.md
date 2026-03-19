# Framework Principle

The diagram you shared is best treated as the framework work principle, not the full product flow.

This improved version expands the demo so it better represents how the framework should reason, act, observe, and publish results.

```mermaid
graph TD
    classDef input fill:#f1f5f9,stroke:#94a3b8,stroke-width:2px,color:#333
    classDef ingestion fill:#0f766e,stroke:#115e59,stroke-width:2px,color:#fff
    classDef core fill:#2563eb,stroke:#1d4ed8,stroke-width:2px,color:#fff
    classDef control fill:#475569,stroke:#334155,stroke-width:2px,color:#fff
    classDef tool fill:#10b981,stroke:#059669,stroke-width:2px,color:#fff
    classDef observation fill:#ec4899,stroke:#db2777,stroke-width:2px,color:#fff
    classDef output fill:#7c3aed,stroke:#6d28d9,stroke-width:2px,color:#fff
    classDef success fill:#14b8a6,stroke:#0f766e,stroke-width:2px,color:#fff

    spec("API Spec") --> normalize
    source("Source Code") --> normalize
    traffic("Live Traffic") --> auth
    kb("Knowledge Base") --> context

    auth["Auth Profile"] --> normalize
    normalize["Normalization and Redaction"] --> context["Context Graph"]

    subgraph orchestrator["Agentic AI Core"]
        brain{"LLM Brain"}
        react(("ReAct Loop"))
        guard["Guardrails"]
        brain <--> react
        react --> guard
    end

    context --> brain
    guard --> hypothesis["Logic Hypothesis"]
    hypothesis --> tools{"Tool Router"}

    tools --> analyzer["Semantic Analyzer"]
    tools --> mapper["Workflow Mapper"]
    tools --> verifier["Automated Verifier"]

    analyzer --> reflection["Observation and Reflection"]
    mapper --> reflection
    verifier --> evidence["Evidence Store"]
    evidence --> reflection

    reflection -. "another vector" .-> react
    reflection -. "issue confirmed" .-> report["Finding and Auto-Patch"]
    reflection -. "run complete" .-> done["Audit Complete"]
    reflection --> dashboard["Dashboard and Logs"]
    report --> dashboard

    class spec,source,traffic,kb input
    class auth,normalize,context ingestion
    class brain,react core
    class guard,hypothesis control
    class tools,analyzer,mapper,verifier tool
    class evidence,reflection observation
    class report,dashboard output
    class done success
```

## What was added beyond the demo

- four-pillar data fusion instead of only two inputs,
- auth profiling and normalization before reasoning,
- a context graph that feeds the orchestrator,
- guardrails before tool execution,
- evidence capture separate from reflection,
- explicit dashboard publishing for non-security users.

## Repository mapping

- `backend/orchestrator/` implements the LLM brain and ReAct loop.
- `backend/proxy/` supplies live traffic capture.
- `backend/tools/analyzer/` implements semantic analysis.
- `backend/tools/workflow/` implements workflow mapping.
- `backend/tools/verifier/` implements PoC verification.
- `backend/api/routers/workflows.py` exposes a graph payload for the future frontend.
