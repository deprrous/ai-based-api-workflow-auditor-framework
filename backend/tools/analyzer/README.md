# Analyzer Tool

This package holds source/spec understanding helpers used by the backend.

## Current correlation helper

- `correlation.py` turns candidate source-code and API-spec references into ranked context attached to verifier findings
- the verifier worker uses these helpers before publishing confirmed findings so reports include code/spec anchors

This keeps high-confidence findings tied to concrete implementation and specification context instead of only runtime evidence.

## Current ingestion helper

- `ingestion.py` parses source-code and OpenAPI artifacts into route summaries
- those summaries can be ingested per scan and matched back into planner or verifier context
- this is the first real source/spec ingestion pipeline in the backend

## Current taint-style review helper

- source artifacts now emit lightweight source-to-sink correlation summaries
- those taint-style flows help planner hypotheses for SQLi, SSRF, and XSS families
- this is still heuristic, but stronger than route-only artifact matching
