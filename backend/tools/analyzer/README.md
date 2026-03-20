# Analyzer Tool

This package holds source/spec understanding helpers used by the backend.

## Current correlation helper

- `correlation.py` turns candidate source-code and API-spec references into ranked context attached to verifier findings
- the verifier worker uses these helpers before publishing confirmed findings so reports include code/spec anchors

This keeps high-confidence findings tied to concrete implementation and specification context instead of only runtime evidence.
