# ADR 0003: Design for Provider Neutrality and Self-Hosting

## Status

Accepted.

## Context

The project goal explicitly includes support for many AI providers, many authentication approaches, and practical self-hosted deployment.

## Decision

Architect the repository around pluggable seams for:

- AI provider access,
- authentication and identity integration,
- traffic capture and replay sources,
- rules and knowledge packs,
- verification backends and future worker modes.

Prefer contracts and adapters over hard-coded vendor behavior.

## Consequences

### Positive

- easier adoption across different self-hosted environments,
- future support for OpenAI, Anthropic, local models, and others,
- future support for local auth, OIDC, and reverse-proxy identity.

### Negative

- initial implementation must define provider contracts early,
- testing matrix becomes broader over time.
