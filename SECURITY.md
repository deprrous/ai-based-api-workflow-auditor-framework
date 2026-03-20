# Security Policy

## Supported Versions

This project is still evolving quickly. Security fixes are provided on a best-effort basis for:

| Version | Supported |
| --- | --- |
| `main` | Yes |
| Older commits / forks | No |

If you are self-hosting this project, stay close to the latest reviewed version on `main` until stable releases are published.

## Reporting a Vulnerability

Please do not report security vulnerabilities in public issues, discussions, or pull requests.

Preferred reporting method:

1. Use GitHub's private vulnerability reporting for this repository.
2. Include as much detail as possible:
   - affected commit, branch, or deployment version
   - impact and attack scenario
   - reproduction steps
   - proof of concept or request/response samples
   - any relevant configuration details
3. If the issue involves secrets, tokens, cookies, or private data, redact them before submission.

If private vulnerability reporting is unavailable for any reason, contact the maintainers through a private GitHub channel and reference this policy. Do not open a public report first.

## What to Report

Examples of in-scope issues include:

- authentication or authorization bypass
- privilege escalation
- insecure default configuration
- secret leakage
- SSRF, RCE, path traversal, or arbitrary file access
- unsafe artifact retention or replay behavior
- multi-tenant or project-isolation failures
- workflow or business-logic issues caused by the framework itself

## Out of Scope

The following are generally out of scope unless they are caused directly by this repository:

- vulnerabilities in third-party providers or model APIs
- issues requiring physical access to infrastructure
- social engineering, phishing, or credential stuffing
- denial-of-service testing that degrades shared systems
- findings in custom user code, private APIs, or self-hosted extensions outside this repository

## Testing Expectations

Because this project is designed for API security workflows, please test responsibly:

- only test systems you own or are explicitly authorized to assess
- avoid destructive actions, data corruption, or unnecessary traffic volume
- do not access, modify, or retain third-party data beyond what is needed to demonstrate impact
- prefer minimal, reproducible proof over broad exploitation

## Disclosure Process

Best-effort process:

1. Acknowledge receipt of the report.
2. Validate and assess severity.
3. Prepare a fix or mitigation.
4. Coordinate disclosure after a fix, mitigation, or documented decision.

Response times are best-effort and may vary because this is an open-source project.

## Self-Hosting Note

If you self-host this project, you are responsible for:

- securing your deployment environment
- protecting stored artifacts, tokens, and replay data
- rotating credentials and service-account tokens
- applying updates promptly after security fixes are published
