# Proxy

This module is the live traffic surface of the system.

## Chosen proxy core

Use `mitmproxy` as the external proxy engine.

- it already solves HTTP/S interception, certificates, replay, and addon hooks well
- our code should focus on API workflow accuracy, target correlation, and evidence-backed vulnerability detection
- the repository wraps `mitmproxy` through our own runtime producer contracts instead of coupling the backend to raw proxy internals

## Planned internal areas

- `addons/` - mitmproxy add-ons and integration hooks.
- `capture/` - capture sessions and raw flow collection.
- `normalization/` - normalized request and response models.
- `redaction/` - secret, token, and sensitive field handling.
- `replay/` - controlled replay preparation and request reconstruction.

The proxy engine exists to make live API behavior visible to the audit system without mixing traffic handling into the API server.

## Runtime ingest addon

`addons/runtime_ingest.py` is the first real proxy integration.

It observes target traffic and emits `proxy.http_observed` contracts into:

- `POST /api/v1/scans/{scan_id}/events`

That allows the backend to update workflow graphs directly from captured target traffic.

The addon now also sends replayable request artifacts so the backend can persist bodies, headers, cookies, and response summaries separately from event payloads.

## Local usage

Install `mitmproxy` as an external tool first.

Recommended approach:

```bash
pipx install mitmproxy
```

Alternative approaches such as a dedicated virtualenv or the official mitmproxy installers are also fine.

Run mitmdump with the addon:

```bash
mitmdump \
  -s proxy/addons/runtime_ingest.py \
  --set auditor_backend_url=http://127.0.0.1:8000/api/v1 \
  --set auditor_scan_id=bootstrap-scan \
  --set auditor_ingest_token=dev-ingest-token \
  --set auditor_include_hosts=qa.example.internal \
  --set auditor_include_path_prefixes=/api,/v1
```
