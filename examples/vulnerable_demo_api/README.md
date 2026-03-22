# Vulnerable Demo API

Intentionally vulnerable local API used to demonstrate the auditor backend.

Included vulnerable behaviors:

- SQLi-like search endpoint
- SSRF import endpoint
- reflected XSS preview endpoint
- stored XSS comment rendering endpoint

Run it locally:

```bash
source .venv/bin/activate
uvicorn examples.vulnerable_demo_api.app:app --host 127.0.0.1 --port 9010
```
