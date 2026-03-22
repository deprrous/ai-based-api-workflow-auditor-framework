#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
from typing import Any

import httpx


def get_json(client: httpx.Client, path: str, *, headers: dict[str, str] | None = None) -> Any:
    response = client.get(path, headers=headers, timeout=30.0)
    response.raise_for_status()
    return response.json()


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect backend pentest state for a scan.")
    parser.add_argument("--backend-url", default="http://127.0.0.1:8000/api/v1")
    parser.add_argument("--scan-id")
    parser.add_argument("--admin-token", default="dev-admin-token")
    args = parser.parse_args()

    base = args.backend_url.rstrip("/")
    admin_headers = {"X-Auditor-Admin-Token": args.admin_token}

    with httpx.Client(base_url=base) as client:
        scans = get_json(client, "/scans")
        if not scans:
            raise SystemExit("No scans found.")

        scan = None
        if args.scan_id:
            scan = next((item for item in scans if item["id"] == args.scan_id), None)
            if scan is None:
                raise SystemExit(f"Scan not found: {args.scan_id}")
        else:
            scan = scans[0]

        scan_id = scan["id"]
        sessions = get_json(client, f"/scans/{scan_id}/orchestration/sessions", headers=admin_headers)
        session = sessions[0] if sessions else None
        session_detail = get_json(client, f"/scans/orchestration/sessions/{session['id']}", headers=admin_headers) if session else None
        planner_history = get_json(client, f"/scans/{scan_id}/planner/history", headers=admin_headers)
        hypotheses = get_json(client, f"/hypotheses/scan/{scan_id}")
        jobs = get_json(client, f"/scans/{scan_id}/verifier-jobs")
        findings = get_json(client, f"/scans/{scan_id}/findings")
        events = get_json(client, f"/scans/{scan_id}/events")

    print("\n=== Scan ===")
    print(json.dumps(scan, indent=2))

    print("\n=== Planner History ===")
    print(json.dumps(planner_history, indent=2))

    print("\n=== Hypotheses ===")
    print(json.dumps(hypotheses, indent=2))

    print("\n=== Verifier Jobs ===")
    print(json.dumps(jobs, indent=2))

    print("\n=== Findings ===")
    print(json.dumps(findings, indent=2))

    print("\n=== Orchestration Session Summary ===")
    print(json.dumps(session, indent=2))

    print("\n=== Orchestration Session Detail ===")
    print(json.dumps(session_detail, indent=2))

    print("\n=== Events (tail) ===")
    print(json.dumps(events[-20:], indent=2))


if __name__ == "__main__":
    main()
