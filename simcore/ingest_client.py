"""
ingest_client.py — POST a run's findings to storeScanResults.

Thin, dependency-free client for the Cloud Function ingest. Builds the exact payload
shape handler.js expects (client_name/scan_id/scan_type/target/status/summary/
findings) and reports the HTTP outcome honestly — a rejected write is an error, never
a swallowed warning.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


def build_payload(run: dict[str, Any]) -> dict[str, Any]:
    counts = {f"{s}_count": 0 for s in ("critical", "high", "medium", "low", "info")}
    for f in run.get("findings", []):
        sev = str(f.get("severity", "info")).lower()
        key = f"{sev}_count"
        if key in counts:
            counts[key] += 1
    return {
        "client_name": run.get("client_name") or run.get("client_id"),
        "client_id": run.get("client_id"),
        "scan_id": run.get("scan_id"),
        "scan_type": run.get("scan_type", "purple-team-validation"),
        "target": ", ".join(run.get("targets", [])) or None,
        "status": run.get("status", "completed"),
        "summary": {**counts, "scenarios": run.get("scenario_count", 0)},
        "findings": run.get("findings", []),
    }


def post(url: str, run: dict[str, Any], token: str = "", timeout: float = 10.0) -> tuple[int, str]:
    payload = build_payload(run)
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Ingest-Token"] = token
    req = urllib.request.Request(url, data=data, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
