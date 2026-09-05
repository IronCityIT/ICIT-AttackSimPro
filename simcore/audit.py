"""
audit.py — append-only, tamper-evident audit trail.

Every privileged action (run, schedule, ingest, export, authorization decision)
appends one record to a JSON Lines log. Each record carries the SHA-256 of the
previous record, forming a hash chain: altering or removing any past entry breaks
verification from that point forward. This is the evidence that a Purple-Team
engagement stayed within authorization.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _digest(payload: dict[str, Any], prev_hash: str) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()


class AuditLog:
    """A hash-chained JSONL audit log."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = GENESIS
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        last = json.loads(line)["hash"]
                    except (json.JSONDecodeError, KeyError):
                        continue
        return last

    def append(
        self,
        actor: str,
        role: str,
        action: str,
        target: str = "",
        detail: dict[str, Any] | None = None,
        outcome: str = "ok",
    ) -> dict[str, Any]:
        prev = self._last_hash()
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "role": role,
            "action": action,
            "target": target,
            "outcome": outcome,
            "detail": detail or {},
            "prev_hash": prev,
        }
        record = dict(payload)
        record["hash"] = _digest(payload, prev)
        line = json.dumps(record, separators=(",", ":"))
        # Append atomically enough for a single-writer trail.
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return record

    def entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        out = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    def verify(self) -> tuple[bool, int | None]:
        """Return (ok, first_bad_index). Recomputes the chain end to end."""
        prev = GENESIS
        for i, rec in enumerate(self.entries()):
            payload = {k: rec[k] for k in (
                "ts", "actor", "role", "action", "target", "outcome", "detail",
                "prev_hash")}
            if rec.get("prev_hash") != prev:
                return False, i
            if _digest(payload, prev) != rec.get("hash"):
                return False, i
            prev = rec["hash"]
        return True, None
