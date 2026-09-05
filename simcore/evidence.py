"""
evidence.py — audit-defensible evidence bundles.

A run produces a directory bundle with:

  * ``run.json``      — full run metadata + every scenario result and finding.
  * ``findings.json`` — flattened findings (the storeScanResults ingest shape).
  * ``report.md`` / ``report.html`` — human reports (written by reporting.py).
  * ``manifest.json`` — SHA-256 of every other file plus a bundle digest.

The manifest makes the bundle verifiable: :func:`verify_bundle` recomputes every
hash, so an evidence bundle can be trusted (or shown to have been altered) long
after the run.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_manifest(bundle_dir: str | Path) -> dict[str, Any]:
    """Compute a manifest over every file in the bundle except the manifest itself."""
    d = Path(bundle_dir)
    files = {}
    for path in sorted(d.rglob("*")):
        if path.is_file() and path.name != "manifest.json":
            files[str(path.relative_to(d))] = _sha256_file(path)
    # Bundle digest = hash of the sorted per-file digests. Deterministic.
    concat = "".join(f"{name}:{digest}" for name, digest in sorted(files.items()))
    bundle_digest = hashlib.sha256(concat.encode("utf-8")).hexdigest()
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "algorithm": "sha256",
        "files": files,
        "bundle_digest": bundle_digest,
    }
    write_json(d / "manifest.json", manifest)
    return manifest


def verify_bundle(bundle_dir: str | Path) -> tuple[bool, list[str]]:
    """Return (ok, problems). Recomputes every file hash against the manifest."""
    d = Path(bundle_dir)
    manifest_path = d / "manifest.json"
    if not manifest_path.exists():
        return False, ["manifest.json missing"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    problems: list[str] = []
    recorded = manifest.get("files", {})
    present = {
        str(p.relative_to(d))
        for p in d.rglob("*")
        if p.is_file() and p.name != "manifest.json"
    }
    for name in sorted(present - set(recorded)):
        problems.append(f"unlisted file present: {name}")
    for name, digest in recorded.items():
        fp = d / name
        if not fp.exists():
            problems.append(f"listed file missing: {name}")
        elif _sha256_file(fp) != digest:
            problems.append(f"hash mismatch: {name}")
    return (not problems), problems
