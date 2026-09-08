"""
coverage.py — aggregate ATT&CK coverage across simulation/ingest sources.

Each report adapter (and each simulation run) produces a run-doc with normalized findings
(carrying ATT&CK technique ids + a tactic) and its own ``coverage`` counts. This module
combines many run-docs into ONE purple-team coverage view — which techniques and tactics
were exercised and remain unmitigated across the whole engagement, by source — powering the
dashboard's ATT&CK coverage panel and the client coverage report (month over month).

It is deliberately honest: the different tools count "the control held" differently
(prevented / not-run / failed / blocked), so this does NOT invent a single conflated
"coverage %". It aggregates the unambiguous signal — the findings (gaps) — into an ATT&CK
matrix, and reports each source's own coverage counts verbatim. Sources are shown by their
white-labeled title, never the underlying tool name.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any


def _source_titles() -> dict[str, str]:
    """Map internal adapter id -> white-labeled title (for client-facing output)."""
    try:
        from simcore.adapters import registry as adapter_registry
        return {a["name"]: a["title"] for a in adapter_registry.catalog()}
    except Exception:
        return {}


def _title_for(source: str, titles: dict[str, str]) -> str:
    return titles.get(source) or source.replace("-", " ").replace("_", " ").title()


def _canon_tactic(value: Any) -> str:
    """Canonical tactic key: lowercase, spaces -> hyphens, so 'Credential Access' and
    'credential-access' (adapters emit both) collapse to one key."""
    return str(value or "").strip().lower().replace(" ", "-")


def _finding_tactics(evidence: dict[str, Any]) -> list[str]:
    """Tactics for a finding: evidence.tactic (singular) or evidence.tactics (list),
    each canonicalized so mixed formats across adapters aggregate together."""
    raw = evidence.get("tactic")
    if raw:
        return [_canon_tactic(raw)]
    lst = evidence.get("tactics")
    if isinstance(lst, list):
        return [_canon_tactic(t) for t in lst if str(t).strip()]
    return []


def aggregate(run_docs: list[dict[str, Any]]) -> dict[str, Any]:
    """Combine run-docs into a single ATT&CK coverage view. Pure; no I/O."""
    titles = _source_titles()
    sources: dict[str, Any] = {}
    techniques: dict[str, dict[str, Any]] = {}
    by_tactic: Counter = Counter()
    sev_totals: Counter = Counter()

    for doc in run_docs:
        src_id = str(doc.get("source") or doc.get("scan_type") or "unknown")
        src_title = _title_for(src_id, titles)
        findings = doc.get("findings", []) or []
        entry = sources.setdefault(src_title, {"findings": 0, "coverage": {}})
        entry["findings"] += len(findings)
        # Keep each source's own coverage counts verbatim (do not conflate shapes).
        for k, v in (doc.get("coverage") or {}).items():
            if isinstance(v, int):
                entry["coverage"][k] = entry["coverage"].get(k, 0) + v

        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            sev_totals[sev] += 1
            # Tactic lives in evidence.tactic (singular) for most adapters, or
            # evidence.tactics (a list) for the cloud adapter — handle both so no
            # source is silently dropped from the tactic breakdown.
            ftactics = _finding_tactics(f.get("evidence") or {})
            for tac in ftactics:
                by_tactic[tac] += 1
            for tid in f.get("attack", []) or []:
                if not tid:
                    continue
                t = techniques.setdefault(tid, {"technique_id": tid, "count": 0,
                                                "sources": set(), "tactics": set(),
                                                "max_severity": "info"})
                t["count"] += 1
                t["sources"].add(src_title)
                for tac in ftactics:
                    t["tactics"].add(tac)
                t["max_severity"] = _max_sev(t["max_severity"], sev)

    tech_list = sorted(
        ({"technique_id": t["technique_id"], "count": t["count"],
          "max_severity": t["max_severity"],
          "sources": sorted(t["sources"]), "tactics": sorted(t["tactics"])}
         for t in techniques.values()),
        key=lambda t: t["technique_id"],
    )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources": dict(sorted(sources.items())),
        "totals": {
            "sources": len(sources),
            "findings_by_severity": {s: sev_totals.get(s, 0)
                                     for s in ("critical", "high", "medium", "low", "info")},
            "unique_techniques": len(techniques),
        },
        "by_tactic": dict(sorted(by_tactic.items())),
        "techniques": tech_list,
    }


_SEV_ORDER = ("info", "low", "medium", "high", "critical")


def _max_sev(a: str, b: str) -> str:
    return a if _SEV_ORDER.index(a) >= _SEV_ORDER.index(_norm_sev(b)) else _norm_sev(b)


def _norm_sev(s: str) -> str:
    return s if s in _SEV_ORDER else "info"


def render_markdown(summary: dict[str, Any]) -> str:
    """A white-labeled ATT&CK coverage report (no tool names)."""
    t = summary["totals"]
    sev = t["findings_by_severity"]
    lines = [
        "# ATT&CK Coverage Report",
        "",
        f"_Generated {summary['generated_at']}_",
        "",
        f"- **Sources:** {t['sources']}",
        f"- **Unique ATT&CK techniques exercised:** {t['unique_techniques']}",
        f"- **Findings:** {sev['critical']} critical · {sev['high']} high · "
        f"{sev['medium']} medium · {sev['low']} low · {sev['info']} info",
        "",
        "## By source",
        "",
        "| Source | Findings | Coverage counts |",
        "| --- | --- | --- |",
    ]
    for name, s in summary["sources"].items():
        cov = ", ".join(f"{k}: {v}" for k, v in sorted(s["coverage"].items())) or "—"
        lines.append(f"| {name} | {s['findings']} | {cov} |")
    lines += ["", "## By tactic", "", "| Tactic | Findings |", "| --- | --- |"]
    for tactic, n in summary["by_tactic"].items():
        lines.append(f"| {tactic} | {n} |")
    lines += ["", "## Techniques exercised", "",
              "| Technique | Severity | Count | Sources | Tactics |",
              "| --- | --- | --- | --- | --- |"]
    for tech in summary["techniques"]:
        lines.append(f"| {tech['technique_id']} | {tech['max_severity']} | {tech['count']} | "
                     f"{', '.join(tech['sources'])} | {', '.join(tech['tactics']) or '—'} |")
    return "\n".join(lines) + "\n"
