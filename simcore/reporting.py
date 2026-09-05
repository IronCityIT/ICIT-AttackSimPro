"""
reporting.py — white-labeled human reports (Markdown + HTML).

Consumes a run summary (see runner.build_run) and the shared remediation catalog to
produce an executive-readable report. No underlying tool names appear — findings are
branded as Iron City validation results. HTML output is fully escaped: findings carry
attacker-influenced strings, so every interpolated value passes through ``esc``.
"""

from __future__ import annotations

import html
from typing import Any

from simcore.base import SEVERITIES, severity_rank
from simcore.remediation import guidance_for

SEVERITY_ORDER = list(reversed(SEVERITIES))  # critical first


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    c = {s: 0 for s in SEVERITIES}
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        if sev in c:
            c[sev] += 1
    return c


def _risk_grade(counts: dict[str, int]) -> str:
    score = (counts["critical"] * 40 + counts["high"] * 10
             + counts["medium"] * 5 + counts["low"] * 2)
    if score == 0:
        return "A+"
    if score < 20:
        return "A"
    if score < 50:
        return "B+"
    if score < 100:
        return "B"
    if score < 150:
        return "C"
    return "D"


def render_markdown(run: dict[str, Any]) -> str:
    findings = run.get("findings", [])
    counts = _counts(findings)
    grade = _risk_grade(counts)
    lines = [
        "# Iron City AttackSimPro — Validation Report",
        "",
        f"**Client:** {run.get('client_name') or run.get('client_id', 'n/a')}  ",
        f"**Assessment ID:** {run.get('scan_id', 'n/a')}  ",
        f"**Generated:** {run.get('generated_at', 'n/a')}  ",
        f"**Targets:** {', '.join(run.get('targets', [])) or 'n/a'}  ",
        f"**Authorization:** {run.get('authorization', 'n/a')}",
        "",
        "## Executive Summary",
        "",
        f"Overall control posture rating: **{grade}**. "
        f"This authorized, non-destructive validation ran "
        f"{run.get('scenario_count', 0)} scenario(s) and identified "
        f"{len(findings)} finding(s): "
        + ", ".join(f"{counts[s]} {s}" for s in SEVERITY_ORDER if counts[s]) + ".",
        "",
        "## Findings by Severity",
        "",
        "| Severity | Finding | Target | Frameworks |",
        "| --- | --- | --- | --- |",
    ]
    for f in sorted(findings, key=lambda x: -severity_rank(str(x.get("severity", "info")))):
        g = guidance_for(f.get("remediation_key", ""))
        fw = ", ".join(g["frameworks"])
        lines.append(
            f"| {f.get('severity', 'info').upper()} | {f.get('title', '')} "
            f"| {f.get('target', '')} | {fw} |"
        )
    lines += ["", "## Remediation Guidance", ""]
    seen = set()
    for f in sorted(findings, key=lambda x: -severity_rank(str(x.get("severity", "info")))):
        key = f.get("remediation_key", "")
        if key in seen:
            continue
        seen.add(key)
        g = guidance_for(key)
        lines.append(f"### {g['title']}  (Priority: {g['priority']}, Effort: {g['effort']})")
        lines.append("")
        lines.append(g["impact"])
        lines.append("")
        for step in g["steps"]:
            lines.append(f"- {step}")
        lines.append("")
        lines.append(f"_Frameworks:_ {', '.join(g['frameworks'])}")
        lines.append("")
    if not findings:
        lines += ["_No control gaps were identified in this assessment._", ""]
    return "\n".join(lines)


def render_html(run: dict[str, Any]) -> str:
    findings = run.get("findings", [])
    counts = _counts(findings)
    grade = _risk_grade(counts)
    rows = []
    for f in sorted(findings, key=lambda x: -severity_rank(str(x.get("severity", "info")))):
        g = guidance_for(f.get("remediation_key", ""))
        rows.append(
            "<tr>"
            f"<td class='sev sev-{esc(str(f.get('severity','info')).lower())}'>"
            f"{esc(str(f.get('severity','info')).upper())}</td>"
            f"<td>{esc(f.get('title',''))}</td>"
            f"<td>{esc(f.get('target',''))}</td>"
            f"<td>{esc(', '.join(g['frameworks']))}</td>"
            "</tr>"
        )
    rem_blocks = []
    seen = set()
    for f in sorted(findings, key=lambda x: -severity_rank(str(x.get("severity", "info")))):
        key = f.get("remediation_key", "")
        if key in seen:
            continue
        seen.add(key)
        g = guidance_for(key)
        steps = "".join(f"<li>{esc(s)}</li>" for s in g["steps"])
        rem_blocks.append(
            f"<div class='rem'><h3>{esc(g['title'])}</h3>"
            f"<p class='meta'>Priority: {esc(g['priority'])} · Effort: {esc(g['effort'])}</p>"
            f"<p>{esc(g['impact'])}</p><ul>{steps}</ul>"
            f"<p class='fw'>Frameworks: {esc(', '.join(g['frameworks']))}</p></div>"
        )
    summary = ", ".join(f"{counts[s]} {esc(s)}" for s in SEVERITY_ORDER if counts[s]) or "none"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Iron City AttackSimPro — Validation Report</title>
<style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#0a0a14;color:#e8e8f0}}
.wrap{{max-width:900px;margin:0 auto;padding:32px}}
h1{{color:#D4AF37}} h2{{color:#9d4edd;border-bottom:1px solid #2a2a3e;padding-bottom:6px;margin-top:32px}}
table{{width:100%;border-collapse:collapse;margin-top:12px}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #2a2a3e;font-size:14px}}
th{{color:#a0a0b0;text-transform:uppercase;font-size:11px;letter-spacing:1px}}
.grade{{font-size:44px;font-weight:700;color:#D4AF37}}
.sev{{font-weight:700}}
.sev-critical{{color:#ff006e}}.sev-high{{color:#ff4757}}.sev-medium{{color:#ffa502}}
.sev-low{{color:#2ed573}}.sev-info{{color:#54a0ff}}
.rem{{background:#14141f;border-left:3px solid #9d4edd;padding:12px 16px;margin:12px 0;border-radius:8px}}
.rem h3{{margin:0 0 6px;color:#D4AF37}} .meta{{color:#a0a0b0;font-size:12px;margin:0 0 8px}}
.fw{{color:#a0a0b0;font-size:12px}} .kv{{color:#a0a0b0}}
</style></head><body><div class="wrap">
<h1>AttackSimPro — Validation Report</h1>
<p class="kv"><strong>Client:</strong> {esc(run.get('client_name') or run.get('client_id','n/a'))}<br>
<strong>Assessment ID:</strong> {esc(run.get('scan_id','n/a'))}<br>
<strong>Generated:</strong> {esc(run.get('generated_at','n/a'))}<br>
<strong>Targets:</strong> {esc(', '.join(run.get('targets', [])) or 'n/a')}<br>
<strong>Authorization:</strong> {esc(run.get('authorization','n/a'))}</p>
<h2>Executive Summary</h2>
<p><span class="grade">{esc(grade)}</span> control posture rating.</p>
<p>{esc(run.get('scenario_count',0))} scenario(s) run · {len(findings)} finding(s): {summary}.</p>
<h2>Findings by Severity</h2>
<table><thead><tr><th>Severity</th><th>Finding</th><th>Target</th><th>Frameworks</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan=4>No control gaps identified.</td></tr>'}</tbody></table>
<h2>Remediation Guidance</h2>
{''.join(rem_blocks) or '<p>No remediation required.</p>'}
</div></body></html>
"""
