#!/usr/bin/env python3
"""Normalize AttackSim Pro scan output, and fold the shared AI consensus into it.

    # In the scan job: one finding list for storage, one subset for the engine
    python3 tools/asp_consensus.py normalize --kind web --input report.json \
        --target https://example.com -o asp-findings.json --engine-out engine-findings.json

    # In the store job: pair the engine's answers with the findings, build the payload
    python3 tools/asp_consensus.py enrich --bundle asp-findings.json \
        --consensus-dir consensus --job-result success \
        --scan-id S --client-id C --scan-type web-exposure-passive -o payload.json

The pattern is ICIT-DNSGuard's (tools/enrich.py + dnsguard/consensus.py), which is
proven in production: the scan picks which findings the engine is asked about,
the engine answers in the same order, and the store step pairs the answers
positionally against the *same* recorded list - never a recomputed one, so the
pairing cannot drift.

Rules this file enforces, because the dashboard renders straight off its output:

* **No fake verdicts.** A finding gets an `ai_analysis` only if the engine really
  answered for it with at least one successful model. Otherwise it carries
  `ai_status: "unavailable"` and its raw scanner `solution`, and the scan-level
  `consensus.status` says why. A failed engine job is `unavailable`, never
  `success`.
* **White-label.** The engine's per-model responses (`model_responses`) name
  providers and models; they are dropped. Only an allow-list of fields reaches
  storage. Underlying scanner names are scrubbed from every client-facing string.
* **The analysis arrives as a file**, never through an environment variable: the
  engine's output runs to hundreds of kilobytes and DNS Guard's first version
  died with "Argument list too long".

Standard library only, so it runs on a bare runner with no install step.
"""

from __future__ import annotations

import argparse
import html
import json
import pathlib
import re
import sys
from typing import Any

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

#: At most this many findings are sent to the engine, worst first. Each finding
#: costs one call per model, and the engine hands its result back as a job output,
#: which GitHub caps in size; the rest are stored with their scanner guidance.
ENGINE_MAX_FINDINGS = 20

#: Client-facing text never names the underlying tooling. Internal names only.
_TOOL_NAMES = re.compile(
    r"\b(?:OWASP\s+ZAP|Zed\s+Attack\s+Proxy|ZAProxy|ZAP|Nuclei|ProjectDiscovery|Metasploit|msfconsole)\b",
    re.IGNORECASE,
)
_TAGS = re.compile(r"<[^>]+>")
_SPACE = re.compile(r"[ \t]+")

#: ZAP `riskcode` -> severity.
_ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}

#: tls-headers: missing response headers, and what the check itself recommends.
#: X-XSS-Protection is reported as information only: modern browsers ignore it,
#: and current guidance is to omit it or set it to 0 - not something to "fix".
_HEADER_CHECKS = {
    "Content-Security-Policy": (
        "medium",
        "Configure the server to send a Content-Security-Policy header that restricts "
        "where scripts, styles and frames may be loaded from.",
    ),
    "Strict-Transport-Security": (
        "medium",
        "Configure the server to send a Strict-Transport-Security header on HTTPS responses.",
    ),
    "X-Frame-Options": (
        "medium",
        "Send X-Frame-Options (or a CSP frame-ancestors directive) to control framing.",
    ),
    "X-Content-Type-Options": ("low", "Send X-Content-Type-Options: nosniff."),
    "Referrer-Policy": ("low", "Send a Referrer-Policy header, for example strict-origin-when-cross-origin."),
    "Permissions-Policy": ("low", "Send a Permissions-Policy header that disables unused browser features."),
    "X-XSS-Protection": (
        "info",
        "Legacy header ignored by current browsers. No action needed unless legacy browsers must be supported.",
    ),
}


# ---------------------------------------------------------------------------
# Text hygiene
# ---------------------------------------------------------------------------


def scrub(value: Any, limit: int = 0) -> str:
    """Plain, white-labelled text: tags stripped, entities decoded, tools unnamed."""
    text = html.unescape(_TAGS.sub(" ", str(value or "")))
    text = _TOOL_NAMES.sub("automated scanner", text)
    text = "\n".join(_SPACE.sub(" ", line).strip() for line in text.splitlines())
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if limit and len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


def severity_rank(value: Any) -> int:
    try:
        return SEVERITY_ORDER.index(str(value).strip().lower())
    except ValueError:
        return len(SEVERITY_ORDER)


def _split_refs(value: Any) -> list[str]:
    if isinstance(value, list):
        items = value
    else:
        items = re.split(r"\s+", scrub(value))
    return [str(i).strip() for i in items if str(i).strip().startswith("http")][:5]


# ---------------------------------------------------------------------------
# Normalizers: one per report format, all producing the same finding shape
# ---------------------------------------------------------------------------


def _finding(**fields: Any) -> dict[str, Any]:
    finding = {
        "id": fields["id"],
        "name": scrub(fields["name"], 200) or "Unnamed finding",
        "severity": fields.get("severity", "info"),
        "confidence": fields.get("confidence", ""),
        "description": scrub(fields.get("description"), 2000),
        "solution": scrub(fields.get("solution"), 1500),
        "references": fields.get("references", []),
        "cwe": fields.get("cwe", ""),
        "target": fields.get("target", ""),
        "evidence": fields.get("evidence", []),
        "instances": fields.get("instances", 0),
        "category": fields.get("category", ""),
    }
    return finding


def normalize_web(report: dict[str, Any], target: str) -> list[dict[str, Any]]:
    """The web-exposure report format (`-J` JSON): site[].alerts[]."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for site in report.get("site") or []:
        host = site.get("@name") or target
        for alert in site.get("alerts") or []:
            ref = str(alert.get("alertRef") or alert.get("pluginid") or alert.get("name") or "")
            key = f"{host}|{ref}"
            if key in seen:
                continue
            seen.add(key)
            instances = alert.get("instances") or []
            cwe = str(alert.get("cweid") or "")
            findings.append(
                _finding(
                    id=f"web-{ref}-{len(findings)}",
                    name=alert.get("name") or alert.get("alert"),
                    severity=_ZAP_RISK.get(str(alert.get("riskcode")), "info"),
                    confidence=str(alert.get("confidence") or ""),
                    description=alert.get("desc"),
                    solution=alert.get("solution"),
                    references=_split_refs(alert.get("reference")),
                    cwe=f"CWE-{cwe}" if cwe and cwe not in ("-1", "0") else "",
                    target=host,
                    evidence=[scrub(i.get("uri"), 300) for i in instances[:5] if i.get("uri")],
                    instances=int(alert.get("count") or len(instances) or 0),
                    category="web-exposure",
                )
            )
    return findings


def normalize_tls(report: dict[str, Any], target: str) -> list[dict[str, Any]]:
    """The tls-headers report written by tls-headers.yml."""
    findings: list[dict[str, Any]] = []
    headers = report.get("headers") or {}
    missing = [h.strip() for h in str(headers.get("missing_headers") or "").split(",") if h.strip()]
    for header in missing:
        severity, solution = _HEADER_CHECKS.get(header, ("low", f"Send the {header} header."))
        findings.append(
            _finding(
                id=f"hdr-{header.lower()}",
                name=f"Missing {header} header",
                severity=severity,
                description=f"Responses from {target} do not include a {header} header.",
                solution=solution,
                target=target,
                category="security-headers",
            )
        )

    tls = report.get("tls") or {}
    versions = str(tls.get("tls_versions") or "").split()
    legacy = [v for v in versions if v in ("tls1", "tls1_1")]
    if legacy:
        pretty = ", ".join("TLS 1.0" if v == "tls1" else "TLS 1.1" for v in legacy)
        findings.append(
            _finding(
                id="tls-legacy-protocols",
                name="Deprecated TLS protocol versions accepted",
                severity="medium",
                description=f"The server at {target} accepts {pretty}.",
                solution="Disable TLS 1.0 and TLS 1.1; allow TLS 1.2 and TLS 1.3 only.",
                target=target,
                category="tls",
            )
        )
    try:
        days = int(str(tls.get("days_until_expiry")))
    except ValueError:
        days = None
    if days is not None and days < 30:
        findings.append(
            _finding(
                id="tls-certificate-expiry",
                name="TLS certificate expired" if days < 0 else "TLS certificate expiring soon",
                severity="critical" if days < 0 else "high",
                description=f"The certificate for {target} expires in {days} day(s) "
                f"({tls.get('certificate_expiry', 'unknown date')}).",
                solution="Renew the certificate and automate renewal.",
                target=target,
                category="tls",
            )
        )
    return findings


def normalize_template(lines: list[dict[str, Any]], target: str) -> list[dict[str, Any]]:
    """The known-vulnerability JSONL format: one result per line."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in lines:
        info = row.get("info") or {}
        tid = str(row.get("template-id") or info.get("name") or "")
        where = str(row.get("matched-at") or row.get("host") or target)
        key = f"{tid}|{where}"
        if key in seen:
            continue
        seen.add(key)
        classification = info.get("classification") or {}
        cwe = classification.get("cwe-id") or []
        findings.append(
            _finding(
                id=f"kv-{tid}-{len(findings)}",
                name=info.get("name") or tid,
                severity=str(info.get("severity") or row.get("severity") or "info").lower(),
                description=info.get("description"),
                solution=info.get("remediation"),
                references=_split_refs(info.get("reference") or []),
                cwe=(cwe[0] if isinstance(cwe, list) and cwe else str(cwe or "")).upper(),
                target=where,
                evidence=[scrub(where, 300)],
                instances=1,
                category="known-vulnerability",
            )
        )
    return findings


def load_report(kind: str, path: pathlib.Path, target: str) -> list[dict[str, Any]]:
    """A missing or empty report is zero findings, not a crash: the scan job has
    already decided whether the scan itself succeeded."""
    if not path.is_file() or path.stat().st_size == 0:
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    if kind == "template":
        rows = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                rows.append(parsed)
        return normalize_template(rows, target)
    report = json.loads(text)
    if kind == "web":
        return normalize_web(report, target)
    if kind == "tls":
        return normalize_tls(report, target)
    raise ValueError(f"unknown report kind: {kind}")


# ---------------------------------------------------------------------------
# Engine selection and pairing
# ---------------------------------------------------------------------------


def for_engine(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The findings the engine is asked about: actionable ones, worst first.

    Informational findings are not sent. Asked to rate good news or inventory, a
    risk engine recommends "fixing" it (DNS Guard measured this: it advised a
    client to weaken an enforcing DMARC policy).
    """
    actionable = [f for f in findings if severity_rank(f.get("severity")) < SEVERITY_ORDER.index("info")]
    actionable.sort(key=lambda f: severity_rank(f.get("severity")))
    return actionable[:ENGINE_MAX_FINDINGS]


def engine_payload(selected: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """What the engine sees per finding. No scanner name, bounded size."""
    return [
        {
            "title": f["name"],
            "severity": f["severity"].upper(),
            "description": f["description"][:1500],
            "solution": f["solution"][:800],
            "url": f["target"],
            "evidence": f["evidence"][:3],
            "cwe": f["cwe"],
            "category": f["category"],
        }
        for f in selected
    ]


def summarise(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        counts[sev if sev in counts else "info"] += 1
    return {
        "critical_count": counts["critical"],
        "high_count": counts["high"],
        "medium_count": counts["medium"],
        "low_count": counts["low"],
        "info_count": counts["info"],
        "total_findings": len(findings),
    }


def read_consensus(directory: pathlib.Path | None) -> list[dict[str, Any]]:
    """The engine's result artifact. Absent or malformed is an empty list."""
    if directory is None or not directory.is_dir():
        return []
    files = sorted(directory.rglob("*.json"))
    if not files:
        return []
    try:
        parsed = json.loads(files[0].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list):
        return [e for e in parsed if isinstance(e, dict)]
    return []


def _steps(values: Any, limit: int) -> list[str]:
    """Remediation steps without near-duplicates, white-labelled."""
    out: list[str] = []
    seen: set[str] = set()
    for value in values or []:
        text = scrub(value, 600)
        key = "".join(ch for ch in text.lower() if ch.isalnum() or ch.isspace()).strip()
        if not text or key in seen:
            continue
        seen.add(key)
        out.append(text)
    return out[:limit]


def analysis_from(entry: dict[str, Any]) -> dict[str, Any] | None:
    """One engine answer reduced to an allow-list. None when no model answered:
    an analysis with zero successful models is not an analysis."""
    succeeded = int(entry.get("successful_models") or 0)
    if succeeded <= 0 or not entry.get("consensus_severity"):
        return None
    compliance = entry.get("compliance_impact") or {}
    mappings = compliance.get("control_mappings") or {}
    return {
        "severity": str(entry.get("consensus_severity", "")).lower(),
        "confidence_percent": entry.get("confidence_percent", 0),
        "exploitability": str(entry.get("exploitability", "")).lower(),
        "impact": str(entry.get("impact", "")).lower(),
        "false_positive_likelihood": str(entry.get("false_positive_likelihood", "")).lower(),
        "remediation_steps": _steps(entry.get("aggregated_remediation"), 10),
        "verification_steps": _steps(entry.get("verification_steps"), 5),
        "frameworks": [scrub(f, 40) for f in compliance.get("frameworks") or []][:12],
        "control_domains": [scrub(d, 80) for d in compliance.get("control_domains") or []][:8],
        "control_mappings": {
            scrub(k, 40): [scrub(c, 80) for c in (v if isinstance(v, list) else [v])][:6] for k, v in mappings.items()
        }
        if isinstance(mappings, dict)
        else {},
        "audit_risk": str(compliance.get("audit_risk", "")).lower(),
        "breach_notification_risk": bool(compliance.get("breach_notification_risk", False)),
        "models_succeeded": succeeded,
        "models_total": int(entry.get("total_models") or 0),
    }


def enrich(
    bundle: dict[str, Any], entries: list[dict[str, Any]], job_result: str
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Attach each analysis to the finding it is about; return findings + status.

    `job_result` is the reusable workflow's `needs.<job>.result`: success,
    failure, cancelled or skipped.
    """
    findings = [dict(f) for f in bundle.get("findings") or []]
    engine_ids = list(bundle.get("engine_ids") or [])
    for f in findings:
        f["ai_status"] = "unavailable"

    consensus: dict[str, Any] = {
        "status": "unavailable",
        "findings_sent": len(engine_ids),
        "findings_analysed": 0,
        "models_succeeded": 0,
        "models_total": 0,
    }

    if not engine_ids:
        consensus["status"] = "not_required"
        consensus["reason"] = "no actionable findings to analyse"
        return findings, consensus
    if job_result != "success":
        consensus["reason"] = f"AI analysis did not complete ({job_result or 'unknown'})"
        return findings, consensus
    if len(entries) != len(engine_ids):
        # Positional pairing is only sound when the counts match. A mislabelled
        # analysis is worse than none.
        consensus["reason"] = (
            f"AI analysis returned {len(entries)} result(s) for {len(engine_ids)} finding(s); results were not attached"
        )
        return findings, consensus

    by_id = {f["id"]: f for f in findings}
    for fid, entry in zip(engine_ids, entries, strict=True):
        finding = by_id.get(fid)
        if finding is None:
            continue
        analysis = analysis_from(entry)
        consensus["models_total"] += int(entry.get("total_models") or 0)
        if analysis is None:
            continue
        finding["ai_analysis"] = analysis
        finding["ai_status"] = "analysed"
        consensus["findings_analysed"] += 1
        consensus["models_succeeded"] += analysis["models_succeeded"]

    if consensus["findings_analysed"] == 0:
        consensus["reason"] = "no model returned a usable analysis"
        return findings, consensus
    consensus["status"] = "success"
    return findings, consensus


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _write_json(path: pathlib.Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def cmd_normalize(args: argparse.Namespace) -> int:
    findings = load_report(args.kind, pathlib.Path(args.input), args.target)
    selected = for_engine(findings)
    _write_json(
        pathlib.Path(args.output),
        {"findings": findings, "engine_ids": [f["id"] for f in selected]},
    )
    _write_json(pathlib.Path(args.engine_out), engine_payload(selected))
    print(f"normalized {len(findings)} finding(s); {len(selected)} sent for AI analysis")
    return 0


def cmd_enrich(args: argparse.Namespace) -> int:
    bundle_path = pathlib.Path(args.bundle)
    if not bundle_path.is_file():
        print(f"no findings bundle at {bundle_path}", file=sys.stderr)
        return 2
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    entries = read_consensus(pathlib.Path(args.consensus_dir) if args.consensus_dir else None)
    findings, consensus = enrich(bundle, entries, args.job_result)
    payload = {
        "scan_id": args.scan_id,
        "client_id": args.client_id,
        "scan_type": args.scan_type,
        "target": args.target,
        "target_url": args.target,
        "status": "completed",
        "summary": summarise(findings),
        "findings": findings,
        "consensus": consensus,
        "timestamp": args.timestamp,
    }
    _write_json(pathlib.Path(args.output), payload)
    print(
        f"consensus {consensus['status']}: {consensus['findings_analysed']}/{consensus['findings_sent']} "
        f"finding(s) analysed, {consensus['models_succeeded']}/{consensus['models_total']} model responses"
        + (f" - {consensus['reason']}" if consensus.get("reason") else "")
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="asp-consensus")
    sub = parser.add_subparsers(dest="command", required=True)

    n = sub.add_parser("normalize", help="report -> findings bundle + engine input")
    n.add_argument("--kind", required=True, choices=["web", "tls", "template"])
    n.add_argument("--input", required=True)
    n.add_argument("--target", required=True)
    n.add_argument("-o", "--output", required=True)
    n.add_argument("--engine-out", required=True)
    n.set_defaults(func=cmd_normalize)

    e = sub.add_parser("enrich", help="findings bundle + engine result -> store payload")
    e.add_argument("--bundle", required=True)
    e.add_argument("--consensus-dir", default="")
    e.add_argument("--job-result", required=True)
    e.add_argument("--scan-id", required=True)
    e.add_argument("--client-id", required=True)
    e.add_argument("--scan-type", required=True)
    e.add_argument("--target", required=True)
    e.add_argument("--timestamp", required=True)
    e.add_argument("-o", "--output", required=True)
    e.set_defaults(func=cmd_enrich)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
