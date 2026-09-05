"""
runner.py — orchestrates one authorized simulation run.

Flow (per target):

  1. RBAC: the actor's role must permit ``run_simulation``.
  2. Scope: ``Scope.authorize(target)`` must return an Authorization, or the target
     is skipped with an audited refusal. This is the safety gate — nothing runs
     against an unauthorized host.
  3. Probes: bind inspection-only network probes to the authorized target (or accept
     injected doubles for tests) and run each applicable scenario.
  4. Aggregate findings, write an evidence bundle, and audit the run.

The runner reaches the network ONLY through the probe factory, so the scope gate can
never be bypassed and tests are fully deterministic.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from simcore import evidence, rbac, reporting
from simcore.base import SimulationScenario
from simcore.net import HttpProbe, default_https_port, tcp_probe, tls_info
from simcore.scope import Authorization, Scope, ScopeError, host_of


def target_kind(target: str) -> str:
    host = host_of(target)
    if target.startswith(("http://", "https://")):
        return "url"
    try:
        ipaddress.ip_address(host)
        return "ip"
    except ValueError:
        pass
    return "domain" if "." in host else "hostname"


def default_probe_factory(target: str, auth: Authorization) -> dict[str, Any]:
    """Build the real inspection-only probe context bound to an authorized target."""
    host = auth.host
    scheme = "https" if target.startswith("https://") else "http"
    http = HttpProbe(target if "://" in target else f"{scheme}://{host}")
    return {
        "host": host,
        "scheme": scheme,
        "fetch": http.fetch,
        "tcp_probe": lambda port: tcp_probe(host, port),
        "tls_info": lambda: tls_info(host, default_https_port(target)),
        "authorization": auth,
    }


def run(
    scenarios: list[SimulationScenario],
    targets: list[str],
    *,
    scope: Scope,
    client_name: str,
    scan_id: str,
    actor: str = "system",
    role: str = "operator",
    audit=None,
    probe_factory: Callable[[str, Authorization], dict[str, Any]] = default_probe_factory,
) -> dict[str, Any]:
    """Execute a run and return the aggregated run dict (see keys below)."""
    rbac.require(role, "run_simulation")

    all_findings: list[dict[str, Any]] = []
    scenario_results: list[dict[str, Any]] = []
    authorized_targets: list[str] = []
    refusals: list[dict[str, str]] = []

    for target in targets:
        try:
            auth = scope.authorize(target)
        except ScopeError as e:
            refusals.append({"target": target, "reason": str(e)})
            if audit:
                audit.append(actor, role, "run_simulation", target,
                             {"scope": "refused", "reason": str(e)}, outcome="denied")
            continue

        authorized_targets.append(target)
        if audit:
            audit.append(actor, role, "run_simulation", target,
                         {"roe_id": auth.roe_id, "sandbox": auth.sandbox})

        ctx = probe_factory(target, auth)
        kind = target_kind(target)
        for scen in scenarios:
            if not scen.applies_to(kind):
                continue
            result = scen.simulate(target, ctx)
            scenario_results.append(result.to_dict())
            for f in result.findings:
                all_findings.append(f.to_dict())

    from collections import Counter

    sev_counts = Counter(str(f.get("severity", "info")).lower() for f in all_findings)
    run_doc = {
        "client_id": _client_id(client_name),
        "client_name": client_name,
        "scan_id": scan_id,
        "scan_type": "purple-team-validation",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "targets": authorized_targets,
        "requested_targets": targets,
        "refusals": refusals,
        "authorization": _auth_label(scenario_results, authorized_targets, scope),
        "scenario_count": len({r["scenario"] for r in scenario_results}),
        "scenario_results": scenario_results,
        "findings": all_findings,
        "summary": {f"{s}_count": sev_counts.get(s, 0)
                    for s in ("critical", "high", "medium", "low", "info")},
        "status": "completed",
    }
    return run_doc


def build_ingest_run(
    findings: list[Any],
    *,
    client_name: str,
    scan_id: str,
    scan_type: str = "adversary-emulation",
    source: str = "",
    coverage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a run doc from already-collected findings (adapter ingestion path).

    Produces the same shape as :func:`run` so evidence, reporting, audit, and the
    ingest client all work unchanged. ``findings`` may be Finding objects or dicts.
    """
    from collections import Counter

    dict_findings = [f.to_dict() if hasattr(f, "to_dict") else dict(f) for f in findings]
    targets = sorted({str(f.get("target")) for f in dict_findings if f.get("target")})
    sev_counts = Counter(str(f.get("severity", "info")).lower() for f in dict_findings)
    return {
        "client_id": _client_id(client_name),
        "client_name": client_name,
        "scan_id": scan_id,
        "scan_type": scan_type,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "targets": targets,
        "requested_targets": targets,
        "refusals": [],
        "authorization": "ingested report (executed under a prior authorization)",
        "source": source,
        "scenario_count": 1,
        "scenario_results": [],
        "findings": dict_findings,
        "coverage": coverage or {},
        "summary": {f"{s}_count": sev_counts.get(s, 0)
                    for s in ("critical", "high", "medium", "low", "info")},
        "status": "completed",
    }


def write_evidence_bundle(run_doc: dict[str, Any], out_dir: str | Path) -> dict[str, Any]:
    """Persist run.json, findings.json, report.md/html, and a signed manifest."""
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    evidence.write_json(d / "run.json", run_doc)
    evidence.write_json(d / "findings.json", run_doc.get("findings", []))
    (d / "report.md").write_text(reporting.render_markdown(run_doc), encoding="utf-8")
    (d / "report.html").write_text(reporting.render_html(run_doc), encoding="utf-8")
    return evidence.write_manifest(d)


def _client_id(name: str) -> str:
    out = []
    for ch in str(name or "").strip().lower():
        if ch.isalnum():
            out.append(ch)
        elif out and out[-1] != "-":
            out.append("-")
    return "".join(out).strip("-")


def _auth_label(results, targets, scope: Scope) -> str:
    if not targets:
        return "no authorized targets"
    if all(host_of(t) and scope for t in targets) and not scope.allow_external:
        return "sandbox (loopback/private only)"
    return "authorized (external opt-in)"
