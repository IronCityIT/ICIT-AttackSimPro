"""
cli.py — AttackSimPro command line.

    python -m simcore list
    python -m simcore catalog            # scenario library as JSON (drives the UI)
    python -m simcore remediation        # remediation catalog as JSON
    python -m simcore run --targets http://127.0.0.1:9101 --group standard \
        --client "Acme Corp" --scan-id sim-1 --out evidence/sim-1
    python -m simcore verify --bundle evidence/sim-1
    python -m simcore schedule --file schedule.example.yaml

Safety: `run` refuses any non-loopback/private target unless BOTH --allow-external is
given AND a matching authorization record exists under --scope-dir. See scope.py.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from simcore import evidence, ingest_client, registry, reporting, runner
from simcore.audit import AuditLog
from simcore.scheduler import load_schedule, plan
from simcore.scope import Scope


def _cmd_list(args) -> int:
    cat = registry.catalog()
    print(f"Groups: {', '.join(cat['groups'])}\n")
    print(f"{'SCENARIO':<20} {'GROUPS':<28} ATT&CK")
    for s in cat["scenarios"]:
        print(f"{s['name']:<20} {','.join(s['groups']):<28} {','.join(s['attack'])}")
        print(f"  {s['title']} — {s['description']}")
    from simcore.adapters import registry as adapter_registry

    adapters = adapter_registry.catalog()
    if adapters:
        print("\nReport adapters (python -m simcore ingest --adapter <name>):")
        for a in adapters:
            print(f"  {a['name']:<18} {a['title']} — {a['description']}")
    return 0


def _cmd_catalog(args) -> int:
    print(json.dumps(registry.catalog(), indent=2))
    return 0


def _cmd_remediation(args) -> int:
    from simcore.remediation import export

    print(json.dumps(export(), indent=2))
    return 0


def _cmd_run(args) -> int:
    targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    if not targets:
        print("error: --targets is required", file=sys.stderr)
        return 2
    names = [s.strip() for s in args.scenarios.split(",") if s.strip()] if args.scenarios else None
    try:
        scenarios = registry.select(names=names, group=args.group)
    except (KeyError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    scope = Scope.from_dir(args.scope_dir, allow_external=args.allow_external)
    audit = AuditLog(args.audit_log) if args.audit_log else None

    run_doc = runner.run(
        scenarios, targets, scope=scope,
        client_name=args.client, scan_id=args.scan_id,
        actor=args.actor, role=args.role, audit=audit,
    )

    if run_doc["refusals"]:
        for r in run_doc["refusals"]:
            print(f"REFUSED {r['target']}: {r['reason']}", file=sys.stderr)
        # Every requested target refused (nothing ran): surface it as a failure so a
        # scheduled or CI invocation does not look like a clean, empty success.
        if not run_doc["targets"]:
            print("error: all targets refused by scope policy", file=sys.stderr)
            return 4

    if args.out:
        manifest = runner.write_evidence_bundle(run_doc, args.out)
        print(f"evidence bundle -> {args.out} (digest {manifest['bundle_digest'][:12]}…)",
              file=sys.stderr)

    print(json.dumps({
        "scan_id": run_doc["scan_id"],
        "client_id": run_doc["client_id"],
        "targets": run_doc["targets"],
        "scenario_count": run_doc["scenario_count"],
        "summary": run_doc["summary"],
        "findings": len(run_doc["findings"]),
    }, indent=2))

    if args.post:
        token = os.environ.get("INGEST_TOKEN", "")
        if audit:
            audit.append(args.actor, args.role, "ingest_results",
                         run_doc["scan_id"], {"url": args.post})
        code, body = ingest_client.post(args.post, run_doc, token=token)
        print(f"POST {args.post} -> {code}: {body}", file=sys.stderr)
        if not (200 <= code < 300):
            return 1

    # Non-zero exit if any high/critical finding, so CI can gate on posture.
    if args.fail_on_findings and (run_doc["summary"]["critical_count"]
                                  or run_doc["summary"]["high_count"]):
        return 3
    return 0


def _cmd_ingest(args) -> int:
    from simcore.adapters import registry as adapter_registry

    try:
        adapter = adapter_registry.get(args.adapter)
    except KeyError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    with open(args.file, encoding="utf-8") as fh:
        data = json.load(fh)
    findings = adapter.parse(data, target_label=args.target_label or "")
    coverage = adapter.coverage(data) if hasattr(adapter, "coverage") else {}

    run_doc = runner.build_ingest_run(
        findings, client_name=args.client, scan_id=args.scan_id,
        scan_type=args.scan_type, source=args.adapter, coverage=coverage,
    )

    audit = AuditLog(args.audit_log) if args.audit_log else None
    if audit:
        audit.append(args.actor, args.role, "ingest_results", args.scan_id,
                     {"adapter": args.adapter, "findings": len(run_doc["findings"])})

    if args.out:
        manifest = runner.write_evidence_bundle(run_doc, args.out)
        print(f"evidence bundle -> {args.out} (digest {manifest['bundle_digest'][:12]}…)",
              file=sys.stderr)

    print(json.dumps({
        "scan_id": run_doc["scan_id"], "client_id": run_doc["client_id"],
        "scan_type": run_doc["scan_type"], "findings": len(run_doc["findings"]),
        "summary": run_doc["summary"],
        "coverage": {"executed": coverage.get("executed", 0),
                     "prevented": coverage.get("prevented", 0)},
    }, indent=2))

    if args.post:
        token = os.environ.get("INGEST_TOKEN", "")
        code, body = ingest_client.post(args.post, run_doc, token=token)
        print(f"POST {args.post} -> {code}: {body}", file=sys.stderr)
        if not (200 <= code < 300):
            return 1
    return 0


def _cmd_verify(args) -> int:
    ok, problems = evidence.verify_bundle(args.bundle)
    if ok:
        print(f"OK: evidence bundle {args.bundle} verified")
        return 0
    print(f"FAILED: {args.bundle}", file=sys.stderr)
    for p in problems:
        print(f"  - {p}", file=sys.stderr)
    return 1


def _cmd_report(args) -> int:
    with open(args.run, encoding="utf-8") as fh:
        run_doc = json.load(fh)
    fmt = args.format
    if fmt in ("md", "markdown"):
        print(reporting.render_markdown(run_doc))
    else:
        print(reporting.render_html(run_doc))
    return 0


def _cmd_schedule(args) -> int:
    entries = load_schedule(args.file)
    now = datetime.now(timezone.utc)
    print(json.dumps(plan(entries, now=now), indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="simcore", description="AttackSimPro safe simulation engine")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list scenarios and groups").set_defaults(fn=_cmd_list)
    sub.add_parser("catalog", help="print scenario catalog JSON").set_defaults(fn=_cmd_catalog)
    sub.add_parser("remediation", help="print remediation catalog JSON").set_defaults(fn=_cmd_remediation)

    r = sub.add_parser("run", help="run scenarios against targets")
    r.add_argument("--targets", required=True, help="comma-separated targets")
    r.add_argument("--scenarios", help="comma-separated scenario ids")
    r.add_argument("--group", help="scenario group preset")
    r.add_argument("--client", required=True, help="client name")
    r.add_argument("--scan-id", required=True, help="unique scan id")
    r.add_argument("--out", help="evidence bundle output dir")
    r.add_argument("--scope-dir", default="authorizations", help="authorization records dir")
    r.add_argument("--allow-external", action="store_true", help="permit authorized external targets")
    r.add_argument("--actor", default="cli", help="acting user id (for audit)")
    r.add_argument("--role", default="operator", help="acting role (viewer/operator/admin)")
    r.add_argument("--audit-log", help="append-only audit log path")
    r.add_argument("--post", help="storeScanResults URL to POST findings to")
    r.add_argument("--fail-on-findings", action="store_true",
                   help="exit non-zero if any high/critical finding")
    r.set_defaults(fn=_cmd_run)

    ing = sub.add_parser("ingest", help="ingest an adversary-emulation report into findings")
    ing.add_argument("--adapter", required=True, help="report adapter id (e.g. caldera)")
    ing.add_argument("--file", required=True, help="operation report JSON file")
    ing.add_argument("--client", required=True)
    ing.add_argument("--scan-id", required=True)
    ing.add_argument("--scan-type", default="adversary-emulation")
    ing.add_argument("--target-label", help="label for hosts missing one in the report")
    ing.add_argument("--out", help="evidence bundle output dir")
    ing.add_argument("--post", help="storeScanResults URL to POST findings to")
    ing.add_argument("--audit-log", help="append-only audit log path")
    ing.add_argument("--actor", default="cli")
    ing.add_argument("--role", default="operator")
    ing.set_defaults(fn=_cmd_ingest)

    v = sub.add_parser("verify", help="verify an evidence bundle")
    v.add_argument("--bundle", required=True)
    v.set_defaults(fn=_cmd_verify)

    rep = sub.add_parser("report", help="render a report from a run.json")
    rep.add_argument("--run", required=True)
    rep.add_argument("--format", default="html", choices=["html", "md", "markdown"])
    rep.set_defaults(fn=_cmd_report)

    s = sub.add_parser("schedule", help="print the run plan for a schedule file")
    s.add_argument("--file", required=True)
    s.set_defaults(fn=_cmd_schedule)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
