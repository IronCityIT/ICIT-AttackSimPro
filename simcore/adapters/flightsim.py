"""
flightsim.py — ingest a malicious-traffic simulation result into Iron City findings.

The internal tool (name never surfaced to a client) generates safe, synthetic malicious
network traffic — C2 beacons, DGA lookups, DNS/ICMP tunneling, data exfiltration, port
scans, cryptomining callbacks — from an authorized host, to test whether the network
detection stack (NDR / DNS security / egress filtering / SIEM) alerts. This adapter reads
the normalized result and turns each *generated* traffic module into a detection-validation
finding: the malicious traffic left the host; the corresponding detection must be confirmed.

  * a module that RAN (generated traffic) → a network detection-validation finding, severity
    by ATT&CK tactic (C2 / exfiltration are high);
  * a module that FAILED (no traffic generated) → coverage, not a finding;
  * `coverage()` → generated / failed + per-module counts.

No traffic is generated here. The result already exists; this is passive ingestion, the
same contract as the other report adapters. White-labeled: findings carry the ATT&CK
technique + traffic category, never the tool's name.

Report shapes handled: a top-level list, or {"modules"|"results"|"runs": [...]}. Each entry
names a module (module/name) and an outcome; it may carry its own technique_id / tactic /
destinations, else they come from a built-in module map.
"""

from __future__ import annotations

from typing import Any, Iterable

from simcore.adapters.base import ReportAdapter, tactic_severity
from simcore.base import Finding

_RAN = {"success", "succeeded", "sent", "generated", "ran", "ok", "complete",
        "completed", "done", "true", "pass", "passed"}
_FAILED = {"failed", "failure", "error", "blocked", "skipped", "false", "notrun", "not-run"}

# module -> (technique_id, tactic, human category). Covers the common traffic modules.
_MODULE_MAP: dict[str, tuple[str, str, str]] = {
    "c2": ("T1071", "command-and-control", "C2 beacon"),
    "sink": ("T1071", "command-and-control", "known-bad callback"),
    "irc": ("T1071", "command-and-control", "IRC C2"),
    "imposter": ("T1071.001", "command-and-control", "protocol impersonation"),
    "telegram-bot-c2": ("T1071.001", "command-and-control", "web-service C2"),
    "spambot": ("T1071.003", "command-and-control", "mail C2"),
    "dga": ("T1568.002", "command-and-control", "domain generation"),
    "dns-tunnel": ("T1071.004", "command-and-control", "DNS tunneling"),
    "tunnel-dns": ("T1071.004", "command-and-control", "DNS tunneling"),
    "tunnel-icmp": ("T1095", "command-and-control", "ICMP tunneling"),
    "oast": ("T1071.004", "command-and-control", "out-of-band callback"),
    "tor": ("T1090.003", "command-and-control", "multi-hop proxy"),
    "miner": ("T1496", "impact", "cryptomining traffic"),
    "scan": ("T1046", "discovery", "network service scanning"),
    "ssh-exfil": ("T1048", "exfiltration", "data exfiltration"),
    "ssh-transfer": ("T1048", "exfiltration", "data exfiltration"),
    "exfil": ("T1041", "exfiltration", "data exfiltration"),
}


def _norm(v: Any) -> str:
    return str(v or "").strip().lower()


def _iter_modules(data: Any) -> Iterable[dict[str, Any]]:
    if isinstance(data, dict):
        items = data.get("modules") or data.get("results") or data.get("runs") or []
    else:
        items = data
    for item in items or []:
        if isinstance(item, dict):
            yield item


def _module_key(item: dict[str, Any]) -> str:
    return _norm(item.get("module") or item.get("name") or item.get("category"))


def _ran(item: dict[str, Any]) -> bool | None:
    tok = _norm(item.get("outcome") or item.get("status") or item.get("result") or item.get("state"))
    if tok in _RAN:
        return True
    if tok in _FAILED:
        return False
    # A count of destinations/packets sent implies traffic was generated.
    for k in ("sent", "count", "destinations", "packets"):
        v = item.get(k)
        if isinstance(v, int) and v > 0:
            return True
        if isinstance(v, (list, tuple)) and len(v) > 0:
            return True
    if not tok:
        return True  # a logged module run with no explicit status is a run
    return None


class FlightsimAdapter(ReportAdapter):
    name = "flightsim"
    title = "Malicious Traffic Simulation"
    description = "Normalizes a malicious-traffic detection-test result into findings."

    def parse(self, data: Any, target_label: str = "") -> list[Finding]:
        if not isinstance(data, (list, dict)):
            raise ValueError("traffic simulation result must be a JSON list or object")
        findings: list[Finding] = []
        for item in _iter_modules(data):
            key = _module_key(item)
            builtin = _MODULE_MAP.get(key)
            tid = str(item.get("technique_id") or (builtin[0] if builtin else "")).strip()
            tactic = _norm(item.get("tactic")) or (builtin[1] if builtin else "")
            if not tid and not tactic:
                continue  # unmapped module with no ATT&CK context
            if _ran(item) is not True:
                continue  # failed / indeterminate: no traffic generated
            category = (builtin[2] if builtin else key) or (tid or "traffic")
            host = str(item.get("host") or item.get("source") or target_label or "host").strip()
            dests = item.get("destinations")
            n_dest = len(dests) if isinstance(dests, (list, tuple)) else (
                dests if isinstance(dests, int) else None)
            findings.append(Finding(
                scenario="malicious_traffic_simulation",
                target=host,
                severity=tactic_severity(tactic or "command-and-control"),
                title=f"Malicious Traffic Undetected: {category}"
                      + (f" ({tid})" if tid else ""),
                detail=(f"Synthetic {category} traffic"
                        + (f" ({tid})" if tid else "")
                        + f" was generated from {host}"
                        + (f" to {n_dest} destination(s)" if n_dest else "")
                        + f" (tactic {tactic or 'command-and-control'}). Confirm the network "
                        f"detection stack (NDR / DNS security / egress filtering / SIEM) "
                        f"alerted; unseen malicious traffic is a detection gap."),
                attack=((tid,) if tid else ()),
                remediation_key="network-traffic-undetected",
                evidence={"module": key, "category": category, "technique_id": tid,
                          "tactic": tactic or "command-and-control", "host": host,
                          "destinations": n_dest, "outcome": "generated"},
            ))
        return findings

    def coverage(self, data: Any) -> dict[str, Any]:
        generated = 0
        failed = 0
        modules: dict[str, int] = {}
        for item in _iter_modules(data):
            key = _module_key(item)
            if not key:
                continue
            state = _ran(item)
            if state is True:
                generated += 1
                modules[key] = modules.get(key, 0) + 1
            elif state is False:
                failed += 1
        return {"generated": generated, "failed": failed, "modules": modules}
