"""
infectionmonkey.py — ingest a network BAS report into Iron City findings.

The internal tool (name never surfaced to a client) safely propagates across a network an
engagement is authorized to test — attempting exploitation, lateral movement, credential
reuse, and crossing network segments — and reports what succeeded. This adapter reads the
normalized report and turns each *successful* action into a control-validation finding:

  * a successful EXPLOITATION / PROPAGATION between hosts → lateral-movement gap;
  * a successful SEGMENTATION crossing (a host reached across a boundary that should block
    it) → network segmentation gap (the highest-value network finding);
  * a successful CREDENTIAL REUSE → valid-accounts / credential-access gap;
  * a failed/blocked action → coverage, the control held (not a finding);
  * `coverage()` → succeeded / blocked + per-type counts.

No propagation happens here. The report already exists; this is passive ingestion, the same
contract as the other report adapters. White-labeled: findings carry the ATT&CK technique
and network context, never the tool's name.

Report shapes handled: a top-level JSON list, or {"events"|"results"|"findings": [...]}.
Each event has a ``type`` (exploitation/propagation/segmentation/credential_reuse/technique),
a ``success`` flag (or status), optional ``technique_id`` / ``tactic``, and network context
(source/target/source_segment/target_segment).
"""

from __future__ import annotations

from typing import Any, Iterable

from simcore.adapters.base import ReportAdapter, tactic_severity
from simcore.base import Finding

_SUCCESS = {"success", "succeeded", "true", "used", "exploited", "reached", "propagated", "ok"}
_FAILED = {"failed", "failure", "blocked", "false", "unreached", "prevented", "denied", "skipped"}

# Default ATT&CK tactic per event type, when the event carries no explicit tactic.
_TYPE_TACTIC = {
    "exploitation": "lateral-movement",
    "propagation": "lateral-movement",
    "lateral_movement": "lateral-movement",
    "segmentation": "lateral-movement",
    "credential_reuse": "credential-access",
    "credential_access": "credential-access",
    "exfiltration": "exfiltration",
}


def _norm(v: Any) -> str:
    return str(v or "").strip().lower()


def _iter_events(data: Any) -> Iterable[dict[str, Any]]:
    if isinstance(data, dict):
        items = data.get("events") or data.get("results") or data.get("findings") or []
    else:
        items = data
    for item in items or []:
        if isinstance(item, dict):
            yield item


def _succeeded(item: dict[str, Any]) -> bool | None:
    if "success" in item and isinstance(item["success"], bool):
        return item["success"]
    tok = _norm(item.get("status") or item.get("result") or item.get("outcome") or item.get("state"))
    if tok in _SUCCESS:
        return True
    if tok in _FAILED:
        return False
    return None


def _tactic(item: dict[str, Any], etype: str) -> str:
    supplied = _norm(item.get("tactic"))
    if supplied:
        return supplied
    return _TYPE_TACTIC.get(etype, "lateral-movement")


class InfectionMonkeyAdapter(ReportAdapter):
    name = "infectionmonkey"
    title = "Network Attack Simulation"
    description = "Normalizes a network BAS propagation/segmentation report into findings."

    def parse(self, data: Any, target_label: str = "") -> list[Finding]:
        if not isinstance(data, (list, dict)):
            raise ValueError("network BAS report must be a JSON list or object")
        findings: list[Finding] = []
        for item in _iter_events(data):
            etype = _norm(item.get("type") or item.get("event") or "technique")
            if _succeeded(item) is not True:
                continue  # blocked/failed/indeterminate: the control held
            tid = str(item.get("technique_id") or item.get("technique") or item.get("attack_id") or "").strip()
            tactic = _tactic(item, etype)
            source = str(item.get("source") or item.get("source_host") or item.get("src") or "").strip()
            target = str(item.get("target") or item.get("target_host") or item.get("dst")
                         or target_label or "host").strip()

            if etype == "segmentation":
                src_seg = str(item.get("source_segment") or item.get("src_segment") or source or "segment A").strip()
                dst_seg = str(item.get("target_segment") or item.get("dst_segment") or "segment B").strip()
                findings.append(Finding(
                    scenario="network_segmentation",
                    target=target or dst_seg,
                    severity="high",
                    title=f"Network Segmentation Not Enforced: {src_seg} → {dst_seg}",
                    detail=(f"Traffic crossed from {src_seg} to {dst_seg} (reached {target or dst_seg}) "
                            f"that a segmentation boundary should have blocked. East-west "
                            f"movement between these zones is possible."),
                    attack=((tid,) if tid else ()),
                    remediation_key="network-segmentation-gap",
                    evidence={"type": "segmentation", "source_segment": src_seg,
                              "target_segment": dst_seg, "target": target, "technique_id": tid},
                ))
                continue

            label = tid or etype.replace("_", " ")
            findings.append(Finding(
                scenario="network_attack_simulation",
                target=target,
                severity=tactic_severity(tactic),
                title=f"Undetected Network Movement: {label}"
                      + (f" ({source} → {target})" if source else ""),
                detail=(f"A network {etype.replace('_', ' ')} action"
                        + (f" ({tid})" if tid else "")
                        + (f" from {source}" if source else "")
                        + f" to {target} succeeded without being prevented (tactic {tactic}). "
                        f"Validate east-west detection/prevention for this movement."),
                attack=((tid,) if tid else ()),
                remediation_key="network-propagation-unprevented",
                evidence={"type": etype, "source": source, "target": target,
                          "tactic": tactic, "technique_id": tid, "outcome": "succeeded"},
            ))
        return findings

    def coverage(self, data: Any) -> dict[str, Any]:
        succeeded = 0
        blocked = 0
        types: dict[str, int] = {}
        for item in _iter_events(data):
            state = _succeeded(item)
            etype = _norm(item.get("type") or item.get("event") or "technique")
            if state is True:
                succeeded += 1
                types[etype] = types.get(etype, 0) + 1
            elif state is False:
                blocked += 1
        return {"succeeded": succeeded, "blocked": blocked, "types": types}
