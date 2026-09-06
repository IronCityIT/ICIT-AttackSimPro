"""
stratus.py — ingest a Stratus Red Team results file into Iron City findings.

Stratus Red Team (internal name only — never surfaced to a client) is "Atomic Red Team
for the cloud": it detonates granular, ATT&CK-mapped attack techniques against a
disposable cloud sandbox (AWS / Azure / GCP / Kubernetes) an engagement is authorized to
use, then can emit its technique state as JSON. This adapter reads that JSON and
normalizes each *detonated* technique into a control-validation finding: the technique
executed in the cloud tenant and its detection/prevention coverage must be validated.

No detonation happens here. The results file already exists; this is passive ingestion —
the same contract as the CALDERA adapter. White-labeled: findings carry MITRE ATT&CK
mapping and the cloud platform, never the tool's name.

Report shapes handled (Stratus versions / wrappers differ):
  * a top-level JSON list of technique objects
  * {"results": [...]} / {"techniques": [...]}
Each technique object may use Stratus' PascalCase keys (ID, FriendlyName, Platform,
MitreAttackTactics, State) or lowercase equivalents.
"""

from __future__ import annotations

from typing import Any, Iterable

from simcore.adapters.base import ReportAdapter, tactic_severity
from simcore.base import Finding

# States that mean the technique actually executed against the cloud tenant.
_DETONATED = {"detonated", "warm", "reverted"}


def _iter_techniques(data: Any) -> Iterable[dict[str, Any]]:
    if isinstance(data, dict):
        items = data.get("results") or data.get("techniques") or []
    else:
        items = data
    for item in items or []:
        if isinstance(item, dict):
            yield item


def _first(item: dict[str, Any], *keys: str, default: str = "") -> str:
    for k in keys:
        if item.get(k):
            return str(item[k])
    return default


def _tactics(item: dict[str, Any]) -> list[str]:
    val = item.get("MitreAttackTactics") or item.get("mitre_attack_tactics") \
        or item.get("tactics") or item.get("tactic")
    if isinstance(val, str):
        return [val]
    if isinstance(val, list):
        return [str(v) for v in val]
    return []


def _tactic_from_id(stratus_id: str) -> str:
    # Stratus ids look like "aws.credential-access.ec2-get-password-data"; the middle
    # segment is the tactic. A useful fallback when no explicit tactic is present.
    parts = str(stratus_id).split(".")
    return parts[1] if len(parts) >= 3 else ""


def _state(item: dict[str, Any]) -> str:
    return _first(item, "State", "state", "status", "outcome").strip().lower()


class StratusAdapter(ReportAdapter):
    name = "stratus"
    title = "Cloud Attack Simulation"
    description = "Normalizes a cloud ATT&CK detonation results file into findings."

    def parse(self, data: Any, target_label: str = "") -> list[Finding]:
        if not isinstance(data, (list, dict)):
            raise ValueError("stratus results must be a JSON list or object")
        findings: list[Finding] = []
        for item in _iter_techniques(data):
            sid = _first(item, "ID", "id", "technique")
            if not sid:
                continue
            # A technique is a finding only if it actually detonated. No state (a plain
            # `stratus list` metadata export) or a non-detonated state = not run = skip.
            if _state(item) not in _DETONATED:
                continue
            state = _state(item)
            tactics = _tactics(item) or [_tactic_from_id(sid)]
            tactic = tactics[0] if tactics else ""
            tid = _first(item, "MitreAttackTechnique", "mitre_attack_technique",
                         "technique_id", "attack_id")
            platform = _first(item, "Platform", "platform", default="cloud")
            name = _first(item, "FriendlyName", "friendly_name", "name", default=sid)
            findings.append(Finding(
                scenario="cloud_attack_simulation",
                target=f"{platform.lower()}:{target_label}" if target_label else platform.lower(),
                severity=tactic_severity(tactic),
                title=f"Cloud Technique Detonated: {name}",
                detail=(f"An ATT&CK cloud technique ({sid}) was detonated on {platform} "
                        f"(tactic {tactic or 'n/a'}). Validate detection/prevention coverage."),
                attack=((tid,) if tid else ()),
                remediation_key="cloud-technique-detonated",
                evidence={
                    "technique_ref": sid,
                    "platform": platform,
                    "tactics": tactics,
                    "technique_id": tid,
                    "state": state or "detonated",
                },
            ))
        return findings

    def coverage(self, data: Any) -> dict[str, Any]:
        detonated = 0
        not_run = 0
        platforms: dict[str, int] = {}
        for item in _iter_techniques(data):
            sid = _first(item, "ID", "id", "technique")
            if not sid:
                continue
            state = _state(item)
            if state in _DETONATED:
                detonated += 1
                plat = _first(item, "Platform", "platform", default="cloud")
                platforms[plat] = platforms.get(plat, 0) + 1
            else:
                not_run += 1
        return {"detonated": detonated, "not_run": not_run, "platforms": platforms}
