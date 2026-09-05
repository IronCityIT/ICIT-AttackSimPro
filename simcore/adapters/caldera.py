"""
caldera.py — ingest a MITRE CALDERA operation report into Iron City findings.

CALDERA (internal name only — never surfaced to a client) orchestrates ATT&CK-aligned
adversary-emulation abilities against hosts an engagement is authorized to test, and
emits an operation report. This adapter reads that report and normalizes each executed
ability into a control-validation finding:

  * an ability that RAN SUCCESSFULLY (status 0) was not prevented — that is a
    detection/prevention gap, severity by ATT&CK tactic;
  * an ability that FAILED / was blocked means the control held — recorded as coverage,
    not a finding.

No adversary emulation is executed here. The report already exists; this is passive
ingestion, the same contract as any other uploaded scan export. White-labeled: findings
carry ATT&CK technique ids, never the orchestrator's name.

Report shapes handled (CALDERA versions differ):
  * {"steps": {"<paw>": {"steps": [ <link>, ... ]}}}
  * {"steps": [ <link>, ... ]}
  * {"links": [ <link>, ... ]}
Each <link> may carry attack metadata under "attack" or as flat fields.
"""

from __future__ import annotations

from typing import Any, Iterable

from simcore.adapters.base import ReportAdapter, tactic_severity
from simcore.base import Finding

# CALDERA link status: 0 == success (ran). Non-zero == failed/blocked/timeout.
_SUCCESS = 0


def _iter_links(data: dict[str, Any]) -> Iterable[dict[str, Any]]:
    steps = data.get("steps")
    if isinstance(steps, dict):
        for agent in steps.values():
            if isinstance(agent, dict):
                yield from (l for l in agent.get("steps", []) if isinstance(l, dict))
            elif isinstance(agent, list):
                yield from (l for l in agent if isinstance(l, dict))
    elif isinstance(steps, list):
        yield from (l for l in steps if isinstance(l, dict))
    for l in data.get("links", []) or []:
        if isinstance(l, dict):
            yield l


def _attack_of(link: dict[str, Any]) -> dict[str, str]:
    a = link.get("attack") if isinstance(link.get("attack"), dict) else {}
    return {
        "technique_id": str(a.get("technique_id") or link.get("technique_id") or "").strip(),
        "technique_name": str(a.get("technique_name") or link.get("technique_name") or "").strip(),
        "tactic": str(a.get("tactic") or link.get("tactic") or "").strip(),
    }


def _status_of(link: dict[str, Any]) -> int:
    val = link.get("status", link.get("result_status"))
    try:
        return int(val)
    except (TypeError, ValueError):
        return -1  # unknown status is treated as "not clearly successful"


class CalderaAdapter(ReportAdapter):
    name = "caldera"
    title = "Automated Adversary Emulation"
    description = "Normalizes an ATT&CK adversary-emulation operation report into findings."

    def parse(self, data: Any, target_label: str = "") -> list[Finding]:
        if not isinstance(data, dict):
            raise ValueError("caldera report must be a JSON object")
        op_name = str(data.get("name") or "operation")
        findings: list[Finding] = []
        for link in _iter_links(data):
            atk = _attack_of(link)
            tid = atk["technique_id"]
            if not tid:
                continue  # skip housekeeping links with no ATT&CK mapping
            host = str(link.get("host") or link.get("paw") or target_label or "host")
            ability = str(link.get("name") or link.get("ability") or atk["technique_name"] or tid)
            if _status_of(link) != _SUCCESS:
                continue  # blocked/failed: the control held, not a finding
            sev = tactic_severity(atk["tactic"])
            findings.append(Finding(
                scenario="adversary_emulation",
                target=host,
                severity=sev,
                title=f"Undetected Technique: {atk['technique_name'] or tid} ({tid})",
                detail=(f"An adversary-emulation ability mapped to {tid} executed on "
                        f"{host} without being prevented (operation '{op_name}', "
                        f"tactic {atk['tactic'] or 'n/a'})."),
                attack=(tid,),
                remediation_key="adversary-technique-unprevented",
                evidence={
                    "technique_id": tid,
                    "technique_name": atk["technique_name"],
                    "tactic": atk["tactic"],
                    "host": host,
                    "ability": ability,
                },
            ))
        return findings

    def coverage(self, data: Any) -> dict[str, Any]:
        """Summarize ATT&CK coverage: techniques executed vs prevented."""
        if not isinstance(data, dict):
            return {"executed": 0, "prevented": 0, "techniques": []}
        techniques: dict[str, dict[str, Any]] = {}
        for link in _iter_links(data):
            atk = _attack_of(link)
            tid = atk["technique_id"]
            if not tid:
                continue
            entry = techniques.setdefault(tid, {"technique_id": tid,
                                                "technique_name": atk["technique_name"],
                                                "tactic": atk["tactic"],
                                                "executed": 0, "prevented": 0})
            if _status_of(link) == _SUCCESS:
                entry["executed"] += 1
            else:
                entry["prevented"] += 1
        return {
            "executed": sum(1 for t in techniques.values() if t["executed"]),
            "prevented": sum(1 for t in techniques.values() if not t["executed"] and t["prevented"]),
            "techniques": sorted(techniques.values(), key=lambda t: t["technique_id"]),
        }
