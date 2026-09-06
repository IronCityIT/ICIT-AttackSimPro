"""
purplesharp.py — ingest a Windows adversary-simulation run into Iron City findings.

The internal tool (name never surfaced to a client) executes ATT&CK-mapped Windows
techniques on an authorized endpoint to *generate telemetry* — its purpose is detection
validation, not exploitation. It emits a per-technique log and can produce an ATT&CK
Navigator layer of the techniques it simulated. This adapter reads either the normalized
run report or that Navigator layer and turns each *simulated* technique into a
detection-validation finding: the technique's telemetry was generated on the host; the
blue team's detection for it must be confirmed to have fired.

  * a SIMULATED technique (the run finished) → a detection-validation finding, severity
    by ATT&CK tactic — "did your detection catch this?";
  * a technique whose simulation FAILED / did not run → coverage, not a finding;
  * `coverage()` → simulated / failed + per-tactic counts for the coverage story.

No simulation is executed here. The run artifact already exists; this is passive
ingestion, the same contract as the CALDERA / Stratus / MAAD adapters. White-labeled:
findings carry the MITRE ATT&CK technique and Windows host, never the tool's name.

Report shapes handled:
  * a normalized run report: a top-level list, or {"techniques"|"results"|"simulations":
    [...]}, of objects with a technique id and an outcome;
  * a native ATT&CK Navigator layer: {"techniques": [{"techniqueID","enabled","score"}]}
    — an entry that is enabled with score >= 1 counts as simulated.
Each entry may carry ``tactic`` / ``technique_name`` / ``host`` / ``outcome``; the tactic
falls back to a built-in technique→tactic map, then to "execution".
"""

from __future__ import annotations

from typing import Any, Iterable

from simcore.adapters.base import ReportAdapter, tactic_severity
from simcore.base import Finding

# Outcomes meaning the technique's telemetry was generated on the host (a gap to detect).
_SIMULATED = {"finished", "success", "succeeded", "completed", "complete", "done",
              "ran", "ok", "simulated", "true", "pass", "passed"}
_FAILED = {"failed", "failure", "error", "exception", "blocked", "skipped",
           "aborted", "false", "notrun", "not-run"}

# Fallback technique(base id) → ATT&CK tactic, so severity is meaningful even when a bare
# Navigator layer carries no tactic. A report-supplied tactic always wins over this.
_TECHNIQUE_TACTIC: dict[str, str] = {
    # credential-access (high)
    "T1003": "credential-access", "T1558": "credential-access",
    "T1552": "credential-access", "T1555": "credential-access",
    "T1110": "credential-access", "T1056": "credential-access",
    # lateral-movement (high)
    "T1021": "lateral-movement", "T1570": "lateral-movement",
    "T1550": "lateral-movement", "T1210": "lateral-movement",
    # command-and-control (high)
    "T1071": "command-and-control", "T1105": "command-and-control",
    "T1219": "command-and-control", "T1090": "command-and-control",
    "T1572": "command-and-control",
    # discovery (medium)
    "T1057": "discovery", "T1018": "discovery", "T1069": "discovery",
    "T1087": "discovery", "T1082": "discovery", "T1016": "discovery",
    "T1049": "discovery", "T1046": "discovery", "T1007": "discovery",
    "T1482": "discovery", "T1033": "discovery",
    # execution (medium)
    "T1059": "execution", "T1053": "execution", "T1204": "execution",
    "T1569": "execution", "T1047": "execution", "T1106": "execution",
    # persistence (medium)
    "T1136": "persistence", "T1543": "persistence", "T1547": "persistence",
    "T1197": "persistence", "T1505": "persistence", "T1546": "persistence",
    # defense-evasion (medium)
    "T1218": "defense-evasion", "T1055": "defense-evasion", "T1070": "defense-evasion",
    "T1112": "defense-evasion", "T1027": "defense-evasion", "T1562": "defense-evasion",
    "T1140": "defense-evasion",
}


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _base_technique(tid: str) -> str:
    # "T1059.001" -> "T1059"; leaves a bare "T1059" untouched.
    return str(tid).split(".")[0].strip().upper()


def _iter_entries(data: Any) -> Iterable[dict[str, Any]]:
    if isinstance(data, dict):
        items = (data.get("techniques") or data.get("results")
                 or data.get("simulations") or data.get("steps") or [])
    else:
        items = data
    for item in items or []:
        if isinstance(item, dict):
            yield item


def _technique_id(item: dict[str, Any]) -> str:
    return str(item.get("technique_id") or item.get("techniqueID")
               or item.get("technique") or item.get("id")
               or item.get("attack_id") or "").strip()


def _is_simulated(item: dict[str, Any]) -> bool | None:
    """True = simulated (a finding), False = failed/coverage, None = not run at all."""
    outcome = _norm(item.get("outcome") or item.get("status")
                    or item.get("result") or item.get("state"))
    if outcome in _SIMULATED:
        return True
    if outcome in _FAILED:
        return False
    # Navigator-layer semantics: enabled with score >= 1 means the technique was simulated.
    if "enabled" in item or "score" in item:
        enabled = item.get("enabled", True)
        try:
            score = float(item.get("score", 0))
        except (TypeError, ValueError):
            score = 0.0
        if enabled and score >= 1:
            return True
        if enabled is False or score < 1:
            return False
    if not outcome:
        # A run report entry with no outcome is treated as simulated (it is present
        # because it ran); a Navigator entry is handled above.
        return True
    return None  # explicit-but-unrecognized outcome: don't guess


def _tactic(item: dict[str, Any], tid: str) -> str:
    supplied = _norm(item.get("tactic"))
    if supplied:
        return supplied
    return _TECHNIQUE_TACTIC.get(_base_technique(tid), "execution")


class PurpleSharpAdapter(ReportAdapter):
    name = "purplesharp"
    title = "Endpoint Attack Simulation"
    description = "Normalizes a Windows ATT&CK adversary-simulation run into findings."

    def parse(self, data: Any, target_label: str = "") -> list[Finding]:
        if not isinstance(data, (list, dict)):
            raise ValueError("endpoint simulation report must be a JSON list or object")
        findings: list[Finding] = []
        for item in _iter_entries(data):
            tid = _technique_id(item)
            if not tid:
                continue
            if _is_simulated(item) is not True:
                continue  # failed / not-run / unrecognized: not a detection-gap finding
            tactic = _tactic(item, tid)
            name = str(item.get("technique_name") or item.get("name")
                       or item.get("technique") or tid).strip()
            host = str(item.get("host") or item.get("hostname")
                       or item.get("machine") or target_label or "endpoint").strip()
            findings.append(Finding(
                scenario="endpoint_attack_simulation",
                target=host,
                severity=tactic_severity(tactic),
                title=f"Simulated Technique Awaiting Detection: {name} ({tid})",
                detail=(f"A Windows ATT&CK technique ({tid}) was simulated on {host} "
                        f"(tactic {tactic}). Confirm the endpoint/SIEM detection for this "
                        f"technique generated an alert; a silent simulation is a "
                        f"detection gap."),
                attack=(tid,),
                remediation_key="endpoint-technique-undetected",
                evidence={
                    "technique_id": tid,
                    "technique_name": name if name != tid else "",
                    "tactic": tactic,
                    "host": host,
                    "outcome": "simulated",
                },
            ))
        return findings

    def coverage(self, data: Any) -> dict[str, Any]:
        simulated = 0
        failed = 0
        tactics: dict[str, int] = {}
        for item in _iter_entries(data):
            tid = _technique_id(item)
            if not tid:
                continue
            state = _is_simulated(item)
            if state is True:
                simulated += 1
                t = _tactic(item, tid)
                tactics[t] = tactics.get(t, 0) + 1
            elif state is False:
                failed += 1
        return {"simulated": simulated, "failed": failed, "tactics": tactics}
