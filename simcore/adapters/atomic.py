"""
atomic.py — ingest an endpoint atomic-test execution log into Iron City findings.

The internal tool (name never surfaced to a client) runs granular, ATT&CK-mapped atomic
tests on an authorized endpoint to generate telemetry — detection validation, not
exploitation — and writes an execution log (one row per executed test: technique id, test
name, exit code). This adapter reads the normalized log and turns each *executed* test
into a detection-validation finding: the test's telemetry was generated on the host; the
blue team's detection for that technique must be confirmed to have fired.

  * an EXECUTED test (exit code 0 / success) → detection-validation finding, severity by
    ATT&CK tactic;
  * a FAILED / errored test → coverage, not a finding;
  * `coverage()` → executed / failed + per-technique counts.

No test is executed here. The log already exists; this is passive ingestion, the same
contract as the CALDERA / Stratus / MAAD / endpoint-simulation adapters. White-labeled:
findings carry the ATT&CK technique + atomic test name, never the tool's name.

Report shapes handled (a wrapper converts the tool's execution-log CSV/JSON to this):
  * a top-level JSON list, or {"atomics"|"results"|"tests"|"executions": [...]}
Each entry carries a technique id (technique/technique_id/attack_technique) and an outcome
(exit_code == 0 = executed, or outcome/status in a success set), plus optional test_name /
guid / tactic / host.
"""

from __future__ import annotations

from typing import Any, Iterable

from simcore.adapters.base import ReportAdapter, tactic_severity
from simcore.base import Finding

_SUCCESS = {"success", "succeeded", "executed", "ran", "complete", "completed", "done",
            "ok", "pass", "passed", "true"}
_FAILED = {"failed", "failure", "error", "errored", "blocked", "skipped", "aborted",
           "false", "notrun", "not-run"}

# Compact technique(base)->tactic fallback for common atomic techniques, so severity is
# meaningful when the log omits the tactic. A report-supplied tactic always wins.
_TECHNIQUE_TACTIC: dict[str, str] = {
    "T1003": "credential-access", "T1552": "credential-access", "T1555": "credential-access",
    "T1558": "credential-access", "T1110": "credential-access", "T1056": "credential-access",
    "T1021": "lateral-movement", "T1570": "lateral-movement", "T1550": "lateral-movement",
    "T1071": "command-and-control", "T1105": "command-and-control", "T1219": "command-and-control",
    "T1090": "command-and-control", "T1572": "command-and-control",
    "T1048": "exfiltration", "T1041": "exfiltration", "T1567": "exfiltration",
    "T1486": "impact", "T1490": "impact", "T1489": "impact", "T1485": "impact",
    "T1057": "discovery", "T1018": "discovery", "T1082": "discovery", "T1087": "discovery",
    "T1016": "discovery", "T1049": "discovery", "T1033": "discovery", "T1518": "discovery",
    "T1059": "execution", "T1053": "execution", "T1204": "execution", "T1569": "execution",
    "T1047": "execution", "T1106": "execution",
    "T1547": "persistence", "T1543": "persistence", "T1546": "persistence",
    "T1136": "persistence", "T1197": "persistence", "T1505": "persistence",
    "T1218": "defense-evasion", "T1055": "defense-evasion", "T1070": "defense-evasion",
    "T1112": "defense-evasion", "T1027": "defense-evasion", "T1562": "defense-evasion",
    "T1140": "defense-evasion", "T1548": "privilege-escalation", "T1134": "privilege-escalation",
}


def _norm(v: Any) -> str:
    return str(v or "").strip().lower()


def _base_technique(tid: str) -> str:
    return str(tid).split(".")[0].strip().upper()


def _iter_entries(data: Any) -> Iterable[dict[str, Any]]:
    if isinstance(data, dict):
        items = (data.get("atomics") or data.get("results") or data.get("tests")
                 or data.get("executions") or data.get("steps") or [])
    else:
        items = data
    for item in items or []:
        if isinstance(item, dict):
            yield item


def _technique_id(item: dict[str, Any]) -> str:
    return str(item.get("technique_id") or item.get("technique")
               or item.get("attack_technique") or item.get("Technique")
               or item.get("attack_id") or "").strip()


def _executed(item: dict[str, Any]) -> bool | None:
    """True = executed (finding), False = failed (coverage), None = indeterminate."""
    # Invoke-AtomicTest logs an ExitCode; 0 == the atomic ran.
    for key in ("exit_code", "ExitCode", "exitcode"):
        if key in item and item[key] is not None:
            try:
                return int(item[key]) == 0
            except (TypeError, ValueError):
                pass
    outcome = _norm(item.get("outcome") or item.get("status") or item.get("result")
                    or item.get("state"))
    if outcome in _SUCCESS:
        return True
    if outcome in _FAILED:
        return False
    if not outcome:
        return True  # a logged execution with no explicit status is a run
    return None


def _tactic(item: dict[str, Any], tid: str) -> str:
    supplied = _norm(item.get("tactic"))
    if supplied:
        return supplied
    return _TECHNIQUE_TACTIC.get(_base_technique(tid), "execution")


class AtomicAdapter(ReportAdapter):
    name = "atomic"
    title = "Endpoint Technique Emulation"
    description = "Normalizes an endpoint ATT&CK technique-execution log into findings."

    def parse(self, data: Any, target_label: str = "") -> list[Finding]:
        if not isinstance(data, (list, dict)):
            raise ValueError("atomic execution log must be a JSON list or object")
        findings: list[Finding] = []
        for item in _iter_entries(data):
            tid = _technique_id(item)
            if not tid:
                continue
            if _executed(item) is not True:
                continue  # failed / indeterminate: not a detection-gap finding
            tactic = _tactic(item, tid)
            test_name = str(item.get("test_name") or item.get("TestName")
                            or item.get("name") or item.get("test") or "").strip()
            host = str(item.get("host") or item.get("hostname") or item.get("Hostname")
                       or target_label or "endpoint").strip()
            guid = str(item.get("guid") or item.get("GUID")
                       or item.get("auto_generated_guid") or "").strip()
            label = test_name or tid
            findings.append(Finding(
                scenario="endpoint_technique_emulation",
                target=host,
                severity=tactic_severity(tactic),
                title=f"Atomic Technique Executed Undetected: {label} ({tid})",
                detail=(f"An ATT&CK atomic test ({tid}"
                        + (f", '{test_name}'" if test_name else "")
                        + f") executed on {host} (tactic {tactic}). Confirm the "
                        f"endpoint/SIEM detection for this technique generated an alert; "
                        f"a silent execution is a detection gap."),
                attack=(tid,),
                remediation_key="endpoint-technique-undetected",
                evidence={
                    "technique_id": tid,
                    "test_name": test_name,
                    "guid": guid,
                    "tactic": tactic,
                    "host": host,
                    "outcome": "executed",
                },
            ))
        return findings

    def coverage(self, data: Any) -> dict[str, Any]:
        executed = 0
        failed = 0
        techniques: dict[str, int] = {}
        for item in _iter_entries(data):
            tid = _technique_id(item)
            if not tid:
                continue
            state = _executed(item)
            if state is True:
                executed += 1
                techniques[tid] = techniques.get(tid, 0) + 1
            elif state is False:
                failed += 1
        return {"executed": executed, "failed": failed, "techniques": techniques}
