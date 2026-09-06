"""
maad.py — ingest an M365 / Entra ID adversary-emulation run report into findings.

The internal tool (name never surfaced to a client) exercises Microsoft 365 and
Entra ID (Azure AD) identity attack techniques — MFA tampering, backdoor accounts,
mailbox forwarding, eDiscovery exfiltration, cross-tenant-sync backdoors — against a
tenant an engagement is authorized to test, and records each executed action. This
adapter reads that run report and normalizes each *successfully executed* action into a
control-validation finding:

  * an action that EXECUTED (the identity control did not stop it) is a
    detection/prevention gap in the tenant — severity by ATT&CK tactic;
  * an action that FAILED / was blocked means the control held — recorded as coverage,
    not a finding;
  * a pure recon / no-ATT&CK-mapping action is skipped (nothing was attacked).

No emulation is executed here. The run report already exists; this is passive ingestion,
the same contract as the CALDERA and Stratus adapters. White-labeled: findings carry the
MITRE ATT&CK identity technique and the M365 service, never the tool's name.

Report shapes handled (the ASP-host runner / transcript wrapper may differ):
  * a top-level JSON list of module-result objects
  * {"modules": [...]} / {"results": [...]} / {"steps": [...]}
Each entry names a MAAD module/action (``module`` / ``action`` / ``name``) and an outcome
(``outcome`` / ``status`` / ``result`` / ``state``). An entry may also carry its own
``technique_id`` / ``tactic`` which override the built-in module→ATT&CK map.
"""

from __future__ import annotations

from typing import Any, Iterable

from simcore.adapters.base import ReportAdapter, tactic_severity
from simcore.base import Finding

# Outcome tokens that mean the action actually executed against the tenant (a gap).
_EXECUTED = {"success", "succeeded", "executed", "ran", "complete", "completed",
             "done", "ok", "true", "pass", "passed"}
# Tokens that mean the control stopped it (coverage, not a finding).
_BLOCKED = {"error", "failed", "failure", "blocked", "prevented", "denied",
            "unauthorized", "forbidden", "false", "skipped", "aborted"}

# Built-in module → ATT&CK map, mirroring the tool's own MITRE map. Each value is
# (tactic, technique, sub_technique, technique_id, service). Modules with no ATT&CK
# mapping (pure recon) are intentionally absent and are skipped.
_MODULE_ATTACK: dict[str, tuple[str, str, str, str, str]] = {
    "backdooraccountcreation": ("Persistence", "Create Account", "Cloud Account", "T1136.003", "Entra ID"),
    "createaccount": ("Persistence", "Create Account", "Cloud Account", "T1136.003", "Entra ID"),
    "ctsbackdoor": ("Persistence", "Create Account", "Cloud Account", "T1136.003", "Entra ID"),
    "trustednetworkconfig": ("Defense Evasion", "Impair Defenses", "", "T1562", "Entra ID"),
    "disablemailboxauditing": ("Defense Evasion", "Impair Defenses", "", "T1562", "Exchange Online"),
    "disableantiphishing": ("Defense Evasion", "Impair Defenses", "", "T1562", "Exchange Online"),
    "mailboxdeleterulesetup": ("Defense Evasion", "Hide Artifacts", "Email Hiding Rules", "T1564.008", "Exchange Online"),
    "mailforwarding": ("Collection", "Email Collection", "", "T1114", "Exchange Online"),
    "grantmailboxaccess": ("Persistence", "Account Manipulation", "Additional Email Delegate Permissions", "T1098.002", "Exchange Online"),
    "externalteamsaccess": ("Collection", "Data from Information Repositories", "", "T1213", "Teams"),
    "ediscovery": ("Collection", "Automated Collection", "", "T1119", "Compliance"),
    "bruteforce": ("Credential Access", "Brute Force", "", "T1110", "Entra ID"),
    "disablemfa": ("Defense Evasion", "Modify Authentication Process", "Multi-Factor Authentication", "T1556.006", "Entra ID"),
    "sharepointexploiter": ("Collection", "Data from Information Repositories", "SharePoint", "T1213.002", "SharePoint"),
    "removeaccess": ("Impact", "Account Access Removal", "", "T1531", "Entra ID"),
    "toranonymizer": ("Command and Control", "Proxy", "Multi-hop Proxy", "T1090.003", "Endpoint"),
    "resetpassword": ("Persistence", "Account Manipulation", "Additional Cloud Roles", "T1098.003", "Entra ID"),
    "addobjecttogroup": ("Persistence", "Account Manipulation", "Additional Cloud Roles", "T1098.003", "Entra ID"),
    "assignrole": ("Persistence", "Account Manipulation", "Additional Cloud Roles", "T1098.003", "Entra ID"),
    "generatenewapplicationcredentials": ("Persistence", "Account Manipulation", "Additional Cloud Credentials", "T1098.001", "Entra ID"),
    "exploitcrosstenantsynchronization": ("Persistence", "Create Account", "Cloud Account", "T1136.003", "Entra ID"),
}

# Friendly, client-safe display names for the recognized modules (never the tool name).
_MODULE_DISPLAY: dict[str, str] = {
    "backdooraccountcreation": "Backdoor account created",
    "createaccount": "Rogue account created",
    "ctsbackdoor": "Cross-tenant-sync backdoor established",
    "trustednetworkconfig": "Trusted-location policy tampered",
    "disablemailboxauditing": "Mailbox auditing disabled",
    "disableantiphishing": "Anti-phishing policy disabled",
    "mailboxdeleterulesetup": "Mailbox hiding/deletion rule created",
    "mailforwarding": "Mailbox forwarding configured",
    "grantmailboxaccess": "Mailbox delegate access granted",
    "externalteamsaccess": "External Teams access granted",
    "ediscovery": "eDiscovery data collection run",
    "bruteforce": "Credential brute-force succeeded",
    "disablemfa": "Multi-factor authentication disabled",
    "sharepointexploiter": "SharePoint data accessed",
    "removeaccess": "Account access removed (lockout)",
    "toranonymizer": "Anonymized (multi-hop proxy) access",
    "resetpassword": "Account password reset",
    "addobjecttogroup": "Privileged group membership added",
    "assignrole": "Privileged directory role assigned",
    "generatenewapplicationcredentials": "New application credential minted",
    "exploitcrosstenantsynchronization": "Cross-tenant synchronization abused",
}

# Aliases: arsenal / transcript labels that resolve to a canonical module key.
_ALIASES: dict[str, str] = {
    "deploybackdooraccount": "backdooraccountcreation",
    "disableaccountmfa": "disablemfa",
    "assignazureadrole": "assignrole",
    "assignmanagementrole": "assignrole",
    "adduser togroup": "addobjecttogroup",
    "adduser to group": "addobjecttogroup",
    "addusertogroup": "addobjecttogroup",
    "setupemailforwarding": "mailforwarding",
    "setupemaildeletionrule": "mailboxdeleterulesetup",
    "gainaccesstoanothermailbox": "grantmailboxaccess",
    "gainaccesstosharepointsite": "sharepointexploiter",
    "exfiltratedatafromsharepoint": "sharepointexploiter",
    "inviteexternalusertoteams": "externalteamsaccess",
    "exploitcrosstenantsync": "exploitcrosstenantsynchronization",
    "modifytrustedipconfig": "trustednetworkconfig",
    "deleteuser": "removeaccess",
    "exfildatawithediscovery": "ediscovery",
}


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _iter_modules(data: Any) -> Iterable[dict[str, Any]]:
    if isinstance(data, dict):
        items = (data.get("modules") or data.get("results")
                 or data.get("steps") or data.get("actions") or [])
    else:
        items = data
    for item in items or []:
        if isinstance(item, dict):
            yield item


def _module_key(item: dict[str, Any]) -> str:
    raw = _norm(item.get("module") or item.get("action")
               or item.get("name") or item.get("technique"))
    key = raw.replace("-", "").replace("_", "").replace(" ", "")
    if key in _MODULE_ATTACK:
        return key
    if raw in _ALIASES:
        return _ALIASES[raw]
    if key in _ALIASES:
        return _ALIASES[key]
    return key  # unknown; resolved only if the entry carries its own ATT&CK id


def _outcome(item: dict[str, Any]) -> str:
    val = _norm(item.get("outcome") or item.get("status") or item.get("result")
                or item.get("state") or item.get("event_type"))
    if val in _EXECUTED:
        return "executed"
    if val in _BLOCKED:
        return "blocked"
    return "unknown"


class MaadAdapter(ReportAdapter):
    name = "maad"
    title = "Identity Attack Simulation"
    description = "Normalizes an M365/Entra ID identity adversary-emulation report into findings."

    def parse(self, data: Any, target_label: str = "") -> list[Finding]:
        if not isinstance(data, (list, dict)):
            raise ValueError("identity attack report must be a JSON list or object")
        tenant = ""
        if isinstance(data, dict):
            tenant = str(data.get("tenant") or data.get("operation") or "")
        findings: list[Finding] = []
        for item in _iter_modules(data):
            key = _module_key(item)
            builtin = _MODULE_ATTACK.get(key)
            # An entry may override / supply its own ATT&CK mapping.
            tid = str(item.get("technique_id") or item.get("attack_id")
                      or (builtin[3] if builtin else "")).strip()
            tactic = str(item.get("tactic") or (builtin[0] if builtin else "")).strip()
            if not tid and not tactic:
                continue  # recon / unmapped action: nothing was attacked
            if _outcome(item) != "executed":
                continue  # blocked/failed/unknown: the control held, not a finding
            technique = str(item.get("technique_name")
                            or (builtin[1] if builtin else "")).strip()
            service = str(item.get("service")
                          or (builtin[4] if builtin else "M365")).strip()
            display = _MODULE_DISPLAY.get(key) or technique or (tid or key)
            target = (str(item.get("target") or item.get("account")
                          or item.get("mailbox") or item.get("upn")
                          or target_label or tenant or service).strip())
            sev = tactic_severity(tactic)
            findings.append(Finding(
                scenario="identity_attack_simulation",
                target=target,
                severity=sev,
                title=f"Undetected Identity Attack: {display}"
                      + (f" ({tid})" if tid else ""),
                detail=(f"An M365/Entra identity technique ({technique or display}"
                        + (f", {tid}" if tid else "")
                        + f") executed against {service} on {target} without being "
                        f"prevented (tactic {tactic or 'n/a'}). Validate that the "
                        f"identity detection stack alerted on this activity."),
                attack=((tid,) if tid else ()),
                remediation_key="identity-technique-unprevented",
                evidence={
                    "module": key,
                    "service": service,
                    "technique": technique,
                    "technique_id": tid,
                    "tactic": tactic,
                    "outcome": "executed",
                    "target": target,
                    "tenant": tenant,
                },
            ))
        return findings

    def coverage(self, data: Any) -> dict[str, Any]:
        """Summarize identity coverage: techniques executed vs prevented per service."""
        executed = 0
        prevented = 0
        services: dict[str, int] = {}
        for item in _iter_modules(data):
            key = _module_key(item)
            builtin = _MODULE_ATTACK.get(key)
            tid = str(item.get("technique_id") or (builtin[3] if builtin else "")).strip()
            tactic = str(item.get("tactic") or (builtin[0] if builtin else "")).strip()
            if not tid and not tactic:
                continue
            service = str(item.get("service") or (builtin[4] if builtin else "M365")).strip()
            outcome = _outcome(item)
            if outcome == "executed":
                executed += 1
                services[service] = services.get(service, 0) + 1
            elif outcome == "blocked":
                prevented += 1
        return {"executed": executed, "prevented": prevented, "services": services}
