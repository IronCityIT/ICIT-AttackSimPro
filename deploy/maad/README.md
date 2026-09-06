# Identity Attack Simulation — Runner (for Bill)

Internal name: **MAAD Attack Framework (MAAD-AF)** (`vectra-ai-research/MAAD-AF`).
White-labeled client-facing as **"Identity Attack Simulation"**. This directory
*describes* the runner; it is **not built or run by CI or any agent**. No emulation
happens in this repo.

## What this adds

M365 & Entra ID (Azure AD) identity attack techniques — MFA tampering, backdoor
accounts, privileged-role assignment, mailbox forwarding/hiding rules, eDiscovery
exfiltration, cross-tenant-sync backdoors — exercised against an **authorized M365
sandbox tenant**. The runner records each executed action; a thin wrapper emits a
normalized run report JSON, and that JSON — not live emulation — enters the product:

```
authorized engagement against an M365/Entra sandbox tenant (signed ROE)
  → run identity techniques → transcript/log → normalize to run-report JSON
    → python -m simcore ingest --adapter maad --file <report.json> \
         --client "<client>" --scan-id <op-id> --out evidence/<op-id> --post <STORE_URL>
      → normalized findings + ATT&CK identity coverage → dashboard
```

## Host requirements

MAAD-AF is **Windows PowerShell 5.1** and drives the Microsoft identity PowerShell
modules (`AzureAD`, `MSOnline`, `ExchangeOnlineManagement`, `MicrosoftTeams`,
`Microsoft.Online.SharePoint.PowerShell`). It is **not** Linux/Docker-friendly, so the
runner is a dedicated Windows/PowerShell host on the ASP infrastructure — not an
ephemeral Actions runner and not this repo's CI.

## Normalized run-report JSON (what the wrapper emits, what the adapter ingests)

The adapter is tolerant of the tool's transcript shapes, but the canonical contract is:

```json
{
  "operation": "M365 Purple-Team Validation",
  "tenant": "<sandbox-tenant>.onmicrosoft.com",
  "modules": [
    {"module": "DisableMFA",  "target": "user@sandbox", "outcome": "success"},
    {"module": "BruteForce",  "target": "user@sandbox", "outcome": "failed"}
  ]
}
```

- `module` — the action id (also accepts `action`/`name`, and the arsenal labels via
  built-in aliases, e.g. "Setup Email Forwarding" → mailbox forwarding).
- `outcome` — `success` = the identity control did **not** stop it → a
  detection/prevention-gap finding, severity by ATT&CK tactic; `failed`/`blocked` = the
  control held → counted as coverage, not a finding.
- An entry may carry its own `technique_id` / `tactic` to map a custom TTP the built-in
  module→ATT&CK map does not cover.

An example normalizer (reads MAAD-AF's own transcript, emits the JSON above — a
read-only converter, it attacks nothing):

```powershell
# emit-report.ps1 (example; Bill runs it on the authorized host after a session)
$modules = Get-Content $Transcript |
  Select-String '\[(SUCCESS|ERROR)\]' |
  ForEach-Object {
    # map each logged action line to {module, target, outcome}; see the module table
  }
@{ operation = $OpName; tenant = $Tenant; modules = $modules } |
  ConvertTo-Json -Depth 5 | Set-Content report.json
```

## Safety / scope

- **Sandbox tenant only.** Techniques run against a throwaway M365/Entra sandbox tenant
  provisioned for the engagement — never a client production tenant, never without a
  signed ROE. Undo each action and decommission the sandbox after the run (several
  modules self-undo; verify).
- **Not default-on / gated**, consistent with ASP's existing offensive-tool posture.
- **Least privilege.** The runner authenticates with credentials scoped to the sandbox
  tenant only.
- White-labeled: findings carry the MITRE ATT&CK identity technique and the M365
  service, never the tool's name.

## Secrets (by name only — never commit values)

Provide sandbox-tenant credentials to the runner via the host environment:

```
MAAD_SANDBOX_TENANT_ID
MAAD_SANDBOX_APP_ID / MAAD_SANDBOX_APP_SECRET   # or an interactive admin sign-in
STORE_SCAN_RESULTS_URL / INGEST_TOKEN           # for the ingest POST
```

## Left for Bill

- Stand up the Windows/PowerShell runner host and pin the tool version.
- Provision the disposable M365/Entra sandbox tenant + scoped credentials.
- Finalize the transcript→JSON normalizer for the pinned tool version.
- Wire `STORE_SCAN_RESULTS_URL` / `INGEST_TOKEN` for the ingest POST.
