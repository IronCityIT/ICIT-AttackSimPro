# Endpoint Attack Simulation — Runner (for Bill)

Internal name: **PurpleSharp** (`mvelazc0/PurpleSharp`). White-labeled client-facing as
**"Endpoint Attack Simulation"**. This directory *describes* the runner; it is **not
built or run by CI or any agent**. No simulation happens in this repo.

## What this adds

ATT&CK-mapped Windows technique simulation for **detection validation** — the tool
executes techniques (credential access, discovery, execution, persistence, defense
evasion, lateral movement, C2) on an authorized endpoint to *generate telemetry*, so the
blue team can confirm the EDR/SIEM detection fired. It is a purple-team detection test,
not exploitation. It fills the Windows-endpoint gap the current web/cloud/identity tools
miss.

```
authorized engagement on a Windows test endpoint (signed ROE)
  → run technique simulations → per-technique log + ATT&CK Navigator layer
    → normalize to run-report JSON (or ingest the Navigator layer directly)
      → python -m simcore ingest --adapter purplesharp --file <report.json> \
           --client "<client>" --scan-id <op-id> --out evidence/<op-id> --post <STORE_URL>
        → normalized findings + ATT&CK detection-coverage view → dashboard
```

## Host requirements

The tool is a **Windows / .NET** executable. The runner is a dedicated Windows test
endpoint (a lab / sandbox VM, ideally with the client's EDR image) on the ASP
infrastructure — never an ephemeral Actions runner and never a client production host
without a signed ROE.

## Report the adapter ingests

Two shapes are accepted:

1. A normalized run report (what a thin wrapper emits from the per-technique log):

```json
{
  "run": "Windows Detection Validation",
  "host": "WIN-WKS01",
  "techniques": [
    {"technique_id": "T1003.001", "tactic": "Credential Access", "host": "WIN-DC01", "outcome": "finished"},
    {"technique_id": "T1055", "outcome": "failed"}
  ]
}
```

2. The tool's native **ATT&CK Navigator layer** JSON — an entry that is `enabled` with
   `score >= 1` counts as simulated.

`outcome: finished` (or an enabled Navigator entry) = telemetry generated → a
detection-validation finding, severity by ATT&CK tactic; `failed` / disabled = coverage,
not a finding. `tactic` is read from the report, else derived from a built-in
technique→tactic map, else defaults to execution.

## Safety / scope

- **Authorized endpoint only**, under a signed ROE. The tool generates telemetry; it is
  not exploitation, but it still runs real technique code, so it stays on lab / sandbox
  endpoints unless an engagement authorizes a specific production host.
- **Not default-on / gated**, consistent with ASP's existing offensive-tool posture.
- White-labeled: findings carry the MITRE ATT&CK technique and Windows host, never the
  tool's name.

## Secrets (by name only — never commit values)

```
STORE_SCAN_RESULTS_URL / INGEST_TOKEN   # for the ingest POST
```

The runner itself needs no cloud secret — it runs locally on the authorized endpoint.

## Left for Bill

- Stand up the Windows test-endpoint runner and pin the tool version.
- Finalize the per-technique-log → run-report normalizer for the pinned version (or wire
  the Navigator-layer export straight into `simcore ingest`).
- Wire `STORE_SCAN_RESULTS_URL` / `INGEST_TOKEN` for the ingest POST.
