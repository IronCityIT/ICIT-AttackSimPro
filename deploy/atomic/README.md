# Endpoint Technique Emulation — Runner (for Bill)

Internal name: **Atomic Red Team** / **Invoke-AtomicRedTeam** (`redcanaryco/invoke-atomicredteam`).
White-labeled client-facing as **"Endpoint Technique Emulation"**. This directory
*describes* the runner; it is **not built or run by CI or any agent**. No test is executed
here.

## What this adds

A large library of granular, ATT&CK-mapped atomic tests run on an **authorized endpoint**
to generate telemetry for **detection validation** (not exploitation). Complements the
endpoint C# simulation adapter with a different, broad atomic-test corpus, and turns the
Atomic Red Team data ASP already references into scheduled, ingestible detection tests.

```
authorized engagement on a Windows/Linux/macOS test endpoint (signed ROE)
  → Invoke-AtomicTest <technique> -ExecutionLogPath log.csv
    → normalize the execution log to a run-report JSON
      → python -m simcore ingest --adapter atomic --file <report.json> \
           --client "<client>" --scan-id <op-id> --out evidence/<op-id> --post <STORE_URL>
        → normalized findings + ATT&CK detection coverage → dashboard
```

## Report the adapter ingests

A normalized JSON run report (a thin wrapper converts the execution-log CSV):

```json
{
  "operation": "Endpoint Detection Validation",
  "host": "WIN-WKS01",
  "atomics": [
    {"technique": "T1059.001", "test_name": "Mimikatz via PowerShell", "exit_code": 0},
    {"technique": "T1055", "test_name": "Process Injection", "exit_code": 1}
  ]
}
```

`exit_code: 0` (or `outcome: success`) = the test executed → a detection-validation finding,
severity by ATT&CK tactic; a non-zero exit / `error` = coverage, not a finding. `tactic` is
read from the report, else derived from a built-in technique→tactic map. Robust to
top-level-list and `{atomics|results|tests|executions:[…]}` shapes and the tool's
PascalCase log columns (Technique / TestName / ExitCode / Hostname).

## Safety / scope

- **Authorized endpoint only**, under a signed ROE. The atomics run real technique code
  (for telemetry), so they stay on lab / sandbox endpoints unless an engagement authorizes
  a specific production host. Run destructive atomics only with explicit authorization.
- **Not default-on / gated**, consistent with ASP's existing offensive-tool posture.
- White-labeled: findings carry the ATT&CK technique + atomic test name, never the tool's
  name.

## Secrets (by name only — never commit values)

```
STORE_SCAN_RESULTS_URL / INGEST_TOKEN   # for the ingest POST
```

The runner needs no cloud secret — it runs locally on the authorized endpoint.

## Left for Bill

- Stand up the endpoint runner and pin the tool + atomics version.
- Finalize the execution-log → run-report normalizer for the pinned version.
- Wire `STORE_SCAN_RESULTS_URL` / `INGEST_TOKEN` for the ingest POST.
