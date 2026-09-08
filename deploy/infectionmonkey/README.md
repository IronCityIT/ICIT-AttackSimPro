# Network Attack Simulation — Runner (for Bill)

Internal name: **Infection Monkey** (`guardicore/monkey`, Akamai). White-labeled
client-facing as **"Network Attack Simulation"**. This directory *describes* the
server-tier runner; it is **not built or run by CI or any agent**. No propagation happens
here.

## What this adds

Network BAS — safe, self-propagating validation of **lateral movement, exploitation,
credential reuse, and network segmentation** across a segment an engagement is authorized
to test. Fills the "can it spread / is the network flat" gap the endpoint/cloud/identity
adapters do not cover. Server-tier: runs on the DigitalOcean/NAS ASP infrastructure (an
Island + agents), not on ephemeral Actions runners.

```
authorized engagement against an authorized network segment (signed ROE)
  → Island orchestrates agents → security report → normalize to an events JSON
    → python -m simcore ingest --adapter infectionmonkey --file <events.json> \
         --client "<client>" --scan-id <op-id> --out evidence/<op-id> --post <STORE_URL>
      → normalized findings (lateral movement + segmentation) → dashboard
```

## Report the adapter ingests

A normalized events JSON (a wrapper extracts these from the Island security report):

```json
{
  "operation": "Network BAS - Acme",
  "events": [
    {"type": "exploitation", "source": "10.0.0.5", "target": "10.0.1.9", "technique_id": "T1210", "success": true},
    {"type": "segmentation", "source_segment": "workstations", "target_segment": "servers", "target": "10.0.1.9", "success": true},
    {"type": "propagation", "source": "10.0.1.9", "target": "10.0.2.4", "technique_id": "T1021", "success": true},
    {"type": "credential_reuse", "target": "10.0.2.4", "technique_id": "T1078", "success": true}
  ]
}
```

A **successful** event = a network control gap: exploitation/propagation → lateral-movement
finding; `segmentation` crossing a boundary → a segmentation gap (the headline network
finding); credential reuse → credential-access. A failed/blocked event = coverage. Robust
to top-level-list and `{events|results|findings:[…]}` shapes.

## Safety / scope

- **Authorized network only**, under a signed ROE. Propagation is non-destructive but it is
  real network activity — scope it to the authorized segment and decommission agents after.
- **Not default-on / gated**, and server-tier (provisioned by Bill), consistent with ASP's
  existing posture.
- White-labeled: findings carry ATT&CK technique + network context, never the tool's name.

## Provisioning (Bill — describe-not-apply)

Stand up the Island + agents on the ASP infrastructure via IaC/compose (not applied here);
provide `STORE_SCAN_RESULTS_URL` / `INGEST_TOKEN` for the ingest POST; pin the tool version;
finalize the security-report → events-JSON normalizer.
