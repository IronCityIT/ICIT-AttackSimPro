# Malicious Traffic Simulation — Runner (for Bill)

Internal name: **flightsim** (`alphasoc/flightsim`). White-labeled client-facing as
**"Malicious Traffic Simulation"**. This directory *describes* the runner; it is **not built
or run by CI or any agent**. No traffic is generated here.

## What this adds

Safe, synthetic **malicious network traffic** — C2 beacons, DGA lookups, DNS/ICMP
tunneling, data exfiltration, port scans, cryptomining callbacks — generated from an
authorized host to test whether the network detection stack (NDR / DNS security / egress
filtering / SIEM) alerts. Detection testing without touching endpoints; complements the
endpoint/identity/cloud adapters with a network-traffic detection dimension.

```
authorized host on an authorized network (signed ROE)
  → generate synthetic malicious traffic → results
    → normalize to a modules JSON
      → python -m simcore ingest --adapter flightsim --file <report.json> \
           --client "<client>" --scan-id <op-id> --out evidence/<op-id> --post <STORE_URL>
        → normalized findings + ATT&CK network-detection coverage → dashboard
```

## Report the adapter ingests

```json
{
  "operation": "Malicious Traffic Detection Test",
  "host": "corp-host-07",
  "modules": [
    {"module": "c2", "destinations": ["1.2.3.4"], "status": "success"},
    {"module": "dns-tunnel", "status": "success"},
    {"module": "tor", "status": "failed"}
  ]
}
```

A module that generated traffic (`status: success`, or destinations/packets sent) →
detection-validation finding, severity by ATT&CK tactic (C2 / exfiltration = high); a
failed module = coverage. Built-in module→ATT&CK map (c2 → T1071, dga → T1568.002,
dns-tunnel → T1071.004, ssh-exfil → T1048, scan → T1046, tor → T1090.003, miner → T1496,
…); an entry may supply its own technique_id/tactic. Robust to list / {modules|results|
runs:[…]} shapes.

## Safety / scope

- **Authorized host + network only**, under a signed ROE. The traffic is synthetic and
  non-destructive, but it is real egress — scope it and coordinate with the SOC (it will,
  by design, look malicious).
- **Not default-on / gated**, consistent with ASP's existing posture.
- White-labeled: findings carry the ATT&CK technique + traffic category, never the tool's
  name.

## Left for Bill

- Stand up the runner on an authorized host and pin the tool version.
- Finalize the results → modules-JSON normalizer.
- Wire `STORE_SCAN_RESULTS_URL` / `INGEST_TOKEN` for the ingest POST.
