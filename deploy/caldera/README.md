# Adversary-Emulation Orchestrator — Host Provisioning (for Bill)

Internal name: **MITRE CALDERA**. White-labeled everywhere client-facing as
"Automated Adversary Emulation". This directory *describes* the host setup; it is **not
applied by CI or any agent**. AttackSim Pro is live/sacred — provisioning is a human,
per-engagement action.

## What this adds

An ATT&CK-aligned adversary-emulation orchestrator on the dedicated DigitalOcean ASP
host. It orchestrates the Atomic Red Team tests ASP already has plus custom TTP chains,
and produces an **operation report** per run. The report — not live execution — is what
enters the product:

```
authorized engagement on the ASP host
  → orchestrator runs ATT&CK abilities (per signed authorization)
    → operation report JSON  (deploy/caldera/reports/<op>.json)
      → python -m simcore ingest --adapter caldera --file <report> \
           --client "<client>" --scan-id <op-id> --out evidence/<op-id> --post <STORE_URL>
        → normalized findings + ATT&CK coverage → dashboard
```

The product repo therefore **never executes offensive emulation**. It ingests a report
that an authorized operator produced on the host.

## Safety / scope

- **Not default-on.** The container runs only during an authorized engagement, then is
  stopped. This matches ASP's existing posture for Empire/Veil/Metasploit (gated).
- **Loopback bind only.** The API/UI listens on `127.0.0.1:8888`. Access via SSH tunnel
  or the host's authenticated reverse proxy. Never expose it publicly.
- **Authorized targets only.** Abilities run only against hosts named in a signed ROE for
  that engagement. Nothing here enables unauthorized access, persistence, credential
  theft, or destructive action outside an authorized engagement.

## Secrets (by name only — never commit values)

Create `deploy/caldera/.env` **on the host** (git-ignored) with:

```
CALDERA_API_KEY_RED=...
CALDERA_API_KEY_BLUE=...
CALDERA_ADMIN_PASSWORD=...
```

## Apply (Bill, on the ASP host — not from CI)

```bash
cd deploy/caldera
# pin the image to a digest first, then:
docker compose up -d
# ... run the authorized operation via the tunneled UI/API ...
# export the operation report to ./reports/<op>.json, then ingest it (command above).
docker compose down          # stop when the engagement window closes
```

## Left for Bill

- Pin `image:` to a specific digest.
- Provision the DigitalOcean host + firewall (loopback-only, no public 8888).
- Create the on-host `.env`.
- Wire `STORE_SCAN_RESULTS_URL` / `INGEST_TOKEN` for the ingest POST.
