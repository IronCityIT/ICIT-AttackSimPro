# ICIT-AttackSimPro

# ICIT AttackSimPro (Purple Team)

ICIT AttackSimPro is a controlled, authorized **Purple Team** validation product from **Iron City IT Advisors**. It is purpose-built to help organizations continuously validate security controls and detection coverage using **non-destructive, audit-defensible simulations**.

AttackSimPro is intentionally separate from **ICIT Sentinel** (SIEM / detection). Sentinel monitors and correlates; AttackSimPro validates and generates repeatable evidence.

---

## What AttackSimPro Delivers

AttackSimPro focuses on repeatable, low-risk validation that produces **evidence bundles** suitable for audit readiness, control verification, and continuous improvement.

Core capabilities include:

- **Web Security Baseline Validation (Passive)**
  - OWASP ZAP Baseline (passive, non-exploitative)
  - Security header verification
  - TLS certificate and posture checks

- **Template-Based Vulnerability Identification**
  - Nuclei scans (no exploit chaining)
  - Findings packaged as timestamped artifacts

- **Evidence Generation & Packaging**
  - Timestamped output bundles (JSON / HTML / ZIP)
  - Repeatable runs with consistent structure
  - Storage in a centralized Evidence Vault (Google Drive initially)

- **Automation-First Orchestration**
  - GitHub Actions scheduled workflows (cron)
  - Optional external schedulers (Cron To Go) for webhook-driven runs

---

## What AttackSimPro Is NOT

AttackSimPro is **not** a red-team platform and is not designed for covert or exploitative activity.

This product does not support and must not be used for:
- Exploit frameworks or exploit payload delivery
- Credential harvesting, brute-force, or password spraying
- Persistence mechanisms or covert command-and-control
- Data exfiltration, destructive testing, or out-of-scope lateral movement
- Any activity against systems without explicit written authorization

AttackSimPro is designed to be **insurable, contract-safe, and audit-defensible** by default.

---

## Authorized Use Only

All AttackSimPro activity must be:
- Explicitly authorized in writing
- Executed only against in-scope assets
- Scheduled and coordinated with stakeholders (Purple Team model)
- Designed to validate controls and detections without disrupting operations

See: `DISCLAIMER.md` and `docs/scope/` for scope and usage rules.

---

## Repo Layout

```
functions/            storeScanResults ingest (Cloud Function)
  handler.js          pure, dependency-injected request handler (all logic)
  index.js            production shell: firebase-admin + Cloud Functions wiring
  local-server.js     zero-dependency local HTTP server (in-memory Firestore)
  testkit/            in-memory Firestore + req/res doubles (test/local only)
  test/               deterministic unit tests (node:test)
  Dockerfile          reproducible local ingest container
public/index.html     Firebase-hosted purple-team dashboard
firestore.rules       multi-tenant read rules (clients/{client_id}/scans)
scripts/smoke.sh      end-to-end ingest smoke test (curl)
.github/workflows/    scan workflows + deploy-functions (workflow_dispatch)
docs/SDLC_STATUS.md   current build status, evidence, and blockers
```

## Running Locally

No GCP credentials, no deploy, no network egress are required for local runs; the
local server runs the exact production handler against an in-memory Firestore double.

```bash
make check            # lint + 16 unit tests + end-to-end smoke test
make serve-ingest     # storeScanResults on http://127.0.0.1:8088
make serve-dashboard  # dashboard on http://127.0.0.1:8080
docker compose up --build   # ingest (:8088) + dashboard (:8080), containerized
```

Open the dashboard for a specific tenant with `?client=<client_id>`, e.g.
`http://127.0.0.1:8080/index.html?client=acme-corp`. Without a client it renders
built-in demo data (shown by a DEMO banner). Post a scan result to the local ingest:

```bash
curl -X POST http://127.0.0.1:8088/ -H 'Content-Type: application/json' \
  -d '{"client_name":"Acme Corp","scan_id":"scan-1","target":"https://acme.example",
       "status":"completed","findings":[{"name":"Missing HSTS","risk":"medium"}]}'
```

See `docs/SDLC_STATUS.md` for build status, test evidence, and open blockers.
