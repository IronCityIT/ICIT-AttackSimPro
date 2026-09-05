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

## Simulation Engine (`simcore/`)

The product's core is a **modular, authorized, non-destructive simulation engine**. Each
capability is one scenario; a scope gate authorizes every target; runs emit signed
evidence bundles and white-labeled reports; actions are RBAC-gated and audited.

```bash
pip install pyyaml                      # only external dependency
python3 -m simcore list                 # the scenario library (9 scenarios)
python3 -m simcore run \
  --targets http://127.0.0.1:9101 \
  --group standard --client "Acme Corp" --scan-id sim-1 \
  --out evidence/sim-1 --audit-log evidence/audit.log
python3 -m simcore verify --bundle evidence/sim-1     # check evidence integrity
python3 -m simcore report --run evidence/sim-1/run.json --format md
python3 -m simcore schedule --file schedule.example.yaml
```

**Safety by construction.** Loopback / private (RFC 1918/4193) targets are the always-
allowed sandbox. Any other target is **refused** unless the run passes `--allow-external`
**and** a matching, in-window authorization record exists under `authorizations/`. The
repo ships **zero** live external authorizations. Scenarios only inspect (GET/HEAD/OPTIONS,
connect-only TCP, handshake-only TLS) — no exploitation, no payloads, no mutation.

**Scenario groups:** `quick`, `standard`, `deep`, `compliance`. Run one scenario
(`--scenarios security_headers,tls_posture`) or a group (`--group deep`). The dashboard's
scenario library renders from the same registry (`public/catalog.json`).

## Repo Layout

```
simcore/              safe simulation engine (Python, stdlib + PyYAML)
  base.py             SimulationScenario / Finding / ScenarioResult contract
  registry.py         scenario discovery + selection (CLI + dashboard source of truth)
  runner.py           orchestration: scope → probes → findings → evidence → audit
  scope.py            authorization / scope gate (the safety core)
  net.py              the only network surface (inspection-only probes)
  evidence.py         signed (SHA-256 manifest) evidence bundles
  reporting.py        white-labeled Markdown + HTML reports
  remediation.py      shared remediation + compliance catalog
  rbac.py / audit.py  roles + tamper-evident (hash-chained) audit trail
  scheduler.py        cron parsing, next-run, run planning
  cli.py              `python -m simcore …`
  scenarios/          9 MITRE ATT&CK-mapped, non-destructive scenarios
  tests/              unit + integration + security suites (unittest)
authorizations/       Rules-of-Engagement records (README + .sample template)
functions/            storeScanResults ingest (Cloud Function) — see below
public/index.html     Firebase-hosted dashboard (+ catalog.json / remediation.json)
firestore.rules       multi-tenant read rules (clients/{client_id}/scans)
scripts/smoke.sh      ingest smoke test (curl)
scripts/e2e/          end-to-end sandbox simulation
.github/workflows/    simulation.yml (consensus-wired) + scan + deploy workflows
Jenkinsfile           CI pipeline (full gate)
docs/                 ACCEPTANCE_CRITERIA.md, SDLC_STATUS.md, evidence/
```

### Ingest Cloud Function (`functions/`)

```
functions/handler.js       pure, dependency-injected request handler (all logic)
functions/index.js         production shell: firebase-admin + Cloud Functions wiring
functions/local-server.js  zero-dependency local HTTP server (in-memory Firestore)
functions/testkit/         in-memory Firestore + req/res doubles (test/local only)
functions/test/            deterministic unit tests (node:test)
```

## Running Locally

No GCP credentials, no deploy, no network egress are required for local runs; the
local server runs the exact production handler against an in-memory Firestore double.

```bash
make gate             # FULL gate: lint + ingest tests + smoke + engine tests + E2E
make engine-test      # simulation engine suite (unit + integration + security)
make e2e              # end-to-end sandbox simulation (loopback fixtures + ingest)
make check            # ingest lint + unit tests + smoke
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
