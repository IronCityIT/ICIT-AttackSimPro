# AttackSim Pro — Developer Handoff

**Product:** Iron City AttackSim Pro (ASP) · **Surface:** asp.ironcityit.com
**Repo:** `IronCityIT/ICIT-AttackSimPro` · **Tier:** REVIEW ONLY (branch + PR only —
never auto-merge, auto-deploy, or live-dispatch; a human reviews and merges).
**This doc's provenance:** written 2026-09-07 from a full read of the repository working
tree and git history. Every claim is tagged **[VERIFIED]** (proven from repo code/tests
this session), **[TARGET]** (intended future state, not yet built), or
**[UNKNOWN / NOT VERIFIED]** (not provable from the repo — do not assume). Secrets are
named, never valued.

> **Architecture direction (2026-09-07):** Firebase / Firestore / Firebase Hosting / GCP
> product storage is **RETIRED** from the ICIT target architecture. GitHub Actions
> remains the execution/orchestration layer. Persistent relational state moves to a
> **self-hosted MariaDB on NAS-backed infrastructure**; artifact/object files move to
> **NAS-backed volumes**. Tenant isolation, RBAC, auditability, secrets hygiene,
> fail-closed behavior, backups/DR and evidence are preserved across the move. This doc
> is the canonical migration reference.

---

## 1. Purpose

AttackSim Pro is a **Purple-Team control-validation product**, not an exploit framework.
It runs authorized, non-destructive simulations and ingests the results of authorized
adversary-emulation engagements, normalizes every result into one Iron City findings
schema mapped to MITRE ATT&CK, enriches it through the shared AI consensus engine, and
presents a white-labeled, multi-tenant dashboard (grades + NIST/CIS/PCI/OWASP/SOC2
mapping). Underlying tool names are never surfaced on any client-facing surface. **[VERIFIED]**

Safety boundary: the engine validates controls and ingests reports; it never performs
uncontrolled real-world attack execution. Offensive workflows (`metasploit.yml`) and
active scan workflows are pre-existing, gated, and out of scope for autonomous change
(REVIEW-ONLY + offensive). **[VERIFIED]**

---

## 2. Current verified implementation

### 2.1 Component map **[VERIFIED]**

| Layer | Where | State |
|---|---|---|
| Simulation engine | `simcore/` (Python 3.12, stdlib + PyYAML only) | Modular `SimulationScenario` framework, 9 ATT&CK-mapped scenarios, scope gate, evidence bundles, reporting, RBAC, hash-chained audit, scheduler |
| Report adapters | `simcore/adapters/` | `ReportAdapter` framework + CALDERA / Stratus / MAAD / PurpleSharp ingest (each in a separate open PR — see §12) |
| Ingest handler | `functions/handler.js` | **Storage-agnostic** pure handler; all validation + write logic; depends only on an injected `db` port + logger |
| Ingest prod shell | `functions/index.js` | Wires Firebase Cloud Functions + Firestore Admin SDK into the handler **(RETIRED target — see §7)** |
| Local/test store | `functions/testkit/inmemory-firestore.js`, `functions/local-server.js` | In-memory `db` double + zero-dep HTTP server running the exact prod handler |
| Dashboard | `public/index.html` | Static SPA; reads `clients/{cid}/scans` via the **Firebase Web SDK (compat)** **(RETIRED target — see §7)** |
| Multi-tenant rules | `firestore.rules` | Read isolation by `client_id` claim **(RETIRED target — see §7)** |
| Orchestration | `.github/workflows/simulation.yml` | Consensus-wired run→analyze→store pipeline; store sink is URL-abstracted |
| Legacy scan workflows | `.github/workflows/{nuclei,tls-headers,zap-*,metasploit}.yml` | Pre-existing dispatch-only scanners; post to the store endpoint |
| Deploy (Firebase) | `.github/workflows/deploy-functions.yml` | Cloud Functions + rules deploy **(RETIRED target — see §7)** |

### 2.2 Ingest contract (store-of-record) **[VERIFIED]**

Every producer POSTs, and the dashboard reads back, this record. Handler:
`functions/handler.js`; Python client: `simcore/ingest_client.py`.

```
POST <store endpoint>            headers: Content-Type: application/json
                                          X-Ingest-Token: <token>   (when the gate is on)
body: {
  client_id | client_name,   scan_id,   scan_type,   target,   status,
  summary{critical_count,high_count,medium_count,low_count,info_count,...},
  findings[], consensus, error
}
```

Validation the handler enforces **[VERIFIED]** by 25 `node:test` cases + a 9-case curl
smoke: `client_id`/`client_name` required; `scan_id` required and `^[A-Za-z0-9._:-]{1,200}$`;
`status ∈ {queued,running,completed,failed}`; body ≤ 1 MiB; findings ≤ 5000; **status is
monotonic** (a `failed` report never downgrades a `completed` scan); `created_at` set once;
optional shared-secret gate via `INGEST_TOKEN` returns 401 on mismatch; a rejected write
is a real error, never a swallowed warning.

### 2.3 Data model — current (document) **[VERIFIED]**

Partition: `clients/{client_id}/scans/{scan_id}` → one document with the fields above.
`client_id` is a slug (`toClientId`: lowercase, non-alphanumeric→`-`, trimmed). Tenant
isolation is by partition + `firestore.rules` (read allowed only when the caller's
`client_id` auth claim equals the path's `clientId`; all client writes denied — writes
come only from the trusted server). **[VERIFIED]** (rules file is committed; live
enforcement is **[UNKNOWN]** — see §11.)

### 2.4 Verification status **[VERIFIED]**

- Engine: 89 checks on `fullfeature`; 126 with the four adapter PRs. `make gate` green
  (lint + 25 ingest + 9 smoke + engine + 16 E2E).
- Live ingest E2E (local server, in-memory store): findings stored at
  `clients/acme-corp/scans/...`; token gate returns 401 on unauthenticated POST.
- Reproduce: `pip install pyyaml && make gate`.

---

## 3. Target architecture

```
GitHub Actions (execution/orchestration — UNCHANGED)
  simulation.yml: self-validation → simulate (scope-gated) → AI consensus → store
    → POST storeScanResults contract (§2.2) to  ┐
                                                 │  self-hosted, on ICIT NAS infra
  ┌──────────────────────────────────────────────┘
  ▼
Ingest API  (self-hosted Node service, same handler.js, MariaDB-backed db port)  [TARGET]
  → MariaDB (relational: clients, scans, findings, audit, rbac)  on NAS-backed volume  [TARGET]
  → evidence bundles (object/artifact files)                     on NAS-backed volume  [TARGET]
Read API    (self-hosted; tenant-scoped, RBAC-gated reads)                            [TARGET]
  ▲
Dashboard   (self-hosted static SPA; reads the Read API, not Firestore Web SDK)       [TARGET]
  ▲  Auth0 SSO (Organizations = tenants); token carries client_id + role              [TARGET]
```

Design invariant preserved from today: **handler.js already depends only on an injected
`db` port** (`collection(id).doc(id).collection(id).doc(id)` → `{get(), set(data,{merge})}`
+ `serverTimestamp()`). Swapping Firestore for MariaDB is therefore an adapter change, not
a handler rewrite. **[VERIFIED — the seam exists in code]**

---

## 4. Target data model (MariaDB) **[TARGET]**

Relational schema for `clients/{client_id}/scans/{scan_id}` + findings + audit + RBAC.
DDL ships in this migration as `deploy/mariadb/schema.sql` (see §12). Shape:

- `clients(client_id PK, client_name, created_at)`
- `scans(client_id FK, scan_id, scan_type, target, status, summary_json, consensus_json,
   error_json, created_at, updated_at, PRIMARY KEY(client_id, scan_id))` — the composite
   key gives the same one-document-per-(client,scan) semantics and preserves monotonic
   status server-side.
- `findings(id PK, client_id, scan_id, severity, scenario, title, detail, attack_json,
   evidence_json, remediation_key, FOREIGN KEY(client_id,scan_id)→scans ON DELETE CASCADE)`
- `audit_log(id PK, ts, actor, role, action, client_id, scan_id, detail_json,
   prev_hash, hash)` — mirrors `simcore/audit.py`'s hash chain for tamper evidence.
- `rbac(subject, client_id, role)` — role ∈ {viewer, operator, admin}; a viewer reads only
   their tenant, operator can trigger/ingest, admin manages.

Tenant isolation is enforced in **every** query by a mandatory `client_id` predicate in the
Read API (fail-closed: no `client_id` ⇒ no rows), not by trusting the caller. Findings JSON
sub-objects (`attack`, `evidence`, `summary`, `consensus`) stay as JSON columns so the
existing findings schema is preserved verbatim. **[TARGET]**

Artifact files (evidence bundles: `run.json`, `findings.json`, `report.md/html`,
`manifest.json`, `audit.log`) are **not** put in MariaDB; they live on a NAS-backed volume
under `${ASP_EVIDENCE_ROOT}/clients/{client_id}/scans/{scan_id}/`, referenced by path from
the `scans` row. **[TARGET]**

---

## 5. Execution flow **[VERIFIED for today; store target self-hosted]**

1. `simulation.yml` dispatch → `self_validation` job (engine tests + loopback E2E; gate).
2. `simulate` job: `python -m simcore run` with the scope gate (loopback/private always
   allowed; external requires `--allow-external` **and** a matching `authorizations/*.yaml`
   record). Emits `findings.json` + evidence bundle (uploaded as an Actions artifact,
   retention 30d). **[VERIFIED]**
3. `ai_consensus` job: reusable `IronCityIT/consensus-engine/.github/workflows/analyze.yml@main`
   (`secrets: inherit`). **[VERIFIED wiring; live run UNKNOWN — see §11]**
4. `store` job: builds the §2.2 payload and `POST`s to `STORE_SCAN_RESULTS_URL` with
   `INGEST_TOKEN`; a non-2xx fails the run. **[VERIFIED]** — this URL becomes the
   self-hosted Ingest API; the workflow needs **no change** beyond the secret's value.

---

## 6. Configuration, access, RBAC, security boundaries

- **Config knobs [VERIFIED]:** `STORE_SCAN_RESULTS_URL`, `INGEST_TOKEN`, `PORT`;
  engine flags `--allow-external`, `--scope-dir`, `--role`, `--audit-log`.
- **RBAC [VERIFIED in engine]:** `simcore/rbac.py` (viewer/operator/admin) gates run/ingest
  actions; `simcore/audit.py` writes a hash-chained, tamper-evident log. **[TARGET]**: carry
  the same roles into the Read API + `rbac` table so dashboard reads are RBAC-gated.
- **Security boundaries [VERIFIED]:** scope gate fail-closes on external targets; ingest
  fail-closes on bad token / oversized / malformed payloads; reports HTML-escape hostile
  finding strings; no tool names on client surfaces (white-label tests).
- **Fail-closed [TARGET]:** Read API returns empty (never all-tenant) when `client_id` is
  absent or the token lacks a tenant claim.

---

## 7. Firebase/Firestore inventory — classify / migrate / remove

Every reference found in the tree, with disposition. **[VERIFIED as present]**; disposition
is **[TARGET]**.

| Ref | File(s) | Disposition |
|---|---|---|
| Firestore Admin write (`getFirestore`, `FieldValue`) | `functions/index.js` | **Replace** the prod shell's `db` with the MariaDB store adapter; keep `handler.js` as-is |
| Firestore Web SDK read + hardcoded web `apiKey` | `public/index.html:8-9,269,410,447` | **Replace** with a fetch to the self-hosted Read API; remove the Web SDK + apiKey |
| `firestore.rules` | `firestore.rules`, `firebase.json` | **Replace** tenant read isolation with server-side `client_id` predicates + Auth0 token claim in the Read API |
| Firebase Hosting + headers/CSP | `firebase.json` | **Replace** with self-hosted static serving on NAS; re-home the security headers/CSP to that server (drop `*.googleapis.com`/`securetoken` from `connect-src`) |
| Firebase deploy workflow | `.github/workflows/deploy-functions.yml` | **Replace** with a NAS deploy workflow (build image → push to ICIT registry → NAS pulls); do **not** deploy in-session |
| `FIREBASE_SERVICE_ACCOUNT`, `FIREBASE_FUNCTION_URL` (by name) | deploy-functions.yml, metasploit.yml | **Retire**; converge every producer on `STORE_SCAN_RESULTS_URL` |
| Legacy Cloud Run store URL `storescanresults-…run.app` (default fallback) | nuclei/tls-headers/zap-*.yml | **Remove the hardcoded fallback**; require `STORE_SCAN_RESULTS_URL` |
| `firebase-admin`, `firebase-functions` deps | `functions/package.json` | **Remove** once `index.js` no longer imports them; add `mysql2` |
| Docs naming Firebase/Firestore | README/STATUS/PRODUCTIZE_NOTES/docs | **Update** to the NAS/MariaDB target (this doc is the anchor) |

No production destructive migration is performed here; the current Firestore path stays
functional until Bill cuts over. **[VERIFIED — additive only]**

---

## 8. Secrets — by NAME ONLY

**Keep:** `STORE_SCAN_RESULTS_URL`, `INGEST_TOKEN`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`,
`GEMINI_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY` (consensus engine, via
`secrets: inherit`). **[VERIFIED names]**
**Add [TARGET]:** `ASP_MARIADB_URL` (or `MARIADB_HOST`/`MARIADB_PORT`/`MARIADB_USER`/
`MARIADB_PASSWORD`/`MARIADB_DATABASE`), `ASP_EVIDENCE_ROOT` (NAS path), Auth0 dashboard
config (`AUTH0_DOMAIN`, `AUTH0_CLIENT_ID` — public; any client secret server-side only).
**Retire [TARGET]:** `FIREBASE_SERVICE_ACCOUNT`, `FIREBASE_FUNCTION_URL`.
No secret value is ever committed. **[VERIFIED policy]**

---

## 9. Network / deployment **[TARGET]**

- Ingest API + Read API + dashboard run as containers on ICIT NAS-backed infra (QNAP /
  Container Station or equivalent — exact host **[UNKNOWN]**), behind the existing reverse
  proxy terminating TLS for asp.ironcityit.com.
- MariaDB runs as a container with its datadir on a NAS-backed volume; evidence files on a
  separate NAS-backed volume. Least-privilege DB user scoped to the ASP schema.
- GitHub Actions reaches the Ingest API over the internet at `STORE_SCAN_RESULTS_URL`
  (TLS + `INGEST_TOKEN`), OR via a self-hosted runner on the NAS network (choice
  **[UNKNOWN]** — Bill decides).

---

## 10. Tests / gates **[VERIFIED]**

- `make gate` = lint + `node --test` (25) + curl smoke (9) + engine unittest + E2E (16).
- Adapters add 19 (MAAD) + 18 (PurpleSharp) engine checks (in their PRs).
- **[TARGET]** MariaDB store: a fake-pool unit test drives the exact `handler.js` through
  the MariaDB `db` adapter (get/set/merge/monotonic), plus an env-gated integration test
  (`ASP_MARIADB_URL`) that runs against a real MariaDB when present and SKIPs clearly
  otherwise. No live DB is required for the default gate.

---

## 11. Known defects / blockers **[VERIFIED as stated in repo]**

- Consensus-engine live call, Jenkins run, Auth0→token, live authorized scan: **BLOCKED**
  on secrets/ROE (STATUS.md). **[VERIFIED as blocked]**
- Live Firestore rule enforcement, live legacy Cloud Run store URL reachability, live
  Firebase Hosting state: **[UNKNOWN / NOT VERIFIED]** — not provable from the repo.
- Pre-existing offensive-workflow injection surface + a TLS string-compare bug are flagged
  in `PRODUCTIZE_NOTES.md §2E/§2F`, out of scope (REVIEW-ONLY, offensive). **[VERIFIED flag]**

---

## 12. Enhancements / backlog & this migration's scope

**This migration PR (branch `productize/asp-nas-migration`) delivers [TARGET→VERIFIED as it lands]:**
1. This handoff doc.
2. `deploy/mariadb/schema.sql` — the relational schema (§4).
3. `functions/store/mariadb-store.js` — a MariaDB `db` adapter satisfying the port
   `handler.js` requires (additive; Firestore shell untouched).
4. `functions/store/README.md` + `deploy/mariadb/docker-compose.yml` — NAS deployment,
   **described not applied**.
5. Tests: fake-pool unit test + env-gated MariaDB integration test.

**Backlog (subsequent PRs):** self-hosted Ingest API prod shell using the adapter; Read
API + dashboard cutover off the Firestore Web SDK; Auth0 Organizations → tenant/role token;
NAS deploy workflow replacing `deploy-functions.yml`; remove `firebase-*` deps + hardcoded
store fallbacks; converge every producer on `STORE_SCAN_RESULTS_URL`; adapter PRs (#6–#9)
merge in order behind #5.

---

## 13. Operational runbooks / rollback / DR **[TARGET]**

- **Backups:** nightly `mysqldump` (or MariaDB `mariabackup`) of the ASP schema to a
  NAS-backed volume + off-NAS copy; evidence-file volume included in the NAS backup job.
  Restore = load the dump into a fresh MariaDB container, remount the evidence volume.
- **Rollback:** the migration is additive and config-selected — until the Ingest API's prod
  shell is pointed at the MariaDB adapter, the Firestore path remains authoritative;
  reverting is a config change, not a data migration. Cutover data backfill (Firestore →
  MariaDB) is a **separate, explicitly-approved** step, never run autonomously.
- **DR:** MariaDB datadir + evidence volume are the only stateful assets; both are
  NAS-backed and in the backup set. Recovery target = restore both volumes + redeploy the
  stateless containers from the ICIT registry.

---

## 14. Provenance / evidence

- Source of every §2 claim: repository working tree at branch `productize/asp-nas-migration`
  (based on `productize/attacksimpro-fullfeature`, PR #5) + git history through commit
  `1658bfa`.
- Test evidence: `make gate` output; `docs/evidence/*.log`; §2.4.
- Anything not provable from the repo is tagged **[UNKNOWN / NOT VERIFIED]** above and must
  be confirmed with Bill before being relied on. Nothing here is invented.
