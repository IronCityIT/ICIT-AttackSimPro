# AttackSimPro — SDLC Status

**Date:** 2026-09-04
**Branch:** `productize/attacksimpro-runnable`
**Tier:** REVIEW ONLY (`ICIT-AttackSimPro` / asp.ironcityit.com) — branch + PR only.
No merge, no deploy, no live scan dispatch performed. See `/root/.claude/CLAUDE.md`.
**Scope guardrail honored:** defensive/authorized-simulation only. No stealth,
persistence, credential theft, destructive payloads, or new exploitation was added;
the offensive `metasploit.yml` workflow was **not** modified.

---

## 1. What this change makes genuinely runnable

The product had a working ingest **contract on paper** but three pieces did not line
up, so the client-facing dashboard could never display a real scan:

| Layer | Was | Now |
|---|---|---|
| Ingest function | one 130-line file, untestable, no size/auth/status guards | pure `handler.js` + thin `index.js`; validated, hardened, unit- and smoke-tested |
| Dashboard read path | `collection('scans')` ordered by `timestamp`, field `target_url` | `clients/{client}/scans` ordered by `created_at`, field `target` — matches what the function writes |
| Local run / verify | none | `npm test`, `scripts/smoke.sh`, `docker compose up`, `Makefile` |

### The core functional defect (fixed)
The Cloud Function writes `clients/{client_id}/scans/{scan_id}` with fields
`created_at` / `target`. The dashboard read the **legacy flat** `scans` collection
ordered by a `timestamp` field that no longer exists, and read `target_url`. Result:
every read returned empty (or was denied by `firestore.rules`) and the UI **always**
fell back to demo data — a client could never see their own results. The dashboard now
reads the correct partition, orders by the real field, resolves the target correctly,
and shows a **LIVE vs DEMO** banner so demo data is never mistaken for a real scan.

---

## 2. Changes on this branch

**Cloud Function (`functions/`)**
- `handler.js` — all ingest logic as a pure, dependency-injected factory (new).
- `index.js` — thin production shell wiring firebase-admin + logger into the handler.
- Hardening added: method allow-list, JSON-object body check, **1 MiB payload cap**
  (413), **status allow-list** (queued/running/completed/failed), `scan_id` format
  check, **≤5000 findings** cap (413), and an **optional** `X-Ingest-Token` shared-secret
  gate (off unless `INGEST_TOKEN` is set — existing callers unaffected).
- Observability: per-request `X-Request-Id`, structured logs, `/healthz` route,
  finding counts in the response.
- Preserved behavior: required `client_id`/`scan_id`, real target retained, and the
  **monotonic status** rule (a late `failed` never downgrades a `completed` scan).
- `testkit/` — in-memory Firestore double + req/res shims (test/local only, not deployed).
- `local-server.js` — zero-dependency HTTP server running the real handler.
- `test/handler.test.js` — 16 deterministic unit tests (`node:test`, no new deps).
- `Dockerfile` — reproducible local ingest container.

**Dashboard (`public/index.html`)**
- Reads the client partition; `?client=<client_id>` selects the tenant; demo fallback kept.
- LIVE/DEMO data-source banner + console diagnostics.

**Tooling / docs**
- `scripts/smoke.sh`, `docker-compose.yml`, `Makefile`, this file, README run section.

---

## 3. Evidence (commands run in this session)

```
$ cd functions && npm run lint
index.js / handler.js / local-server.js  -> node --check OK

$ node --test
# tests 16  # pass 16  # fail 0

$ bash scripts/smoke.sh
healthz 200 · GET/ 405 · missing client 400 · missing scan_id 400 ·
bad status 400 · valid scan 200 · late failure 200 (already_completed) ·
stored status=completed · stored target=https://acme.example
Results: 9 passed, 0 failed  (exit 0)

$ node --check <dashboard app script>   -> OK
$ python3 -m http.server (public/)      -> GET /index.html 200, fixes present
```

JSON/YAML gates: `functions/package.json` parses clean (`python3 -m json.tool`);
workflow YAML unchanged by this branch.

---

## 4. Blockers / not done (honest)

- **Auth0 → Firebase custom token is not wired.** `firestore.rules` require a
  `client_id` claim to read `clients/{cid}/scans`. The dashboard now issues the
  correct query, but a live read stays **permission-denied until** the Auth0 org
  login mints a Firebase custom token carrying `client_id`. Needs the Auth0 tenant
  app config/secrets (not available in this session). Until then the dashboard runs
  in demo mode against production. **Owner decision + secrets required.**
- **Docker stack not executed here** — no Docker/Java in this sandbox. The
  `Dockerfile`/`docker-compose.yml` are provided and the underlying commands were
  verified directly (node local-server + python http.server both serve). Run
  `docker compose up --build` in an environment with Docker to confirm the images.
- **`firebase deploy` not run** (REVIEW ONLY + no `FIREBASE_SERVICE_ACCOUNT`).
- **Workflows unchanged.** The architecture items previously flagged in
  `PRODUCTIZE_NOTES.md` (§2: consensus-engine wiring, two scans that never store,
  two store sinks, TLS cert-expiry bug, white-labeling tool names at the store
  boundary) remain open and are Bill's to sequence. This branch deliberately did
  not touch offensive/active-scan workflow logic.

---

## 5. How to run locally

```
make check          # lint + unit tests + smoke (no creds, no network)
make serve-ingest   # storeScanResults on :8088 (in-memory Firestore)
make serve-dashboard# dashboard on :8080  ->  open /index.html?client=<id>
docker compose up --build   # both, containerized
```
