# AttackSimPro — Test Campaign STATUS

**Run:** 2026-09-04 (America/New_York) · **Branch:** `productize/attacksimpro-runnable`
**Tier:** REVIEW ONLY — branch + PR only, no merge/deploy/live dispatch.
**Scope:** defensive/authorized-simulation only. Simulations ran against **local
loopback fixtures only**; no third-party or production system was targeted, and no
stealth/persistence/credential-theft/destructive/exploitation behavior was added.
**Evidence:** `docs/evidence/test-run-2026-09-04.log` (full console capture).
Deeper build notes and architecture history: `docs/SDLC_STATUS.md`, `PRODUCTIZE_NOTES.md`.

---

## PROVEN — verified locally this run

| Area | What was verified | Result |
|---|---|---|
| **Build** | `npm install` in `functions/`; `firebase-admin@12.7.0` + `firebase-functions` require cleanly; `node --check` on all sources | ✅ |
| **Unit** | 16 `node:test` cases on the pure ingest handler (validation, size/status/findings caps, monotonic status, created_at, token gate, 500 path) | ✅ 16/16 |
| **Dashboard logic** | 5 cases running the REAL `public/index.html` app script in a VM: compliance mapping, remediation lookup, demo fallback, `?client=` parsing, and the corrected `target`-field live-read mapping | ✅ 5/5 |
| **Integration / E2E** | 4 cases booting `local-server.js` over a live TCP socket: `/healthz`, token gate 401, full store round-trip (+`X-Request-Id`), monotonic status over HTTP | ✅ 4/4 |
| **Runtime smoke** | `scripts/smoke.sh` drives the ingest with curl: healthz, method/validation rejections, store, late-failure handling, store-content assertions | ✅ 9/9 |
| **Safe attack simulation** | `scripts/attack-sim/`: passive header scan of a **vulnerable** (6 findings) and a **hardened** (0 findings) local fixture → findings → ingest → verified stored at `clients/{client}/scans/{id}` with the real target | ✅ |
| **Adversarial input (defensive)** | path-traversal `scan_id` (400), >1 MiB body (413), invalid status (400), hostile XSS string stored as inert data (200, not executed) | ✅ 4/4 |
| **Config hardening** | Added CSP + HSTS to `firebase.json` hosting headers; CSP source-list cross-checked against every origin the dashboard loads | ✅ (see blocked note for browser confirmation) |
| **Secret hygiene** | Repo scan: no hardcoded private keys/tokens; workflow secrets referenced by name only; Firebase web apiKey confirmed public-by-design | ✅ |

**Total automated: 25/25 node:test + 9/9 smoke + 10/10 simulation — 0 failures.**

---

## BLOCKED — cannot be proven in this environment (needs live integrations/secrets)

| Integration | Why blocked | What would prove it |
|---|---|---|
| **Firestore rules enforcement** | No Firebase/Firestore emulator (needs Java, absent) and no live project access | `firebase emulators:exec` with the rules test SDK asserting cross-tenant reads are denied |
| **Auth0 → Firebase custom token** | Auth0 tenant app config/secrets not available in-session; the dashboard's live read stays permission-denied until a `client_id` claim is minted | End-to-end login on `dev-ws5377dam2tnlv5g.us.auth0.com` → custom token → authorized Firestore read |
| **CSP/HSTS runtime effect** | `python -m http.server` does not apply `firebase.json` headers; no Firebase Hosting emulator / browser here | Serve via `firebase emulators:start hosting` (or deployed preview) and confirm headers + no CSP console violations |
| **Container images** | No Docker/Java in sandbox | `docker compose up --build` on a Docker host; the underlying node/python commands were verified directly |
| **Live scan workflows** | REVIEW ONLY + active/offensive scanners require an authorized target and secrets; not run | Authorized dry-run `workflow_dispatch` against an in-scope target once secrets exist |
| **Cloud Function deploy** | REVIEW ONLY; no `FIREBASE_SERVICE_ACCOUNT` | `deploy-functions.yml` with the service-account secret provisioned |

---

## DEFECTS found this run + remediation

| # | Severity | Defect | Status | Remediation |
|---|---|---|---|---|
| D1 | High (UX/data) | Dashboard read the wrong collection/fields (`scans`/`timestamp`/`target_url`) vs what the function writes (`clients/{id}/scans`/`created_at`/`target`) — clients could never see real data | **Fixed** (prior commit on this branch) | Now reads the correct partition; covered by the dashboard-logic live-read test |
| D2 | Medium | Dashboard hosting omitted Content-Security-Policy and HSTS — the product flags exactly these on clients | **Fixed** this run | CSP+HSTS added to `firebase.json`; runtime confirmation is BLOCKED (see table) |
| D3 | Low | Build fragility: overlapping `npm install` runs corrupted the `firebase-admin` tree (`ENOTEMPTY`, missing `utils/validator.js`) | **Fixed** this run | Clean reinstall; `package-lock.json` committed for reproducible installs; `.gitignore` added so `node_modules` is never committed |
| D4 | Low (residual) | CSP retains `'unsafe-inline'` for `script-src` because the dashboard uses inline `onclick=` handlers and an inline `<script>` | **Open** | Refactor the dashboard to remove inline handlers, then drop `'unsafe-inline'` — a larger, separate change |
| D5 | Info (pre-existing) | Active/offensive workflows still interpolate `${{ github.event.inputs.* }}` into `run:`/config bodies (injection surface); TLS cert-expiry string-vs-number comparison bug | **Open — flagged** | Tracked in `PRODUCTIZE_NOTES.md §2E/§2F`; out of scope for this defensive pass (REVIEW ONLY, offensive logic) |

No new defects were found in the ingest handler; its validation and monotonic-status
behavior held under every adversarial probe.

---

## How to reproduce

```bash
make install          # npm install (functions/)
make check            # lint + 25 node:test + 9-case smoke
bash scripts/attack-sim/run_simulation.sh   # safe local simulation + adversarial probes
```
