# AttackSimPro — Full-Feature Build STATUS

**Run:** 2026-09-04 (America/New_York) · **Branch:** `productize/attacksimpro-fullfeature`
**Tier:** REVIEW ONLY — branch + PR only, no merge/deploy/live dispatch.
**Scope:** authorized, non-destructive Purple-Team validation only. Simulations ran
against **local loopback fixtures only**. No exploitation, credential access,
persistence, C2, or destructive behavior was added; the offensive `metasploit.yml`
workflow was **not** modified.
**Acceptance criteria + gap matrix:** `docs/ACCEPTANCE_CRITERIA.md`.
**Evidence:** `docs/evidence/fullfeature-run-2026-09-04.log`.

---

## What this build delivers

AttackSimPro moved from "a hardened ingest + one passive header script" to a **modular
simulation product**: a scope-gated engine, a scenario library, scheduling, evidence
bundles, reporting, RBAC/audit, a consensus-wired workflow, a Jenkins pipeline, and a
four-layer test suite. Every capability preserves the safety boundary in the README:
**no uncontrolled real-world attack execution.**

| AC | Capability | Where | Status |
|---|---|---|---|
| AC-1 | Modular safe simulation engine | `simcore/` (base, registry, runner, net) | ✅ built + tested |
| AC-2 | Scenario library (9, ATT&CK-mapped) | `simcore/scenarios/` | ✅ built + tested |
| AC-3 | Authorization / scope controls | `simcore/scope.py`, `authorizations/` | ✅ built + tested |
| AC-4 | Scheduling | `simcore/scheduler.py`, `simulation.yml` schedule, `Jenkinsfile` | ✅ built + tested |
| AC-5 | Results / evidence bundles | `simcore/evidence.py` (SHA-256 manifest) | ✅ built + tested |
| AC-6 | Reporting (Markdown + HTML) | `simcore/reporting.py` | ✅ built + tested |
| AC-7 | Remediation guidance | `simcore/remediation.py`, `public/remediation.json` | ✅ built + tested |
| AC-8 | RBAC + tamper-evident audit | `simcore/rbac.py`, `simcore/audit.py` | ✅ built + tested |
| AC-9 | Resilient API / UI | `functions/` (prior) + dashboard scenario library | ✅ built + tested |
| AC-10 | Consensus-engine wiring | `.github/workflows/simulation.yml` | ✅ built · live run BLOCKED |
| AC-11 | Unit/integration/E2E/security tests | `simcore/tests/`, `scripts/e2e/`, `functions/test/` | ✅ 115 checks green |
| AC-12 | Jenkins pipeline | `Jenkinsfile` | ✅ authored · Jenkins run BLOCKED |
| AC-13 | STATUS + evidence | this file, `docs/evidence/` | ✅ |

---

## PROVEN — verified locally this run

| Area | What was verified | Result |
|---|---|---|
| **Engine unit** | Findings validation, remediation catalog, RBAC matrix, ingest payload, registry select/catalog | ✅ |
| **Scenarios** | Each of 9 scenarios against in-memory vulnerable/hardened contexts (headers, cookie, TLS expiry/version, sensitive paths, ports, methods, CORS, listing, disclosure) | ✅ |
| **Scope gate (security)** | Loopback/private always allowed; external denied without opt-in; denied even with opt-in absent a record; host/CIDR/window record matching; out-of-scope + out-of-window denied | ✅ |
| **Evidence integrity (security)** | Manifest verify; tamper (content change, added file) detected; deterministic bundle digest | ✅ |
| **Audit chain (security)** | Append + hash-chain link; tamper at any index breaks verification at that index | ✅ |
| **Report escaping (security)** | Hostile finding/target strings HTML-escaped; no tool names leak (white-label) | ✅ |
| **Scheduler** | Cron parse (`*`, `*/n`, `a-b`, lists), next-run (hourly/daily/DOW), plan + disabled entries, bad-field rejection | ✅ |
| **Runner integration** | Multi-target run → findings + evidence bundle + audit; external refusal audited; viewer role denied; partial authorization | ✅ |
| **Ingest** | 25 node:test cases + 9-case curl smoke (validation, caps, monotonic status, token gate, tenant partition) | ✅ |
| **End-to-end (real sockets)** | `simcore run` → evidence bundle + report → POST to live ingest; stored at `clients/acme-corp/scans/…`; hardened fixture near-clean; bundle + audit verified; external refused; report unescaped-payload check | ✅ 16/16 |
| **Dashboard** | Scenario library renders from `public/catalog.json` (same registry the CLI uses); output-encoded | ✅ (browser confirmation BLOCKED) |
| **Default posture** | `authorizations/` loads **0** external records — ships sandbox-only | ✅ |

**Automated totals: 65 engine + 25 ingest + 9 smoke + 16 E2E = 115 checks, 0 failures.**

---

## BLOCKED — cannot be proven in this environment (needs live integrations/secrets)

| Integration | Why blocked | What would prove it |
|---|---|---|
| **Consensus-engine live call** | `simulation.yml` calls `IronCityIT/consensus-engine/analyze.yml@main`; needs a GitHub Actions run + (optional) provider keys | `workflow_dispatch` of `simulation.yml` against an authorized target |
| **Jenkins run** | No Jenkins controller in-session | Run `Jenkinsfile` on a Jenkins agent with python3 + node 20 |
| **Firestore rules enforcement** | No emulator (needs Java) / live project | `firebase emulators:exec` with the rules test SDK |
| **Auth0 → Firebase custom token** | Tenant secrets not in-session | End-to-end login → custom token → authorized read |
| **CSP/HSTS + dashboard in a browser** | No Firebase Hosting emulator / browser | `firebase emulators:start hosting` + browser console |
| **Live authorized scan** | REVIEW ONLY + requires a signed ROE and authorized target | `workflow_dispatch` with `--allow-external` and a committed authorization record |

---

## DEFECTS found + remediation (this build)

| # | Severity | Defect | Status |
|---|---|---|---|
| E1 | Medium (test fidelity) | Hardened fixture served 200 for every path, so path-exposure scenarios flagged it | **Fixed** — hardened fixture now 404s non-root paths |
| E2 | Low (safety UX) | A run where every target was scope-refused exited 0 (looked like a clean empty success) | **Fixed** — CLI exits 4 when all targets refused |
| — | — | Pre-existing offensive-workflow injection surface + TLS string-compare bug | **Open — flagged**, `PRODUCTIZE_NOTES.md §2E/§2F` (out of scope: REVIEW ONLY, offensive logic) |

---

## How to reproduce

```bash
pip install pyyaml           # only external dep (YAML auth/schedule files)
make gate                    # lint + ingest tests + smoke + engine tests + E2E
python3 -m simcore list      # the scenario library
python3 -m simcore run --targets http://127.0.0.1:9101 --group standard \
  --client "Demo" --scan-id d1 --out evidence/d1 --audit-log evidence/audit.log
python3 -m simcore verify --bundle evidence/d1
```
