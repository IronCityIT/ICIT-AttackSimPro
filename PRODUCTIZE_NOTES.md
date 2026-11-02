# AttackSim Pro — Productization / Actions Audit Notes

# GitHub Actions Audit + Enhancement (2026-08-24)

Branch: `enhance/actions-ui-20260824`. **Tier: REVIEW ONLY** (per the ICIT
guardrails, `ICIT-AttackSimPro` / asp.ironcityit.com). Branch + PR only — **no merge,
no deploy, no live dispatch** was performed. This is also an *offensive* product
(the Metasploit workflow executes real exploits), which is a second, independent
reason not to auto-run it.

Changes were kept surgical: security fix, input typing, and store error-handling.
The deeper architectural gaps are **flagged for Bill**, not rewritten — several are
core-adjacent decisions that a REVIEW-ONLY tier explicitly reserves for a human.

---

## 1. Audit — 7 workflows

| Workflow | Trigger | Calls consensus-engine? | Store target |
|---|---|---|---|
| `metasploit.yml` | dispatch | **No** | `secrets.FIREBASE_FUNCTION_URL` |
| `nuclei.yml` | dispatch | **No** | hardcoded `storescanresults-wrl6y3keaa-ul.a.run.app` |
| `tls-headers.yml` | dispatch | **No** | hardcoded (same) |
| `zap-baseline.yml` | dispatch | **No** | hardcoded (same) |
| `zap-fullscan.yml` | dispatch | **No** | hardcoded (same) |
| `zap-api-scan.yml` | dispatch | **No** | **none — results never leave the runner** |
| `zap-auth-scan.yml` | dispatch | **No** | **none — results never leave the runner** |

All triggers are `workflow_dispatch` only (good — no accidental firing). The
Metasploit workflow has a genuinely careful multi-gate authorization design (ROE
confirmation, target validation, mode selection) that was left intact.

### Defects fixed in this PR

| # | Defect | Severity |
|---|---|---|
| 1 | `nuclei.yml`: `eval $NUCLEI_CMD` with `${{ inputs.target_url }}` / `severity` / `template_tags` interpolated in | **High — command injection** |
| 2 | Store POSTs masked a rejected write with `\|\| echo "Warning: Failed to post to dashboard"` (8 sites) and `\|\| echo "⚠️ Firebase post failed"` (1) | Store-of-record failures reported as green |
| 3 | Every dispatch input across 6 of 7 workflows was untyped | UI/CLI render free-text for fixed-choice fields |
| 4 | 5 of 7 workflows declared no `permissions:` | Ran with the default broad token |
| 5 | Store endpoint hardcoded, inconsistent (`run.app` URL vs `FIREBASE_FUNCTION_URL` secret) | Not configurable; two different sinks |

### Fixes

- **`eval` removed** (defect 1). Nuclei arguments are built as a bash array with values
  passed through `env:`; `severity`, `template_tags`, and `scan_id` are validated against
  strict allow-lists before use; `target_url` is validated with `grep -qE` (kept out of
  the shell parser). A hostile `target_url` is now one argument, never shell.
- **Store POSTs fail loudly** (defect 2). Each `|| echo "Warning…"` became
  `|| { echo "::error::…"; exit 1; }`. Each store step runs at most one of its two curls
  (if/else), so exiting non-zero on whichever ran correctly fails the step and turns the
  run red instead of green-with-a-warning.
- **All inputs typed** (defect 3) — `type: string` added to every previously-untyped
  input across all 6 workflows (existing `choice` inputs on Metasploit left as-is).
- **Least-privilege `permissions: contents: read`** added to the 5 workflows that had none
  (defect 4).
- **Store endpoint made configurable** (defect 5). The hardcoded URL became
  `${STORE_SCAN_RESULTS_URL:-<current-url>}`, and `STORE_SCAN_RESULTS_URL` is wired from
  the repo secret into each store step. Behaviour is unchanged when the secret is unset
  (falls back to the current URL); no endpoint was guessed and no new secret invented.

---

## 2. FLAGGED for Bill — NOT changed (REVIEW-ONLY / architecture decisions)

**A. No workflow calls `consensus-engine`.** None of the 7 route findings through the
shared AI engine. This is *not* the "duplicated AI logic" violation (there is no inline
LLM code here) — it is the opposite: the AI analysis step is simply absent. Per the
guardrails I flag rather than silently wire in a `workflow_call`, because adding the
engine to an offensive product touches the shared-core contract and is a REVIEW-ONLY
decision. Recommendation: add an `ai-consensus` job (as Threat Inspector / DNS Guard have)
that calls `IronCityIT/consensus-engine/.github/workflows/analyze.yml@main`.

**B. Two scans never store results at all.** `zap-api-scan.yml` and `zap-auth-scan.yml`
only upload artifacts — nothing reaches Firestore, so those scans are invisible to any
dashboard. They need a store step like the other five. Not added here because their
result-file shapes differ and wiring them blind (no dry-run possible, see §4) risks a
malformed payload; better done with a validating dry-run once secrets exist.

**C. Two store sinks.** Metasploit posts to `secrets.FIREBASE_FUNCTION_URL`; the others to
the `run.app` URL. They should converge on one `storeScanResults` endpoint. Left split
because collapsing them changes where live data lands — a deploy-topology decision.

**D. No `report-failure` path.** Unlike the repos I could fully own, I did not add a
failure-reporter job here. The store steps already run `if: always()` and now fail loudly,
but there is no `status:"failed"` record written when a scan job dies before reaching the
store step. Adding one depends on the store-endpoint convergence in (C), so it is deferred
to the same decision.

**E. Genuine latent bug — TLS cert-expiry comparison.** shellcheck SC2170 in
`tls-headers.yml` (~line 256): `-eq` / `-le` used on values that are strings, not numbers,
in the certificate-expiry logic. This is a real correctness bug in product logic, present
before this PR. Not fixed here (product logic, REVIEW-ONLY, out of the dispatch/error
scope) but should be corrected.

**F. Large residual injection surface.** Many steps still interpolate
`${{ github.event.inputs.* }}` directly into `run:` bodies (counts: nuclei was 35, now
reduced; zap-auth 43; tls 29; zap-fullscan 30; zap-api 26; zap-baseline 26; metasploit 8).
I fixed the one that reached `eval` (the exploitable path). The rest are lower-risk
(mostly `echo`/report interpolation, and inputs that Metasploit already validates) but
should be migrated to `env:` systematically. That is a large mechanical sweep across an
offensive engine and is better reviewed as its own change.

**G. White-label.** Tool names (Nuclei, ZAP, Metasploit) appear in `scan_type` values and
report text that reach the store payload (`"scan_type": "nuclei"`, `"metasploit_exploitation"`,
etc.). Internal code comments naming tools are fine, but these are stored on the record the
dashboard reads. Mapping them to Iron City categories at the store boundary is recommended;
not done here because it needs the store-layer convergence in (C).

---

## 3. Validation run

- `actionlint 1.7.7` workflow-structure lint on all 7 — **exit 0, clean**.
- PyYAML `safe_load` on all 7 — parse clean.
- `shellcheck 0.10.0` (via actionlint): the parse error I introduced in `nuclei.yml` was
  fixed; the 12 remaining warning/error findings are **all pre-existing**, in product
  logic not touched by this PR (Metasploit exploit steps, the TLS cert logic in §2E, ZAP
  invocations). Left as-is per REVIEW-ONLY discipline; the real one (§2E) is flagged.
- Confirmed: **no `eval` remains**; **no masked store warning remains**.

## 4. Dry-run — deliberately NOT performed

REVIEW-ONLY permits a dry-run `workflow_dispatch`, but:
- `metasploit.yml` executes **real exploits** against a real target — never run without a
  signed ROE and an authorized target; neither exists in this session.
- The ZAP/Nuclei workflows are **active scanners**; they need an authorized target.
- All would fail at any AI step anyway (no consensus-engine call; and the missing engine
  secrets that block the other products).

So no live dispatch was issued. Static validation only. Bill's review should decide the
architecture items in §2 before any live run.

## 5. UI-accessibility

`public/index.html` (a dashboard) exists in-repo. Gap (a) — typed `workflow_dispatch` — is
now satisfied for all 7. Gaps (b) trigger function and (c) dashboard→function wiring were
**not audited in depth** here because the store-layer and consensus decisions in §2 gate
them; they should be revisited once those land.

---

# fix/asp-consensus — real AI consensus on every finding (2026-11-02)

Branch off `main`. NAS/MariaDB branches (#10–#18) untouched.

## Contract wired to (read from `consensus-engine/.github/workflows/analyze.yml@main`)
- `workflow_call` inputs: `findings_json` (base64 JSON), `product`, `client_id`, `scan_id`,
  `api_url`, `post_to_api` (default false). Output: `consensus_b64`. Secrets, all optional:
  `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `GEMINI_API_KEY`, `IRONCITY_API_KEY`.
- The engine also uploads its result as artifact `consensus-result-<scan_id>`; the store job
  reads **that file**, not `consensus_b64` through env (DNS Guard died on "Argument list too long").
- Result shape: one `ConsensusResult` per input finding, same order, no id. Per finding:
  `consensus_severity`, `confidence_percent`, `exploitability`, `impact`, `aggregated_remediation[]`,
  `verification_steps[]`, `compliance_impact.{frameworks,control_domains,control_mappings,audit_risk}`,
  `successful_models`/`total_models`, and `model_responses[]` (names providers — dropped).
- The engine does **not** produce `code`, `priority` or `effort`. The dashboard renders those only
  if the stored data ever carries them; nothing is invented to fill the gap.

## What changed
| File | Change |
|---|---|
| `tools/asp_consensus.py` | `normalize` (web/tls/template reports → one finding shape + the engine subset, recorded by id) and `enrich` (positional pairing with a count check, allow-listed fields, vendor and tool names stripped, `consensus.status` = success / unavailable / not_required). Pattern copied from ICIT-DNSGuard `tools/enrich.py` + `dnsguard/consensus.py`. |
| 6 scan workflows | scan job → `Normalize findings` + artifact; new `ai-consensus` job (`uses: IronCityIT/consensus-engine/.github/workflows/analyze.yml@main`, `secrets: inherit`); new `store` job (`needs` both, `if: always() && scan succeeded`). Old raw-report POST removed (it stored scanner JSON verbatim, tool names included). zap-api-scan and zap-auth-scan never stored anything before; they do now. |
| Workflow names | `run-name` added; no client-facing workflow/job name says ZAP/Nuclei/Metasploit. File names unchanged, so dispatch callers are unaffected. |
| `public/index.html` | Per-finding AI remediation rendered from `ai_analysis`. `remediationDB` and `defaultRemediation` deleted; no analysis → "AI analysis unavailable for this finding" + the scanner's own solution. Static "10-model" banner with vendor names replaced by real counts (hidden when none). All stored text via `textContent` (closed a stored XSS through `innerHTML` and inline `onclick`). Fabricated demo findings replaced by an empty state. CSV export neutralises formula injection. |
| `functions/record.js` + test | Record building extracted and tested (`npm test`): per-finding analysis persists, `consensus.status` persists, vendor keys stripped server-side. |
| `.github/workflows/consensus-tests.yml` | PR gate: ruff format/lint, mypy strict, pytest, node test. |

## Blockers found (not fixable from this branch)
1. **GitHub Actions is disabled on this repo** (`actions/permissions.enabled=false`); dispatches
   queue forever with 0 jobs. Branch dispatch proof (step 6) cannot run until it is re-enabled.
2. **No `FIREBASE_SERVICE_ACCOUNT`** on the repo, no Firebase CLI / ADC / gcloud account on the
   devbox. Also: this repo is REVIEW-ONLY — merge and deploy are Bill's.
3. **The deployed `storeScanResults` is not this source.** Live docs in the flat `scans`
   collection have the old shape (`tool`, `source`, no `client_id`, no `consensus`). Until
   `functions/` is deployed, consensus data is not persisted per finding.
4. **The dashboard has no sign-in.** It reads the legacy flat `scans` collection, which is
   world-readable today (unauthenticated GET = 200). `main`'s function writes
   `clients/{client_id}/scans/{scan_id}` and `main`'s rules require an Auth0-derived `client_id`
   claim to read it. Showing newly stored scans on the live dashboard therefore needs the Auth0 →
   Firebase custom-token work (on the NAS/auth branch chain, excluded from this mission) or a
   decision to keep the legacy collection. Not decided here.
