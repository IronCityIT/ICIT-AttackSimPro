# AttackSimPro — Acceptance Criteria & Gap Matrix

**Date:** 2026-09-04 · **Branch:** `productize/attacksimpro-fullfeature`
**Tier:** REVIEW ONLY (`ICIT-AttackSimPro` / asp.ironcityit.com) — branch + PR only.
No merge, no deploy, no live/offensive dispatch. See `/root/.claude/CLAUDE.md`.

This document defines what "a robust full-feature product, not a demo" means for
AttackSimPro, and tracks each capability from gap → built → verified. It is the
contract the rest of this branch is measured against.

## Product thesis (from README + DISCLAIMER, non-negotiable)

AttackSimPro is a **controlled, authorized Purple-Team validation** product. It runs
**non-destructive, audit-defensible simulations** to validate security controls and
produce repeatable evidence. It is **not** a red-team/exploit platform. Every
capability added here preserves that boundary:

- **No uncontrolled real-world attack execution.** Simulations run only against
  authorized, in-scope targets, and by default only against sandboxed loopback /
  RFC-1918 fixtures. Reaching a public target requires an explicit, recorded
  authorization (Rules of Engagement) AND an explicit `--allow-external` opt-in.
- **No exploitation, credential theft, persistence, C2, or destructive actions** are
  added by this work. The pre-existing offensive `metasploit.yml` workflow is **not
  modified** and remains flagged for Bill (`PRODUCTIZE_NOTES.md §2`).

## Acceptance criteria (definition of "full-feature")

| # | Capability | Acceptance criterion |
|---|---|---|
| AC-1 | **Safe simulation engine** | A modular engine runs discrete, sandboxed simulation scenarios; each is one module; scenarios run individually, by group, or all. No monolith. One registry drives CLI + UI. |
| AC-2 | **Scenario library** | ≥ 8 non-destructive scenarios, each MITRE ATT&CK-mapped, each producing normalized findings + evidence. All safe by construction. |
| AC-3 | **Authorization / scope controls** | Every run is gated by a scope policy: target must match an authorization record (ROE id, allowed CIDRs/hosts, window). Non-loopback is refused unless authorized + `--allow-external`. Refusals are hard failures, logged. |
| AC-4 | **Scheduling** | Scenarios can be scheduled (cron expressions); a scheduler computes next-run and emits a plan. GitHub Actions + Jenkins scheduled triggers wire to it. Scheduling never bypasses scope/authorization. |
| AC-5 | **Results / evidence** | Each run emits a signed (hashed) evidence bundle: manifest, per-scenario findings, raw evidence, run metadata, integrity digest. Reproducible + verifiable. |
| AC-6 | **Reporting** | Human report (Markdown + HTML), white-labeled (no tool names), with executive summary, findings by severity, compliance mapping, and remediation. |
| AC-7 | **Remediation guidance** | Every finding type carries actionable remediation steps + compliance framework references. Shared source of truth for report + dashboard. |
| AC-8 | **RBAC / audit** | Roles (viewer / operator / admin) gate actions. Every privileged action (run, schedule, ingest, export) writes an append-only, tamper-evident audit record. |
| AC-9 | **Resilient APIs / UI** | Ingest API validates, rate-guards, caps, and fails loud; is idempotent and observable. Dashboard is defensive (output-encoded), reads real data, degrades honestly (LIVE/DEMO), and shows scenario library + evidence + audit. |
| AC-10 | **Consensus wiring** | A safe simulation workflow routes findings through `IronCityIT/consensus-engine` (`analyze.yml`) via `workflow_call` and stores the result — no duplicated LLM logic. |
| AC-11 | **Tests** | Unit + integration + E2E + security suites, all green locally with no external deps. Coverage spans engine, scope, evidence, reporting, RBAC/audit, ingest, dashboard. |
| AC-12 | **CI/CD** | A **Jenkins pipeline** (`Jenkinsfile`) runs the full gate (lint, unit, integration, E2E, security, build). GitHub Actions parity retained. |
| AC-13 | **Status / evidence** | `STATUS.md` reports proven-vs-blocked honestly with reproduction; evidence log committed. |

## Gap matrix — before this branch → target

| Area | Before (`runnable` baseline) | Gap | Target (this branch) | AC |
|---|---|---|---|---|
| Simulation | 1 passive header script (`scripts/attack-sim/`) | No modular engine, 1 scenario, no scope object, no evidence bundle | `simcore/` modular engine + registry + runner | AC-1 |
| Scenarios | header check only | No library, no ATT&CK mapping | ≥ 8 scenarios in `simcore/scenarios/`, ATT&CK-tagged | AC-2 |
| Authorization | loopback check in one script | No reusable scope/ROE model, no authorization records | `simcore/scope.py` + `authorizations/*.yaml` + ROE gate | AC-3 |
| Scheduling | `productize/attacksimpro-schedule` adds a cron trigger to one workflow | No scenario-level scheduler, no plan | `simcore/scheduler.py` + scheduled workflow/Jenkins | AC-4 |
| Evidence | scan JSON only | No bundle, no manifest, no integrity digest | `simcore/evidence.py` bundle + SHA-256 manifest | AC-5 |
| Reporting | dashboard only | No portable report artifact | `simcore/reporting.py` → Markdown + HTML | AC-6 |
| Remediation | hard-coded in dashboard JS | Not shared with engine/report | `simcore/remediation.py` shared catalog | AC-7 |
| RBAC/Audit | ingest token only | No roles, no audit trail | `simcore/rbac.py` + `simcore/audit.py`, ingest audit | AC-8 |
| API/UI | hardened ingest; dashboard reads correct partition | No audit, no scenario catalog in UI, no evidence view | ingest audit + rate-guard; dashboard scenario/evidence/audit panels | AC-9 |
| Consensus | no workflow calls it (flagged) | AI analysis absent | `simulation.yml` calls `analyze.yml` via `workflow_call` | AC-10 |
| Tests | 25 node:test + 9 smoke (ingest/dashboard) | No engine tests, no python tests, no security suite label | `simcore/tests/` unit+integration+e2e+security | AC-11 |
| CI/CD | GitHub Actions only | No Jenkins pipeline (explicitly requested) | `Jenkinsfile` full gate | AC-12 |
| Status | STATUS.md (runnable pass) | Needs full-feature report | updated `STATUS.md` + evidence | AC-13 |

## Out of scope / explicitly refused (safety boundary)

- Modifying offensive/exploit workflow logic (`metasploit.yml`, active ZAP/Nuclei
  exploit paths). Flagged, not changed (`PRODUCTIZE_NOTES.md §2E/§2F`).
- Any capability that reaches a non-loopback target without a recorded authorization.
- Any exploitation, credential access, persistence, C2, or destructive behavior.
- Merge / deploy / live dispatch (REVIEW ONLY tier).
