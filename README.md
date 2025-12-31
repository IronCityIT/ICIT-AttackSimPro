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

``
