-- Iron City AttackSim Pro — relational store (self-hosted MariaDB on NAS-backed infra).
--
-- Target state replacing the retired Firestore document store. Preserves the exact
-- store-of-record contract (functions/handler.js): one record per (client_id, scan_id),
-- multi-tenant isolation by client_id, monotonic status, findings, consensus, audit.
--
-- Apply on a MariaDB (>=10.5, JSON support) database owned by a least-privilege ASP user:
--   mysql --host "$MARIADB_HOST" --user "$MARIADB_USER" -p "$MARIADB_DATABASE" < schema.sql
-- No credentials are embedded; connection is supplied by environment (see functions/store/README.md).

SET NAMES utf8mb4;

-- One row per tenant. client_id is the path-safe slug handler.js's toClientId() produces.
CREATE TABLE IF NOT EXISTS clients (
  client_id    VARCHAR(200) NOT NULL,
  client_name  VARCHAR(255) NULL,
  created_at   DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- One row per scan, keyed by (client_id, scan_id) — the same one-doc-per-scan semantics
-- as clients/{client_id}/scans/{scan_id}. JSON columns preserve the findings schema
-- verbatim. Status is kept monotonic in the application layer (a completed scan is never
-- downgraded to failed), matching handler.js.
CREATE TABLE IF NOT EXISTS scans (
  client_id      VARCHAR(200) NOT NULL,
  scan_id        VARCHAR(200) NOT NULL,
  client_name    VARCHAR(255) NULL,
  scan_type      VARCHAR(120) NOT NULL DEFAULT 'unknown',
  target         TEXT NULL,
  status         ENUM('queued','running','completed','failed') NOT NULL DEFAULT 'completed',
  summary_json   JSON NULL,
  consensus_json JSON NULL,
  error_json     JSON NULL,
  created_at     DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at     DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  evidence_path  VARCHAR(512) NULL,  -- NAS-backed evidence bundle dir, if any
  PRIMARY KEY (client_id, scan_id),
  CONSTRAINT fk_scans_client FOREIGN KEY (client_id)
    REFERENCES clients (client_id) ON DELETE CASCADE,
  INDEX idx_scans_client_updated (client_id, updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Normalized findings (also queryable relationally for the ATT&CK coverage view). The
-- full finding object is preserved as JSON so nothing from the source schema is lost.
CREATE TABLE IF NOT EXISTS findings (
  id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  client_id       VARCHAR(200) NOT NULL,
  scan_id         VARCHAR(200) NOT NULL,
  severity        ENUM('info','low','medium','high','critical') NOT NULL DEFAULT 'info',
  scenario        VARCHAR(120) NULL,
  title           VARCHAR(512) NULL,
  detail          TEXT NULL,
  attack_json     JSON NULL,       -- ATT&CK technique ids
  evidence_json   JSON NULL,
  remediation_key VARCHAR(120) NULL,
  PRIMARY KEY (id),
  CONSTRAINT fk_findings_scan FOREIGN KEY (client_id, scan_id)
    REFERENCES scans (client_id, scan_id) ON DELETE CASCADE,
  INDEX idx_findings_scan (client_id, scan_id),
  INDEX idx_findings_sev (client_id, severity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tamper-evident audit chain (mirrors simcore/audit.py). prev_hash/hash link each row.
CREATE TABLE IF NOT EXISTS audit_log (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  ts          DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  actor       VARCHAR(200) NULL,
  role        VARCHAR(40)  NULL,
  action      VARCHAR(120) NOT NULL,
  client_id   VARCHAR(200) NULL,
  scan_id     VARCHAR(200) NULL,
  detail_json JSON NULL,
  prev_hash   CHAR(64) NULL,
  hash        CHAR(64) NOT NULL,
  PRIMARY KEY (id),
  INDEX idx_audit_client (client_id, ts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- RBAC: subject (Auth0 sub / user id) -> role within a tenant. The Read API fail-closes:
-- no matching row = no access. role: viewer (read own tenant), operator (trigger/ingest),
-- admin (manage). Tenant isolation is enforced by a mandatory client_id predicate.
CREATE TABLE IF NOT EXISTS rbac (
  subject    VARCHAR(255) NOT NULL,
  client_id  VARCHAR(200) NOT NULL,
  role       ENUM('viewer','operator','admin') NOT NULL DEFAULT 'viewer',
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (subject, client_id),
  CONSTRAINT fk_rbac_client FOREIGN KEY (client_id)
    REFERENCES clients (client_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
