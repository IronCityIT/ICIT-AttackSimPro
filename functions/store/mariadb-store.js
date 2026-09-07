/**
 * MariaDB-backed store adapter for storeScanResults.
 *
 * TARGET-ARCHITECTURE STORE (Firebase/Firestore is retired). This adapter exposes the
 * EXACT `db` port that functions/handler.js already depends on — so the pure handler is
 * reused unchanged, and only the storage behind it changes:
 *
 *   db.collection("clients").doc(cid).collection("scans").doc(sid) -> { get(), set(data,{merge}) }
 *   snapshot.exists, snapshot.get(field), snapshot.data()
 *   db.serverTimestamp()
 *
 * The handler only ever addresses clients/{client_id}/scans/{scan_id}; this adapter maps
 * that one path to the relational schema in deploy/mariadb/schema.sql. Any other path is
 * rejected loudly rather than guessed.
 *
 * Dependency injection: takes a mysql2/promise-style `pool` with
 * `pool.query(sql, params) -> [rows]`. index.js (prod) injects a real pool; tests inject
 * a fake pool. This keeps the adapter unit-testable with no live database.
 *
 * Merge semantics (matching Firestore .set(...,{merge:true})): only the fields present in
 * `data` are written. `findings` rows are replaced only when the `findings` key is present
 * (so the handler's partial "{error, updated_at}" write never wipes stored findings).
 */

"use strict";

// Scalar record fields -> scans columns. JSON fields handled separately below.
const SCALAR_COLUMNS = {
  client_name: "client_name",
  scan_type: "scan_type",
  target: "target",
  status: "status",
  created_at: "created_at",
  updated_at: "updated_at",
};
const JSON_COLUMNS = { summary: "summary_json", consensus: "consensus_json", error: "error_json" };

function toDate(v) {
  if (v instanceof Date) return v;
  if (typeof v === "string") {
    const d = new Date(v);
    if (!isNaN(d.getTime())) return d;
  }
  return new Date();
}

function jsonOrNull(v) {
  if (v === undefined || v === null) return null;
  try {
    return JSON.stringify(v);
  } catch {
    return null;
  }
}

/** Build the INSERT ... ON DUPLICATE KEY UPDATE for the scans row from present fields. */
function buildScanUpsert(clientId, scanId, data) {
  const cols = ["client_id", "scan_id"];
  const vals = [clientId, scanId];
  for (const [field, col] of Object.entries(SCALAR_COLUMNS)) {
    if (field in data) {
      cols.push(col);
      vals.push(field === "created_at" || field === "updated_at" ? toDate(data[field]) : data[field]);
    }
  }
  for (const [field, col] of Object.entries(JSON_COLUMNS)) {
    if (field in data) {
      cols.push(col);
      vals.push(jsonOrNull(data[field]));
    }
  }
  // On duplicate key, update every provided column except the primary key (merge).
  const updatable = cols.filter((c) => c !== "client_id" && c !== "scan_id");
  const placeholders = cols.map(() => "?").join(", ");
  const updates = updatable.map((c) => `${c}=VALUES(${c})`).join(", ");
  const sql =
    `INSERT INTO scans (${cols.join(", ")}) VALUES (${placeholders})` +
    (updates ? ` ON DUPLICATE KEY UPDATE ${updates}` : "");
  return { sql, params: vals };
}

function findingRows(clientId, scanId, findings) {
  return (Array.isArray(findings) ? findings : []).map((f) => [
    clientId,
    scanId,
    String(f && f.severity ? f.severity : "info").toLowerCase(),
    (f && f.scenario) || null,
    (f && f.title) || null,
    (f && f.detail) || null,
    jsonOrNull(f && f.attack),
    jsonOrNull(f && f.evidence),
    (f && f.remediation_key) || null,
  ]);
}

function makeSnapshot(row) {
  const exists = !!row;
  return {
    exists,
    get: (field) => (exists ? row[field] : undefined),
    data: () => (exists ? { ...row } : undefined),
  };
}

class ScanDocRef {
  constructor(pool, clientId, scanId) {
    this.pool = pool;
    this.clientId = clientId;
    this.scanId = scanId;
  }

  async get() {
    // mysql2/promise resolves query() to [rows, fields].
    const result = await this.pool.query(
      "SELECT * FROM scans WHERE client_id=? AND scan_id=?",
      [this.clientId, this.scanId]
    );
    const rows = Array.isArray(result) ? result[0] : result;
    const row = Array.isArray(rows) ? rows[0] : rows;
    return makeSnapshot(row);
  }

  async set(data, options = {}) {
    const merge = !!options.merge;
    // Ensure the tenant row exists (idempotent) before writing a scan for it.
    await this.pool.query(
      "INSERT IGNORE INTO clients (client_id, client_name, created_at) VALUES (?,?,?)",
      [this.clientId, data.client_name || null, toDate(data.created_at || data.updated_at)]
    );

    if (!merge) {
      // Full overwrite: clear then write the row's scalar/JSON fields.
      await this.pool.query("DELETE FROM scans WHERE client_id=? AND scan_id=?", [
        this.clientId,
        this.scanId,
      ]);
    }
    const { sql, params } = buildScanUpsert(this.clientId, this.scanId, data);
    await this.pool.query(sql, params);

    // Replace findings ONLY when the caller actually supplied them (merge-safe).
    if ("findings" in data) {
      await this.pool.query("DELETE FROM findings WHERE client_id=? AND scan_id=?", [
        this.clientId,
        this.scanId,
      ]);
      const rows = findingRows(this.clientId, this.scanId, data.findings);
      if (rows.length) {
        await this.pool.query(
          "INSERT INTO findings (client_id, scan_id, severity, scenario, title, detail, attack_json, evidence_json, remediation_key) VALUES ?",
          [rows]
        );
      }
    }
  }
}

// The handler builds the path clients/{cid}/scans/{sid} via chained collection()/doc().
// These thin refs accumulate exactly that shape and reject anything else.
class ScansCollectionRef {
  constructor(pool, clientId) {
    this.pool = pool;
    this.clientId = clientId;
  }
  doc(scanId) {
    return new ScanDocRef(this.pool, this.clientId, String(scanId));
  }
}

class ClientDocRef {
  constructor(pool, clientId) {
    this.pool = pool;
    this.clientId = String(clientId);
  }
  collection(name) {
    if (name !== "scans") {
      throw new Error(`mariadb-store: unsupported sub-collection ${name}`);
    }
    return new ScansCollectionRef(this.pool, this.clientId);
  }
}

class ClientsCollectionRef {
  constructor(pool) {
    this.pool = pool;
  }
  doc(clientId) {
    return new ClientDocRef(this.pool, clientId);
  }
}

/**
 * @param {object} opts
 * @param {object} opts.pool  mysql2/promise-style pool: query(sql, params) -> [rows]
 * @returns {{collection: Function, serverTimestamp: Function}}
 */
function createMariaDbStore(opts = {}) {
  const pool = opts.pool;
  if (!pool || typeof pool.query !== "function") {
    throw new Error("createMariaDbStore: a pool with query(sql, params) is required");
  }
  return {
    collection: (name) => {
      if (name !== "clients") {
        throw new Error(`mariadb-store: unsupported top-level collection ${name}`);
      }
      return new ClientsCollectionRef(pool);
    },
    serverTimestamp: () => new Date(),
  };
}

module.exports = { createMariaDbStore, buildScanUpsert, findingRows };
