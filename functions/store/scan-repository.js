/**
 * Tenant-scoped read data layer over the MariaDB store.
 *
 * FAIL-CLOSED BY CONSTRUCTION: every query REQUIRES a non-empty client_id and always
 * includes a `WHERE client_id=?` predicate. There is no code path that reads across
 * tenants — a missing client_id throws rather than widening the query. This is the
 * server-side half of the dashboard Read API; who supplies the client_id (and proves the
 * caller owns it) is the authorizer's job — see read-api.js.
 *
 * Takes a mysql2/promise-style pool (query(sql, params) -> [rows, fields]).
 */

"use strict";

function requireClientId(clientId) {
  const cid = String(clientId || "").trim();
  if (!cid) throw new Error("scan-repository: client_id is required (fail-closed)");
  return cid;
}

function rowsOf(result) {
  const rows = Array.isArray(result) ? result[0] : result;
  return Array.isArray(rows) ? rows : rows ? [rows] : [];
}

function jsonParse(v) {
  if (v === null || v === undefined) return null;
  if (typeof v === "object") return v;
  try {
    return JSON.parse(v);
  } catch {
    return null;
  }
}

function deserializeScan(row) {
  return {
    client_id: row.client_id,
    scan_id: row.scan_id,
    scan_type: row.scan_type,
    target: row.target,
    status: row.status,
    summary: jsonParse(row.summary_json),
    consensus: jsonParse(row.consensus_json),
    error: jsonParse(row.error_json),
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

function deserializeFinding(row) {
  return {
    severity: row.severity,
    scenario: row.scenario,
    title: row.title,
    detail: row.detail,
    attack: jsonParse(row.attack_json),
    evidence: jsonParse(row.evidence_json),
    remediation_key: row.remediation_key,
  };
}

const SCAN_COLS =
  "client_id, scan_id, scan_type, target, status, summary_json, consensus_json, error_json, created_at, updated_at";

/** List a tenant's scans, newest first. Always scoped to client_id. */
async function listScans(pool, clientId, opts = {}) {
  const cid = requireClientId(clientId);
  let limit = parseInt(opts.limit, 10);
  if (!Number.isFinite(limit)) limit = 50;
  limit = Math.min(Math.max(limit, 1), 200);
  const result = await pool.query(
    `SELECT ${SCAN_COLS} FROM scans WHERE client_id=? ORDER BY updated_at DESC LIMIT ?`,
    [cid, limit]
  );
  const scans = rowsOf(result).map(deserializeScan);
  if (opts.withFindings && scans.length) {
    // Batch-load findings for exactly this page of scans, still tenant-scoped.
    const ids = scans.map((s) => s.scan_id);
    const placeholders = ids.map(() => "?").join(", ");
    const findRows = rowsOf(
      await pool.query(
        `SELECT scan_id, severity, scenario, title, detail, attack_json, evidence_json, remediation_key FROM findings WHERE client_id=? AND scan_id IN (${placeholders}) ORDER BY id`,
        [cid, ...ids]
      )
    );
    const byScan = new Map(scans.map((s) => [s.scan_id, s]));
    for (const s of scans) s.findings = [];
    for (const r of findRows) {
      const s = byScan.get(r.scan_id);
      if (s) s.findings.push(deserializeFinding(r));
    }
  }
  return scans;
}

/** Get one scan (with its findings) for a tenant, or null. Always scoped to client_id. */
async function getScan(pool, clientId, scanId) {
  const cid = requireClientId(clientId);
  const sid = String(scanId || "").trim();
  if (!sid) throw new Error("scan-repository: scan_id is required");
  const scanRows = rowsOf(
    await pool.query(`SELECT ${SCAN_COLS} FROM scans WHERE client_id=? AND scan_id=?`, [cid, sid])
  );
  if (!scanRows.length) return null;
  const scan = deserializeScan(scanRows[0]);
  const findRows = rowsOf(
    await pool.query(
      "SELECT severity, scenario, title, detail, attack_json, evidence_json, remediation_key FROM findings WHERE client_id=? AND scan_id=? ORDER BY id",
      [cid, sid]
    )
  );
  scan.findings = findRows.map(deserializeFinding);
  return scan;
}

module.exports = { listScans, getScan, deserializeScan, deserializeFinding };
