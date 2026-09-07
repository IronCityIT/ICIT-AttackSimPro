"use strict";

/**
 * MariaDB store adapter tests.
 *
 * The default suite drives the EXACT production handler (handler.js) through the MariaDB
 * `db` adapter using an in-memory fake pool that faithfully applies the adapter's own SQL
 * (upsert-merge, findings replace, monotonic status). No live database is needed.
 *
 * An env-gated integration test runs the same round-trip against a real MariaDB when
 * ASP_MARIADB_URL is set; otherwise it SKIPs with a clear message.
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const { createMariaDbStore } = require("../store/mariadb-store");
const { createStoreScanResultsHandler } = require("../handler");
const { makeReq, makeRes } = require("../testkit/express-shim");

// ---- Faithful in-memory fake of a mysql2/promise pool -----------------------------
function makeFakePool() {
  const scans = new Map();
  const findings = new Map();
  const clients = new Map();
  const key = (cid, sid) => cid + "|" + sid;
  return {
    scans,
    findings,
    clients,
    async query(sql, params) {
      const s = sql.trim();
      if (s.startsWith("SELECT * FROM scans")) {
        const [cid, sid] = params;
        const row = scans.get(key(cid, sid));
        return [row ? [{ ...row }] : [], []];
      }
      if (s.startsWith("INSERT IGNORE INTO clients")) {
        const [cid, name] = params;
        if (!clients.has(cid)) clients.set(cid, { client_id: cid, client_name: name });
        return [{}, []];
      }
      if (s.startsWith("DELETE FROM scans")) {
        const [cid, sid] = params;
        scans.delete(key(cid, sid));
        return [{}, []];
      }
      if (s.startsWith("INSERT INTO scans")) {
        const cols = s.slice(s.indexOf("(") + 1, s.indexOf(")")).split(",").map((c) => c.trim());
        const cid = params[0];
        const sid = params[1];
        const row = { ...(scans.get(key(cid, sid)) || {}) };
        cols.forEach((c, i) => {
          row[c] = params[i];
        });
        scans.set(key(cid, sid), row);
        return [{}, []];
      }
      if (s.startsWith("DELETE FROM findings")) {
        const [cid, sid] = params;
        findings.delete(key(cid, sid));
        return [{}, []];
      }
      if (s.startsWith("INSERT INTO findings")) {
        const rows = params[0];
        findings.set(key(rows[0][0], rows[0][1]), rows);
        return [{}, []];
      }
      throw new Error("fake pool: unhandled SQL: " + s.slice(0, 48));
    },
  };
}

function handlerOn(pool) {
  return createStoreScanResultsHandler({ db: createMariaDbStore({ pool }) });
}

test("stores a scan + findings through the handler into the relational store", async () => {
  const pool = makeFakePool();
  const handler = handlerOn(pool);
  const res = makeRes();
  await handler(
    makeReq({
      body: {
        client_name: "Acme Corp",
        scan_id: "sim-1",
        scan_type: "purple-team-validation",
        target: "https://app.acme.test",
        status: "completed",
        summary: { high_count: 1, medium_count: 2 },
        findings: [
          { severity: "high", scenario: "s1", title: "T1", attack: ["T1190"], remediation_key: "k1" },
          { severity: "medium", scenario: "s2", title: "T2" },
          { severity: "medium", scenario: "s3", title: "T3" },
        ],
      },
    }),
    res
  );
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.status, "stored");
  assert.equal(res.body.client_id, "acme-corp");
  assert.equal(res.body.findings, 3);

  const row = pool.scans.get("acme-corp|sim-1");
  assert.ok(row, "scan row persisted");
  assert.equal(row.status, "completed");
  assert.equal(row.client_id, "acme-corp");
  assert.equal(JSON.parse(row.summary_json).high_count, 1);
  assert.equal(pool.findings.get("acme-corp|sim-1").length, 3);
  assert.ok(pool.clients.has("acme-corp"), "tenant row created");
});

test("monotonic status: a failed report never downgrades a completed scan or wipes findings", async () => {
  const pool = makeFakePool();
  const handler = handlerOn(pool);

  const r1 = makeRes();
  await handler(
    makeReq({
      body: {
        client_name: "Acme", scan_id: "s2", status: "completed",
        findings: [{ severity: "high", title: "keepme" }],
      },
    }),
    r1
  );
  assert.equal(r1.body.status, "stored");

  const r2 = makeRes();
  await handler(
    makeReq({ body: { client_name: "Acme", scan_id: "s2", status: "failed", error: { message: "late stage failed" } } }),
    r2
  );
  assert.equal(r2.statusCode, 200);
  assert.equal(r2.body.status, "already_completed");

  const row = pool.scans.get("acme|s2");
  assert.equal(row.status, "completed", "status stayed completed");
  assert.equal(JSON.parse(row.error_json).message, "late stage failed", "error recorded");
  assert.equal(pool.findings.get("acme|s2").length, 1, "findings preserved");
});

test("tenant isolation: two clients get separate rows, no cross-write", async () => {
  const pool = makeFakePool();
  const handler = handlerOn(pool);
  for (const [name, sid] of [["Client A", "a1"], ["Client B", "b1"]]) {
    const res = makeRes();
    await handler(makeReq({ body: { client_name: name, scan_id: sid, status: "completed", findings: [] } }), res);
    assert.equal(res.body.status, "stored");
  }
  assert.ok(pool.scans.has("client-a|a1"));
  assert.ok(pool.scans.has("client-b|b1"));
  assert.equal(pool.scans.get("client-a|a1").client_id, "client-a");
  assert.equal(pool.scans.get("client-b|b1").client_id, "client-b");
});

test("adapter rejects unsupported paths (fail-loud, no silent misroute)", async () => {
  const pool = makeFakePool();
  const db = createMariaDbStore({ pool });
  assert.throws(() => db.collection("scans"), /unsupported top-level collection/);
  assert.throws(() => db.collection("clients").doc("c").collection("nope"), /unsupported sub-collection/);
});

test("createMariaDbStore requires a pool with query()", () => {
  assert.throws(() => createMariaDbStore({}), /a pool with query/);
});

// ---- Env-gated live integration ---------------------------------------------------
test("integration: round-trip against a real MariaDB (ASP_MARIADB_URL)", async (t) => {
  const url = process.env.ASP_MARIADB_URL;
  if (!url) {
    t.skip("ASP_MARIADB_URL not set — skipping live MariaDB integration");
    return;
  }
  let mysql;
  try {
    mysql = require("mysql2/promise");
  } catch {
    t.skip("mysql2 not installed — skipping live MariaDB integration");
    return;
  }
  const pool = await mysql.createPool(url);
  try {
    const handler = handlerOn(pool);
    const scanId = "it-" + Date.now();
    const res = makeRes();
    await handler(
      makeReq({ body: { client_name: "IT Client", scan_id: scanId, status: "completed",
        findings: [{ severity: "high", title: "live" }] } }),
      res
    );
    assert.equal(res.body.status, "stored");
    const [rows] = await pool.query("SELECT status FROM scans WHERE client_id=? AND scan_id=?", ["it-client", scanId]);
    assert.equal(rows[0].status, "completed");
    await pool.query("DELETE FROM scans WHERE client_id=? AND scan_id=?", ["it-client", scanId]);
  } finally {
    await pool.end();
  }
});
