"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { chooseStoreKind, createStore } = require("../store/select-store");
const { createStoreScanResultsHandler } = require("../handler");
const { makeReq, makeRes } = require("../testkit/express-shim");

test("chooseStoreKind: default is memory when nothing is configured", () => {
  assert.equal(chooseStoreKind({}), "memory");
});

test("chooseStoreKind: ASP_MARIADB_URL implies mariadb", () => {
  assert.equal(chooseStoreKind({ ASP_MARIADB_URL: "mysql://x" }), "mariadb");
});

test("chooseStoreKind: explicit ASP_STORE wins and is validated", () => {
  assert.equal(chooseStoreKind({ ASP_STORE: "memory", ASP_MARIADB_URL: "mysql://x" }), "memory");
  assert.equal(chooseStoreKind({ ASP_STORE: "mariadb" }), "mariadb");
  assert.throws(() => chooseStoreKind({ ASP_STORE: "firestore" }), /ASP_STORE must be one of/);
});

test("createStore memory: a scan round-trips through the real handler", async () => {
  const { db } = createStore({ kind: "memory", env: {} });
  const handler = createStoreScanResultsHandler({ db });
  const res = makeRes();
  await handler(makeReq({ body: { client_name: "Acme", scan_id: "m1", status: "completed", findings: [] } }), res);
  assert.equal(res.body.status, "stored");
  assert.equal(res.body.client_id, "acme");
});

test("createStore mariadb: uses ASP_MARIADB_URL + injected mysql, round-trips via handler", async () => {
  // Faithful fake pool (same shape the mariadb-store test uses).
  const scans = new Map();
  const findings = new Map();
  const clients = new Map();
  const key = (c, s) => c + "|" + s;
  const pool = {
    async query(sql, params) {
      const s = sql.trim();
      if (s.startsWith("SELECT * FROM scans")) {
        const row = scans.get(key(params[0], params[1]));
        return [row ? [{ ...row }] : [], []];
      }
      if (s.startsWith("INSERT IGNORE INTO clients")) { clients.set(params[0], 1); return [{}, []]; }
      if (s.startsWith("DELETE FROM scans")) { scans.delete(key(params[0], params[1])); return [{}, []]; }
      if (s.startsWith("INSERT INTO scans")) {
        const cols = s.slice(s.indexOf("(") + 1, s.indexOf(")")).split(",").map((c) => c.trim());
        const row = { ...(scans.get(key(params[0], params[1])) || {}) };
        cols.forEach((c, i) => (row[c] = params[i]));
        scans.set(key(params[0], params[1]), row);
        return [{}, []];
      }
      if (s.startsWith("DELETE FROM findings")) { findings.delete(key(params[0], params[1])); return [{}, []]; }
      if (s.startsWith("INSERT INTO findings")) { const r = params[0]; findings.set(key(r[0][0], r[0][1]), r); return [{}, []]; }
      throw new Error("unhandled: " + s.slice(0, 40));
    },
    end() {},
  };
  const injectedMysql = { createPool: () => pool };
  const { db, describe, close } = createStore({
    kind: "mariadb",
    env: { ASP_MARIADB_URL: "mysql://user:pw@nas:3306/attacksimpro" },
    mysql: injectedMysql,
  });
  assert.match(describe, /mariadb/);
  const handler = createStoreScanResultsHandler({ db });
  const res = makeRes();
  await handler(makeReq({ body: { client_name: "Acme", scan_id: "db1", status: "completed",
    findings: [{ severity: "high", title: "x" }] } }), res);
  assert.equal(res.body.status, "stored");
  assert.equal(scans.get("acme|db1").status, "completed");
  assert.equal(findings.get("acme|db1").length, 1);
  await close();
});

test("createStore mariadb without ASP_MARIADB_URL fails closed", () => {
  assert.throws(() => createStore({ kind: "mariadb", env: {}, mysql: { createPool: () => ({}) } }),
    /requires ASP_MARIADB_URL/);
});
