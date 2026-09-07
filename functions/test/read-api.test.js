"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { createReadHandler } = require("../store/read-api");
const { listScans, getScan } = require("../store/scan-repository");
const { makeReq, makeRes } = require("../testkit/express-shim");

// A tiny read-only fake pool preloaded with two tenants' scans + findings.
function seededPool() {
  const scans = [
    { client_id: "acme", scan_id: "a2", scan_type: "pt", target: "t", status: "completed",
      summary_json: '{"high_count":1}', consensus_json: null, error_json: null,
      created_at: "2026-09-01", updated_at: "2026-09-02" },
    { client_id: "acme", scan_id: "a1", scan_type: "pt", target: "t", status: "completed",
      summary_json: '{"high_count":0}', consensus_json: null, error_json: null,
      created_at: "2026-08-01", updated_at: "2026-08-02" },
    { client_id: "globex", scan_id: "g1", scan_type: "pt", target: "t", status: "completed",
      summary_json: "{}", consensus_json: null, error_json: null,
      created_at: "2026-08-01", updated_at: "2026-08-02" },
  ];
  const findings = [
    { client_id: "acme", scan_id: "a2", severity: "high", scenario: "s", title: "T",
      detail: "d", attack_json: '["T1190"]', evidence_json: "{}", remediation_key: "k" },
    { client_id: "globex", scan_id: "g1", severity: "low", scenario: "s", title: "G",
      detail: "d", attack_json: "[]", evidence_json: "{}", remediation_key: "k" },
  ];
  return {
    queries: [],
    async query(sql, params) {
      this.queries.push({ sql, params });
      const s = sql.trim();
      if (s.startsWith("SELECT") && s.includes("FROM scans") && s.includes("AND scan_id=?")) {
        const [cid, sid] = params;
        return [scans.filter((r) => r.client_id === cid && r.scan_id === sid), []];
      }
      if (s.startsWith("SELECT") && s.includes("FROM scans")) {
        const cid = params[0];
        const rows = scans.filter((r) => r.client_id === cid)
          .sort((a, b) => (a.updated_at < b.updated_at ? 1 : -1));
        return [rows, []];
      }
      if (s.startsWith("SELECT") && s.includes("FROM findings")) {
        const [cid, sid] = params;
        return [findings.filter((r) => r.client_id === cid && r.scan_id === sid), []];
      }
      throw new Error("unhandled read SQL: " + s.slice(0, 40));
    },
  };
}

const authorizeAs = (client_id, role = "viewer") => () => ({ client_id, role });

// Build a GET request the way the server does: path derived from the url.
function get(url) {
  return makeReq({ method: "GET", url, path: url.split("?")[0] });
}

test("repository fail-closed: empty client_id throws, never widens the query", async () => {
  const pool = seededPool();
  await assert.rejects(() => listScans(pool, ""), /client_id is required/);
  await assert.rejects(() => getScan(pool, "", "a1"), /client_id is required/);
});

test("repository scopes every query to the tenant", async () => {
  const pool = seededPool();
  const rows = await listScans(pool, "acme");
  assert.equal(rows.length, 2);
  assert.ok(rows.every((r) => r.client_id === "acme"));
  assert.equal(rows[0].scan_id, "a2"); // newest first
  assert.ok(pool.queries.every((q) => q.params[0] === "acme"));
});

test("getScan returns the scan with its findings, tenant-scoped", async () => {
  const pool = seededPool();
  const scan = await getScan(pool, "acme", "a2");
  assert.equal(scan.scan_id, "a2");
  assert.equal(scan.summary.high_count, 1);
  assert.equal(scan.findings.length, 1);
  assert.deepEqual(scan.findings[0].attack, ["T1190"]);
});

test("read API denies with no authorizer configured (fail-closed 401)", async () => {
  const handler = createReadHandler({ pool: seededPool() });
  const res = makeRes();
  await handler(get("/clients/acme/scans"), res);
  assert.equal(res.statusCode, 401);
});

test("read API: authorized principal reads ONLY their own tenant", async () => {
  const handler = createReadHandler({ pool: seededPool(), authorize: authorizeAs("acme") });
  const res = makeRes();
  await handler(get("/clients/acme/scans"), res);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.client_id, "acme");
  assert.equal(res.body.scans.length, 2);
});

test("read API: cross-tenant read is forbidden even with a valid token (403)", async () => {
  const handler = createReadHandler({ pool: seededPool(), authorize: authorizeAs("acme") });
  const res = makeRes();
  await handler(get("/clients/globex/scans"), res);
  assert.equal(res.statusCode, 403);
});

test("read API: single scan + 404 on miss, method + path guards", async () => {
  const handler = createReadHandler({ pool: seededPool(), authorize: authorizeAs("acme") });
  let res = makeRes();
  await handler(get("/clients/acme/scans/a2"), res);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.scan_id, "a2");

  res = makeRes();
  await handler(get("/clients/acme/scans/nope"), res);
  assert.equal(res.statusCode, 404);

  res = makeRes();
  await handler(makeReq({ method: "POST", url: "/clients/acme/scans", path: "/clients/acme/scans" }), res);
  assert.equal(res.statusCode, 405);

  res = makeRes();
  await handler(get("/nonsense"), res);
  assert.equal(res.statusCode, 404);
});

test("createReadHandler requires a pool", () => {
  assert.throws(() => createReadHandler({}), /a pool with query/);
});
