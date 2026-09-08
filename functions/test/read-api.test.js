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
      if (s.startsWith("SELECT") && s.includes("FROM findings") && s.includes(" IN (")) {
        const cid = params[0];
        const ids = params.slice(1);
        return [findings.filter((r) => r.client_id === cid && ids.includes(r.scan_id)), []];
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
  const [path, qs] = url.split("?");
  const query = {};
  if (qs) for (const kv of qs.split("&")) { const [k, v] = kv.split("="); query[decodeURIComponent(k)] = decodeURIComponent(v || ""); }
  return { ...makeReq({ method: "GET", url, path }), query };
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

test("read API include=findings attaches each scan's findings (tenant-scoped)", async () => {
  const handler = createReadHandler({ pool: seededPool(), authorize: authorizeAs("acme") });
  const res = makeRes();
  await handler(get("/clients/acme/scans?include=findings"), res);
  assert.equal(res.statusCode, 200);
  const a2 = res.body.scans.find((x) => x.scan_id === "a2");
  assert.ok(Array.isArray(a2.findings));
  assert.equal(a2.findings.length, 1);
  assert.deepEqual(a2.findings[0].attack, ["T1190"]);
});

// ---- Env-gated: exercise the tenant-scoped read path against a REAL MariaDB ----------
test("integration: Read API round-trips against a real MariaDB (ASP_MARIADB_URL)", async (t) => {
  const url = process.env.ASP_MARIADB_URL;
  if (!url) {
    t.skip("ASP_MARIADB_URL not set — skipping live read-path integration");
    return;
  }
  let mysql;
  try {
    mysql = require("mysql2/promise");
  } catch {
    t.skip("mysql2 not installed — skipping live read-path integration");
    return;
  }
  const { createMariaDbStore } = require("../store/mariadb-store");
  const { createStoreScanResultsHandler } = require("../handler");
  const pool = await mysql.createPool(url);
  try {
    const handler = createStoreScanResultsHandler({ db: createMariaDbStore({ pool }) });
    const sid = "ris-" + Date.now();

    // Store a scan (with findings) for tenant "read-it", and one for a different tenant.
    let r = makeRes();
    await handler(makeReq({ body: {
      client_name: "Read IT", scan_id: sid, status: "completed",
      target: "https://r.test", summary: { high_count: 1 },
      findings: [{ severity: "high", scenario: "s", title: "T", attack: ["T1190"],
                   evidence: { tactic: "initial-access" }, remediation_key: "k" }],
    } }), r);
    assert.equal(r.body.status, "stored");
    r = makeRes();
    await handler(makeReq({ body: { client_name: "Other Co", scan_id: "other-1",
                                    status: "completed", findings: [] } }), r);
    assert.equal(r.body.status, "stored");

    // listScans is tenant-scoped: only read-it rows, never the other tenant.
    const scans = await listScans(pool, "read-it");
    assert.ok(scans.some((s) => s.scan_id === sid), "own scan listed");
    assert.ok(scans.every((s) => s.client_id === "read-it"), "no cross-tenant rows");

    // getScan: real-MariaDB JSON columns deserialize back to objects/arrays.
    const scan = await getScan(pool, "read-it", sid);
    assert.equal(scan.status, "completed");
    assert.equal(scan.summary.high_count, 1, "summary_json deserialized to object");
    assert.equal(scan.findings.length, 1);
    assert.deepEqual(scan.findings[0].attack, ["T1190"], "attack_json deserialized to array");

    // listScans withFindings (the IN(...) batch load) attaches findings, tenant-scoped.
    const withF = await listScans(pool, "read-it", { withFindings: true });
    const mine = withF.find((s) => s.scan_id === sid);
    assert.equal(mine.findings.length, 1, "batch-loaded findings attached");

    // A different tenant sees none of read-it's data.
    const otherScans = await getScan(pool, "other-co", sid);
    assert.equal(otherScans, null, "cross-tenant getScan returns null");

    await pool.query("DELETE FROM scans WHERE client_id IN (?,?)", ["read-it", "other-co"]);
  } finally {
    await pool.end();
  }
});
