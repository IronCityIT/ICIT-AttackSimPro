"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");

const {
  createStoreScanResultsHandler,
  toClientId,
  approxByteLength,
  MAX_FINDINGS,
} = require("../handler");
const { createInMemoryFirestore } = require("../testkit/inmemory-firestore");
const { makeReq, makeRes } = require("../testkit/express-shim");

function setup(opts = {}) {
  const db = createInMemoryFirestore();
  const handler = createStoreScanResultsHandler({ db, ...opts });
  return { db, handler };
}

async function call(handler, reqOpts) {
  const res = makeRes();
  await handler(makeReq(reqOpts), res);
  return res;
}

test("toClientId slugs names into a stable, path-safe id", () => {
  assert.equal(toClientId("Acme Corp, Inc."), "acme-corp-inc");
  assert.equal(toClientId("  Foo__Bar  "), "foo-bar");
  assert.equal(toClientId(""), "");
  assert.equal(toClientId(null), "");
});

test("rejects non-POST with 405", async () => {
  const { handler } = setup();
  const res = await call(handler, { method: "GET" });
  assert.equal(res.statusCode, 405);
  assert.equal(res.body.error, "method_not_allowed");
});

test("healthz returns ok", async () => {
  const { handler } = setup();
  const res = await call(handler, { method: "GET", path: "/healthz" });
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.status, "ok");
});

test("requires client_id", async () => {
  const { handler } = setup();
  const res = await call(handler, { body: { scan_id: "s1" } });
  assert.equal(res.statusCode, 400);
  assert.match(res.body.error, /client_id/);
});

test("requires scan_id", async () => {
  const { handler } = setup();
  const res = await call(handler, { body: { client_name: "Acme" } });
  assert.equal(res.statusCode, 400);
  assert.match(res.body.error, /scan_id/);
});

test("rejects malformed scan_id", async () => {
  const { handler } = setup();
  const res = await call(handler, {
    body: { client_name: "Acme", scan_id: "../../etc/passwd" },
  });
  assert.equal(res.statusCode, 400);
  assert.match(res.body.error, /invalid format/);
});

test("rejects an unknown status", async () => {
  const { handler } = setup();
  const res = await call(handler, {
    body: { client_name: "Acme", scan_id: "s1", status: "pwned" },
  });
  assert.equal(res.statusCode, 400);
  assert.match(res.body.error, /invalid status/);
});

test("stores a completed scan under clients/{id}/scans/{id} and keeps the real target", async () => {
  const { db, handler } = setup();
  const res = await call(handler, {
    body: {
      client_name: "Acme Corp",
      scan_id: "scan-42",
      scan_type: "web-baseline",
      target: "https://acme.example",
      findings: [{ name: "Missing HSTS", risk: "medium" }],
      summary: { high_count: 0, medium_count: 1 },
    },
  });
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.status, "stored");
  assert.equal(res.body.client_id, "acme-corp");
  assert.equal(res.body.findings, 1);

  const rec = db._get("clients/acme-corp/scans/scan-42");
  assert.ok(rec, "record written at partitioned path");
  assert.equal(rec.client_id, "acme-corp");
  assert.equal(rec.scan_id, "scan-42");
  assert.equal(rec.target, "https://acme.example"); // NOT "Multiple targets"
  assert.equal(rec.status, "completed");
  assert.equal(rec.findings.length, 1);
  assert.ok(rec.created_at, "created_at set on first write");
});

test("maps legacy target_url onto target", async () => {
  const { db, handler } = setup();
  await call(handler, {
    body: { client_name: "Acme", scan_id: "s2", target_url: "https://legacy.example" },
  });
  assert.equal(db._get("clients/acme/scans/s2").target, "https://legacy.example");
});

test("status is monotonic: a late failure never downgrades a completed scan", async () => {
  const { db, handler } = setup();
  await call(handler, {
    body: { client_name: "Acme", scan_id: "s3", status: "completed", findings: [{ name: "x" }] },
  });
  const res = await call(handler, {
    body: { client_name: "Acme", scan_id: "s3", status: "failed", error: { message: "ai step died" } },
  });
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.status, "already_completed");

  const rec = db._get("clients/acme/scans/s3");
  assert.equal(rec.status, "completed", "status preserved");
  assert.equal(rec.findings.length, 1, "findings preserved");
  assert.ok(rec.error, "error annotation recorded");
});

test("created_at is preserved across updates", async () => {
  const { db, handler } = setup();
  await call(handler, { body: { client_name: "Acme", scan_id: "s4", status: "running" } });
  const first = db._get("clients/acme/scans/s4").created_at;
  await call(handler, { body: { client_name: "Acme", scan_id: "s4", status: "completed" } });
  const rec = db._get("clients/acme/scans/s4");
  assert.equal(rec.created_at, first, "created_at unchanged");
  assert.equal(rec.status, "completed");
});

test("rejects a payload over the size cap with 413", async () => {
  const { handler } = setup({ maxBodyBytes: 500 });
  const res = await call(handler, {
    body: { client_name: "Acme", scan_id: "s5", summary: { blob: "x".repeat(1000) } },
  });
  assert.equal(res.statusCode, 413);
  assert.equal(res.body.error, "payload_too_large");
});

test("rejects too many findings with 413", async () => {
  const { handler } = setup();
  const findings = Array.from({ length: MAX_FINDINGS + 1 }, (_, i) => ({ name: "f" + i }));
  const res = await call(handler, { body: { client_name: "Acme", scan_id: "s6", findings } });
  assert.equal(res.statusCode, 413);
  assert.equal(res.body.error, "too_many_findings");
});

test("ingest token gate: rejects without a matching token", async () => {
  const { handler } = setup({ ingestToken: "sekret" });
  const bad = await call(handler, { body: { client_name: "Acme", scan_id: "s7" } });
  assert.equal(bad.statusCode, 401);

  const ok = await call(handler, {
    headers: { "X-Ingest-Token": "sekret" },
    body: { client_name: "Acme", scan_id: "s7" },
  });
  assert.equal(ok.statusCode, 200);
});

test("returns 500 when the store throws", async () => {
  const throwingDb = {
    serverTimestamp: () => "t",
    collection: () => ({
      doc: () => ({
        collection: () => ({ doc: () => ({ get: async () => { throw new Error("boom"); } }) }),
      }),
    }),
  };
  const handler = createStoreScanResultsHandler({ db: throwingDb });
  const res = await call(handler, { body: { client_name: "Acme", scan_id: "s8" } });
  assert.equal(res.statusCode, 500);
  assert.equal(res.body.error, "store_failed");
});

test("approxByteLength handles unserializable bodies", () => {
  const circular = {};
  circular.self = circular;
  assert.equal(approxByteLength(circular), Infinity);
});
