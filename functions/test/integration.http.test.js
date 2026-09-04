"use strict";

// Integration / E2E: boots the real local-server.js over a live TCP socket and
// drives the ingest contract with actual HTTP requests (not the in-process shim).
// Covers the happy path, the monotonic-status rule, and the optional ingest-token
// gate end to end.

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const { spawn } = require("node:child_process");
const path = require("node:path");

const PORT = 8097;
const BASE = `http://127.0.0.1:${PORT}`;
let child;

function req(method, pathname, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const data = body ? Buffer.from(JSON.stringify(body)) : null;
    const r = http.request(
      BASE + pathname,
      { method, headers: { "Content-Type": "application/json", ...headers } },
      (res) => {
        let buf = "";
        res.on("data", (c) => (buf += c));
        res.on("end", () =>
          resolve({ status: res.statusCode, headers: res.headers, body: buf ? JSON.parse(buf) : null })
        );
      }
    );
    r.on("error", reject);
    if (data) r.write(data);
    r.end();
  });
}

async function waitUp() {
  for (let i = 0; i < 100; i++) {
    try {
      const r = await req("GET", "/healthz");
      if (r.status === 200) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error("server did not come up");
}

before(async () => {
  child = spawn(process.execPath, [path.join(__dirname, "..", "local-server.js")], {
    env: { ...process.env, PORT: String(PORT), INGEST_TOKEN: "e2e-token" },
    stdio: "ignore",
  });
  await waitUp();
});

after(() => {
  if (child) child.kill();
});

test("healthz is live over HTTP", async () => {
  const r = await req("GET", "/healthz");
  assert.equal(r.status, 200);
  assert.equal(r.body.status, "ok");
});

test("token gate rejects an unauthenticated POST (401)", async () => {
  const r = await req("POST", "/", { client_name: "Acme", scan_id: "e1" });
  assert.equal(r.status, 401);
});

test("full store round-trip with a valid token + request id header", async () => {
  const r = await req(
    "POST",
    "/",
    {
      client_name: "Acme Corp",
      scan_id: "e2e-1",
      target: "https://acme.example",
      status: "completed",
      findings: [{ name: "Missing HSTS", risk: "medium" }],
    },
    { "X-Ingest-Token": "e2e-token" }
  );
  assert.equal(r.status, 200);
  assert.equal(r.body.status, "stored");
  assert.equal(r.body.findings, 1);
  assert.ok(r.headers["x-request-id"], "response carries a request id");

  const dump = await req("GET", "/__dump");
  assert.equal(dump.body["clients/acme-corp/scans/e2e-1"].target, "https://acme.example");
});

test("monotonic status holds over HTTP: late failure does not downgrade", async () => {
  await req("POST", "/", { client_name: "Acme", scan_id: "e2e-2", status: "completed", findings: [{ name: "x" }] },
    { "X-Ingest-Token": "e2e-token" });
  const r = await req("POST", "/", { client_name: "Acme", scan_id: "e2e-2", status: "failed", error: { message: "late" } },
    { "X-Ingest-Token": "e2e-token" });
  assert.equal(r.status, 200);
  assert.equal(r.body.status, "already_completed");

  const dump = await req("GET", "/__dump");
  assert.equal(dump.body["clients/acme/scans/e2e-2"].status, "completed");
});
