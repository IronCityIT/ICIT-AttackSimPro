"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("http");
const { buildServer } = require("../server");

function post(port, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body));
    const req = http.request(
      { host: "127.0.0.1", port, method: "POST", path: "/",
        headers: { "Content-Type": "application/json", "Content-Length": data.length, ...headers } },
      (res) => {
        let out = "";
        res.on("data", (c) => (out += c));
        res.on("end", () => resolve({ status: res.statusCode, body: JSON.parse(out || "{}") }));
      }
    );
    req.on("error", reject);
    req.end(data);
  });
}

test("buildServer wires the memory store and serves an ingest over a real socket", async () => {
  const { server, kind } = buildServer({ ASP_STORE: "memory", INGEST_TOKEN: "tok" });
  assert.equal(kind, "memory");
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  try {
    // token gate rejects a missing token
    const bad = await post(port, { client_name: "Acme", scan_id: "s1", status: "completed" });
    assert.equal(bad.status, 401);
    // authenticated POST stores
    const ok = await post(port, { client_name: "Acme", scan_id: "s1", status: "completed", findings: [] },
      { "X-Ingest-Token": "tok" });
    assert.equal(ok.status, 200);
    assert.equal(ok.body.status, "stored");
    assert.equal(ok.body.client_id, "acme");
  } finally {
    await new Promise((r) => server.close(r));
  }
});
