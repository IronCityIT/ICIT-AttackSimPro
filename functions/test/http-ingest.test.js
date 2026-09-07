"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("http");
const { createIngestServer } = require("../store/http-ingest");

function req(port, method, path) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: "127.0.0.1", port, method, path }, (res) => {
      let out = "";
      res.on("data", (c) => (out += c));
      res.on("end", () => resolve({ status: res.statusCode, body: JSON.parse(out || "{}") }));
    });
    r.on("error", reject);
    r.end();
  });
}

test("createIngestServer routes GET /clients/* to the read handler, POST to ingest", async () => {
  const seen = { get: null, post: 0 };
  const ingest = async (rq, res) => {
    seen.post += 1;
    res.status(200).json({ status: "stored" });
  };
  const readHandler = async (rq, res) => {
    seen.get = { path: rq.path, query: rq.query };
    res.status(200).json({ ok: true, path: rq.path });
  };
  const server = createIngestServer(ingest, { readHandler });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  try {
    const g = await req(port, "GET", "/clients/acme/scans?limit=5");
    assert.equal(g.status, 200);
    assert.equal(g.body.path, "/clients/acme/scans");
    assert.equal(seen.get.query.limit, "5");

    const p = await req(port, "POST", "/");
    assert.equal(p.status, 200);
    assert.equal(seen.post, 1);
  } finally {
    await new Promise((r) => server.close(r));
  }
});
