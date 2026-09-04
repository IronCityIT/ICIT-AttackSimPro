#!/usr/bin/env node
/**
 * Local smoke server for storeScanResults.
 *
 * Runs the EXACT production handler (handler.js) against an in-memory Firestore
 * double, over a real HTTP socket, with zero external dependencies. This is what
 * `npm run smoke` / scripts/smoke.sh drive, so the ingest contract can be
 * verified end to end on a laptop or in CI without GCP credentials or a deploy.
 *
 *   PORT=8088 INGEST_TOKEN=secret node functions/local-server.js
 *   GET  /healthz            -> liveness
 *   GET  /__dump             -> current in-memory store (debug only)
 *   POST /                   -> store a scan result
 */

"use strict";

const http = require("http");
const { createStoreScanResultsHandler } = require("./handler");
const { createInMemoryFirestore } = require("./testkit/inmemory-firestore");
const { makeRes } = require("./testkit/express-shim");

const PORT = Number(process.env.PORT || 8088);
const db = createInMemoryFirestore();
const handler = createStoreScanResultsHandler({
  db,
  ingestToken: process.env.INGEST_TOKEN || "",
});

const server = http.createServer((req, res) => {
  const chunks = [];
  let bytes = 0;
  req.on("data", (c) => {
    bytes += c.length;
    if (bytes > 2_000_000) req.destroy(); // socket-level guard
    else chunks.push(c);
  });
  req.on("end", async () => {
    // Debug-only dump of the in-memory store.
    if (req.method === "GET" && req.url === "/__dump") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(db._dump(), null, 2));
      return;
    }

    let body = {};
    const raw = Buffer.concat(chunks).toString("utf8");
    if (raw) {
      try {
        body = JSON.parse(raw);
      } catch {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "invalid_json" }));
        return;
      }
    }

    const shim = makeRes();
    const fakeReq = {
      method: req.method,
      url: req.url,
      path: (req.url || "/").split("?")[0],
      body,
      headers: req.headers,
      get: (n) => req.headers[String(n).toLowerCase()],
    };
    await handler(fakeReq, shim);

    const headers = { "Content-Type": "application/json", ...shim.headers };
    res.writeHead(shim.statusCode, headers);
    res.end(JSON.stringify(shim.body ?? {}));
  });
});

server.listen(PORT, () => {
  console.log(`storeScanResults local server listening on http://127.0.0.1:${PORT}`);
  if (process.env.INGEST_TOKEN) console.log("ingest token gate: ENABLED");
});

module.exports = { server };
