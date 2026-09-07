/**
 * Minimal HTTP wrapper that drives functions/handler.js over a real socket, with a
 * request-body cap and an optional debug dump. Zero external dependencies. Used by the
 * self-hosted ingest service (server.js). The Firestore Cloud Functions shell (index.js)
 * does not use this — it is the retired path.
 */

"use strict";

const http = require("http");
const { makeRes } = require("../testkit/express-shim");

/**
 * @param {(req,res)=>Promise<void>} handler  storeScanResults handler
 * @param {object} [opts]
 * @param {Function} [opts.dumpStore]  optional () -> object exposed at GET /__dump (dev only)
 * @param {number}   [opts.maxSocketBytes]
 * @returns {http.Server}
 */
function createIngestServer(handler, opts = {}) {
  const dumpStore = opts.dumpStore;
  const readHandler = opts.readHandler; // optional GET Read API (tenant-scoped, fail-closed)
  const maxSocketBytes = opts.maxSocketBytes || 2_000_000;

  return http.createServer((req, res) => {
    const chunks = [];
    let bytes = 0;
    req.on("data", (c) => {
      bytes += c.length;
      if (bytes > maxSocketBytes) req.destroy();
      else chunks.push(c);
    });
    req.on("end", async () => {
      if (req.method === "GET" && req.url === "/__dump" && dumpStore) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(dumpStore(), null, 2));
        return;
      }
      // Tenant-scoped Read API for the dashboard (GET). POST falls through to ingest.
      if (req.method === "GET" && readHandler && (req.url || "/").startsWith("/clients/")) {
        const shim = makeRes();
        const q = {};
        const qs = (req.url || "").split("?")[1];
        if (qs) for (const kv of qs.split("&")) { const [k, v] = kv.split("="); q[decodeURIComponent(k)] = decodeURIComponent(v || ""); }
        await readHandler({
          method: "GET",
          url: req.url,
          path: (req.url || "/").split("?")[0],
          query: q,
          headers: req.headers,
          get: (n) => req.headers[String(n).toLowerCase()],
        }, shim);
        res.writeHead(shim.statusCode, { "Content-Type": "application/json", ...shim.headers });
        res.end(JSON.stringify(shim.body ?? {}));
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
      res.writeHead(shim.statusCode, { "Content-Type": "application/json", ...shim.headers });
      res.end(JSON.stringify(shim.body ?? {}));
    });
  });
}

module.exports = { createIngestServer };
