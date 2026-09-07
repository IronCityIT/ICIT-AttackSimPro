#!/usr/bin/env node
/**
 * Self-hosted AttackSim Pro ingest service (target architecture; Firebase retired).
 *
 * Runs the exact production handler (handler.js) over HTTP, backed by the store chosen
 * from the environment (MariaDB on the NAS in production, in-memory for dev). Deployed as
 * a container on ICIT NAS-backed infra behind the reverse proxy; GitHub Actions posts to
 * it at STORE_SCAN_RESULTS_URL with INGEST_TOKEN — the same contract the workflows use.
 *
 *   ASP_STORE=mariadb ASP_MARIADB_URL=... INGEST_TOKEN=... PORT=8088 node functions/server.js
 */

"use strict";

const { createStoreScanResultsHandler } = require("./handler");
const { chooseStoreKind, createStore } = require("./store/select-store");
const { createIngestServer } = require("./store/http-ingest");
const { createReadHandler } = require("./store/read-api");

function buildServer(env = process.env, opts = {}) {
  const kind = chooseStoreKind(env);
  const store = createStore({ kind, env });
  const handler = createStoreScanResultsHandler({
    db: store.db,
    ingestToken: env.INGEST_TOKEN || "",
  });
  // Debug dump only for the in-memory dev store, never for a real backing store.
  const dumpStore = kind === "memory" && store.db._dump ? () => store.db._dump() : undefined;
  // Tenant-scoped Read API when a real pool backs the store. Fail-closed: without an
  // injected `authorize` strategy (Auth0 -> client_id+role token), it denies every read.
  const readHandler = store.pool
    ? createReadHandler({ pool: store.pool, authorize: opts.authorize })
    : undefined;
  const server = createIngestServer(handler, { dumpStore, readHandler });
  return { server, store, kind };
}

if (require.main === module) {
  const PORT = Number(process.env.PORT || 8088);
  const { server, kind } = buildServer();
  server.listen(PORT, () => {
    console.log(`AttackSimPro ingest listening on http://0.0.0.0:${PORT} — store: ${kind}`);
    if (process.env.INGEST_TOKEN) console.log("ingest token gate: ENABLED");
  });
}

module.exports = { buildServer };
