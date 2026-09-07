/**
 * Store selection for the self-hosted ingest service.
 *
 * Chooses which `db` port implementation backs functions/handler.js from the environment,
 * so the same handler runs against the target MariaDB store on the NAS or an in-memory
 * store for local/dev. Firebase/Firestore is NOT an option here — it is retired.
 *
 *   ASP_STORE=mariadb  (or ASP_MARIADB_URL present)  -> MariaDB (self-hosted, NAS-backed)
 *   ASP_STORE=memory   (default when no DB configured) -> in-memory (dev/local only)
 *
 * `createStore` takes injectable `mysql` and `inMemoryFactory` so it is unit-testable
 * without a live database or the mysql2 dependency installed.
 */

"use strict";

const { createMariaDbStore } = require("./mariadb-store");

const VALID = new Set(["mariadb", "memory"]);

/** Decide the store kind from env. Pure. */
function chooseStoreKind(env = {}) {
  const explicit = String(env.ASP_STORE || "").trim().toLowerCase();
  if (explicit) {
    if (!VALID.has(explicit)) {
      throw new Error(`ASP_STORE must be one of ${[...VALID].join(", ")}; got ${explicit}`);
    }
    return explicit;
  }
  return env.ASP_MARIADB_URL ? "mariadb" : "memory";
}

/**
 * Build the store for a kind.
 * @param {object} opts
 * @param {string} opts.kind             "mariadb" | "memory"
 * @param {object} opts.env
 * @param {object} [opts.mysql]          mysql2/promise-like: createPool(url) -> pool
 * @param {Function} [opts.inMemoryFactory]  () -> in-memory db (for memory kind / tests)
 * @returns {{db: object, describe: string, close: Function}}
 */
function createStore(opts = {}) {
  const { kind, env = {}, mysql, inMemoryFactory } = opts;
  if (kind === "mariadb") {
    const url = env.ASP_MARIADB_URL;
    if (!url) throw new Error("ASP_STORE=mariadb requires ASP_MARIADB_URL");
    const driver = mysql || require("mysql2/promise");
    const pool = driver.createPool(url);
    return {
      db: createMariaDbStore({ pool }),
      describe: "mariadb (self-hosted, NAS-backed)",
      close: () => (pool.end ? pool.end() : undefined),
    };
  }
  if (kind === "memory") {
    const factory = inMemoryFactory || require("../testkit/inmemory-firestore").createInMemoryFirestore;
    return { db: factory(), describe: "in-memory (dev/local only)", close: () => {} };
  }
  throw new Error(`unknown store kind: ${kind}`);
}

module.exports = { chooseStoreKind, createStore, VALID };
