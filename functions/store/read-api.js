/**
 * Tenant-scoped, fail-closed Read API for the dashboard (replaces the Firestore Web SDK
 * read path). Serves a client its OWN scans only:
 *
 *   GET /clients/{client_id}/scans           -> { client_id, scans:[...] }
 *   GET /clients/{client_id}/scans/{scan_id} -> a scan with findings
 *
 * SAFE BY CONSTRUCTION:
 *   * `authorize(req) -> {client_id, role} | null` is INJECTED. The default denies every
 *     request (returns null -> 401), so an unconfigured deployment exposes nothing. The
 *     real strategy (Auth0 Organizations -> a token carrying client_id + role) is wired by
 *     provisioning, not guessed here.
 *   * the path's client_id must equal the authorized principal's client_id, else 403 — a
 *     caller can never read another tenant even with a valid token.
 *   * the data layer (scan-repository.js) always scopes every query to client_id.
 */

"use strict";

const { listScans, getScan } = require("./scan-repository");

const PATH_RE = /^\/clients\/([^/]+)\/scans(?:\/([^/]+))?\/?$/;

function createReadHandler(opts = {}) {
  const pool = opts.pool;
  if (!pool || typeof pool.query !== "function") {
    throw new Error("createReadHandler: a pool with query(sql, params) is required");
  }
  // Fail-closed default: no authorizer configured => nobody is authorized.
  const authorize = typeof opts.authorize === "function" ? opts.authorize : () => null;

  return async function readHandler(req, res) {
    if (req.method !== "GET") {
      res.status(405).json({ error: "method_not_allowed" });
      return;
    }
    const path = (req.path || (req.url || "/").split("?")[0]);
    const m = PATH_RE.exec(path);
    if (!m) {
      res.status(404).json({ error: "not_found" });
      return;
    }

    let principal = null;
    try {
      principal = await authorize(req);
    } catch {
      principal = null;
    }
    if (!principal || !principal.client_id) {
      res.status(401).json({ error: "unauthorized" });
      return;
    }

    const pathClient = decodeURIComponent(m[1]);
    // Tenant isolation: a principal may only read their own tenant.
    if (pathClient !== principal.client_id) {
      res.status(403).json({ error: "forbidden" });
      return;
    }

    try {
      if (m[2]) {
        const scan = await getScan(pool, principal.client_id, decodeURIComponent(m[2]));
        if (!scan) {
          res.status(404).json({ error: "scan_not_found" });
          return;
        }
        res.status(200).json(scan);
      } else {
        const q = req.query || {};
        const scans = await listScans(pool, principal.client_id, {
          limit: q.limit,
          withFindings: q.include === "findings",
        });
        res.status(200).json({ client_id: principal.client_id, scans });
      }
    } catch (err) {
      res.status(500).json({ error: "read_failed" });
    }
  };
}

module.exports = { createReadHandler, PATH_RE };
