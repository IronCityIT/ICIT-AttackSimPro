/**
 * Iron City AttackSimPro — storeScanResults request handler (pure, testable).
 *
 * This module contains ALL of the ingest logic with NO firebase-functions or
 * firebase-admin coupling. `index.js` injects the real Firestore + logger; the
 * unit tests and the local smoke server inject in-memory doubles. Keeping the
 * logic here is what makes the endpoint verifiable end to end without a deploy.
 *
 * Contract (what every workflow POSTs and what the dashboard reads back):
 *   clients/{client_id}/scans/{scan_id}
 *     client_id, client_name, scan_id, scan_type, target, status, summary,
 *     findings[], consensus, error, created_at, updated_at
 */

"use strict";

/** Firestore document hard limit is ~1 MiB; reject before we ever try to write. */
const MAX_BODY_BYTES = 1_000_000;

/** A single scan record must not carry an unbounded number of findings. */
const MAX_FINDINGS = 5000;

/** Statuses a caller is allowed to report. Anything else is a client error. */
const ALLOWED_STATUSES = new Set(["queued", "running", "completed", "failed"]);

/** Console-shaped fallback so the handler works with or without an injected logger. */
const CONSOLE_LOGGER = {
  info: (...a) => console.log(...a),
  warn: (...a) => console.warn(...a),
  error: (...a) => console.error(...a),
};

/** Normalize a client name into a stable, path-safe client_id slug. */
function toClientId(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/** A short, log-correlatable request id. Not security-sensitive. */
function newRequestId() {
  return (
    Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 8)
  );
}

/**
 * Estimate the byte size of an already-parsed body. onRequest parses JSON before
 * we see it, so we cannot inspect Content-Length reliably; re-serializing is the
 * honest measure of what we are about to persist.
 */
function approxByteLength(body) {
  try {
    return Buffer.byteLength(JSON.stringify(body || {}), "utf8");
  } catch {
    return Infinity; // circular / unserializable — refuse it
  }
}

/**
 * Build the storeScanResults handler.
 *
 * @param {object}   opts
 * @param {object}   opts.db           Firestore-like: collection(id).doc(id)...set/get
 * @param {object}  [opts.logger]      info/warn/error logger (defaults to console)
 * @param {string}  [opts.ingestToken] if set, callers MUST send X-Ingest-Token matching it
 * @param {number}  [opts.maxBodyBytes]
 * @returns {(req,res)=>Promise<void>}
 */
function createStoreScanResultsHandler(opts = {}) {
  const db = opts.db;
  if (!db) throw new Error("createStoreScanResultsHandler: db is required");
  const logger = opts.logger || CONSOLE_LOGGER;
  const ingestToken = opts.ingestToken || "";
  const maxBodyBytes = opts.maxBodyBytes || MAX_BODY_BYTES;

  return async function storeScanResults(req, res) {
    const requestId = newRequestId();
    res.setHeader?.("X-Request-Id", requestId);

    if (req.method === "GET" && (req.path === "/healthz" || req.url === "/healthz")) {
      res.status(200).json({ status: "ok", service: "storeScanResults" });
      return;
    }

    if (req.method !== "POST") {
      res.status(405).json({ error: "method_not_allowed", request_id: requestId });
      return;
    }

    // Optional shared-secret gate. Disabled unless an ingest token is provisioned,
    // so existing callers keep working; when set it rejects unauthenticated POSTs.
    if (ingestToken) {
      const provided = headerValue(req, "x-ingest-token");
      if (provided !== ingestToken) {
        logger.warn("rejected ingest: bad or missing token", { request_id: requestId });
        res.status(401).json({ error: "unauthorized", request_id: requestId });
        return;
      }
    }

    const body = req.body || {};

    if (typeof body !== "object" || Array.isArray(body)) {
      res.status(400).json({ error: "body must be a JSON object", request_id: requestId });
      return;
    }

    const size = approxByteLength(body);
    if (size > maxBodyBytes) {
      logger.warn("rejected ingest: payload too large", { request_id: requestId, size });
      res.status(413).json({
        error: "payload_too_large",
        max_bytes: maxBodyBytes,
        request_id: requestId,
      });
      return;
    }

    const clientId = toClientId(body.client_id || body.client_name);
    const scanId = String(body.scan_id || "").trim();

    // Both are required. The originally-deployed function defaulted them away,
    // which is how an unattributable scan came to look like a successful one.
    if (!clientId) {
      res.status(400).json({ error: "client_id (or client_name) is required", request_id: requestId });
      return;
    }
    if (!scanId) {
      res.status(400).json({ error: "scan_id is required", request_id: requestId });
      return;
    }
    if (!/^[A-Za-z0-9._:-]{1,200}$/.test(scanId)) {
      res.status(400).json({ error: "scan_id has an invalid format", request_id: requestId });
      return;
    }

    const status = body.status || "completed";
    if (!ALLOWED_STATUSES.has(status)) {
      res.status(400).json({
        error: "invalid status",
        allowed: [...ALLOWED_STATUSES],
        request_id: requestId,
      });
      return;
    }

    const findings = Array.isArray(body.findings) ? body.findings : [];
    if (findings.length > MAX_FINDINGS) {
      res.status(413).json({
        error: "too_many_findings",
        max_findings: MAX_FINDINGS,
        request_id: requestId,
      });
      return;
    }

    const now = db.serverTimestamp ? db.serverTimestamp() : new Date().toISOString();
    const record = {
      client_id: clientId,
      client_name: body.client_name || null,
      scan_id: scanId,
      scan_type: body.scan_type || "unknown",
      // The target the caller actually scanned. The originally-deployed function
      // wrote the literal "Multiple targets" here regardless of what was sent.
      target: body.target || body.target_url || null,
      status,
      summary: isPlainObject(body.summary) ? body.summary : {},
      findings,
      consensus: body.consensus || null,
      error: body.error || null,
      updated_at: now,
    };

    try {
      const ref = db
        .collection("clients")
        .doc(clientId)
        .collection("scans")
        .doc(scanId);

      const existing = await ref.get();

      // Status is monotonic: a scan that already stored findings must never be
      // downgraded to "failed". The workflows report failure whenever ANY job in
      // the run failed, which includes a run whose scan succeeded and whose
      // downstream analysis did not — that run has already written real findings.
      if (status === "failed" && existing.exists && existing.get("status") === "completed") {
        await ref.set(
          { error: body.error || { message: "a stage of this run failed" }, updated_at: now },
          { merge: true }
        );
        logger.warn("failure report ignored — scan already completed", {
          request_id: requestId,
          client_id: clientId,
          scan_id: scanId,
        });
        res.status(200).json({
          status: "already_completed",
          client_id: clientId,
          scan_id: scanId,
          request_id: requestId,
        });
        return;
      }

      // created_at is set once, on first write, and preserved thereafter.
      if (!existing.exists) record.created_at = now;

      await ref.set(record, { merge: true });

      logger.info("stored scan result", {
        request_id: requestId,
        client_id: clientId,
        scan_id: scanId,
        scan_type: record.scan_type,
        status,
        findings: findings.length,
      });

      res.status(200).json({
        status: "stored",
        client_id: clientId,
        scan_id: scanId,
        findings: findings.length,
        request_id: requestId,
      });
    } catch (err) {
      logger.error("failed to store scan result", { request_id: requestId, message: err && err.message });
      res.status(500).json({ error: "store_failed", request_id: requestId });
    }
  };
}

function isPlainObject(v) {
  return v != null && typeof v === "object" && !Array.isArray(v);
}

function headerValue(req, name) {
  if (typeof req.get === "function") return req.get(name) || "";
  const h = req.headers || {};
  return h[name] || h[name.toLowerCase()] || "";
}

module.exports = {
  createStoreScanResultsHandler,
  toClientId,
  approxByteLength,
  MAX_BODY_BYTES,
  MAX_FINDINGS,
  ALLOWED_STATUSES,
};
