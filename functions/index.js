/**
 * Iron City AttackSimPro — Cloud Functions
 *
 * storeScanResults: ingest endpoint for the offensive-scan workflows.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * A storeScanResults function is already deployed to `ironcity-attacksimpro` and
 * has no source anywhere in this repository. It was built live on the project and
 * has drifted from the contract its callers actually send: every workflow here
 * POSTs `scan_id`, `client_id` and `target_url`, and the deployed function writes
 * a fixed shape that keeps none of them —
 *
 *     keys: findings, scan_type, source, status, summary, target_url, timestamp, tool
 *     target_url: "Multiple targets"   (the real target discarded)
 *     scan_id:    absent
 *     client_id:  absent
 *
 * A scan that cannot be attributed to a client is a multi-tenant failure, and a
 * scan that cannot be found by its scan_id cannot be verified end to end. This is
 * the source that makes the deployed function correct, written to the same
 * contract threat-inspector already implements.
 *
 * Region: us-east5 (Columbus) — ICIT standard, no exceptions.
 * Partitioning: clients/{client_id}/scans/{scan_id}.
 */

const { onRequest } = require("firebase-functions/v2/https");
const logger = require("firebase-functions/logger");
const { initializeApp, getApps } = require("firebase-admin/app");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");

if (!getApps().length) initializeApp();
const db = getFirestore();

const REGION = "us-east5";

/** Normalize a client name into a stable, path-safe client_id slug. */
function toClientId(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

exports.storeScanResults = onRequest(
  { region: REGION, cors: false },
  async (req, res) => {
    if (req.method !== "POST") {
      res.status(405).json({ error: "method_not_allowed" });
      return;
    }

    const body = req.body || {};
    const clientId = toClientId(body.client_id || body.client_name);
    const scanId = String(body.scan_id || "").trim();

    // Both are required. The deployed function defaulted them away, which is how
    // an unattributable scan came to look like a successful one.
    if (!clientId) {
      res.status(400).json({ error: "client_id (or client_name) is required" });
      return;
    }
    if (!scanId) {
      res.status(400).json({ error: "scan_id is required" });
      return;
    }

    const record = {
      client_id: clientId,
      client_name: body.client_name || null,
      scan_id: scanId,
      scan_type: body.scan_type || "unknown",
      // The target the caller actually scanned. The deployed function wrote the
      // literal "Multiple targets" here regardless of what was sent.
      target: body.target || body.target_url || null,
      status: body.status || "completed",
      summary: body.summary || {},
      findings: Array.isArray(body.findings) ? body.findings : [],
      consensus: body.consensus || null,
      error: body.error || null,
      created_at: FieldValue.serverTimestamp(),
    };

    try {
      const ref = db
        .collection("clients")
        .doc(clientId)
        .collection("scans")
        .doc(scanId);

      // Status is monotonic: a scan that already stored findings must never be
      // downgraded to "failed". The workflows report failure whenever ANY job in
      // the run failed, which includes a run whose scan succeeded and whose
      // downstream analysis did not — that run has already written real findings.
      if (record.status === "failed") {
        const existing = await ref.get();
        if (existing.exists && existing.get("status") === "completed") {
          await ref.set(
            { error: body.error || { message: "a stage of this run failed" } },
            { merge: true }
          );
          logger.warn("failure report ignored — scan already completed", {
            client_id: clientId,
            scan_id: scanId,
          });
          res
            .status(200)
            .json({ status: "already_completed", client_id: clientId, scan_id: scanId });
          return;
        }
      }

      await ref.set(record, { merge: true });

      logger.info("stored scan result", {
        client_id: clientId,
        scan_id: scanId,
        scan_type: record.scan_type,
        findings: record.findings.length,
      });

      res.status(200).json({ status: "stored", client_id: clientId, scan_id: scanId });
    } catch (err) {
      logger.error("failed to store scan result", err);
      res.status(500).json({ error: "store_failed" });
    }
  }
);
