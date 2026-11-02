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

const { buildRecord } = require("./record");

if (!getApps().length) initializeApp();
const db = getFirestore();

const REGION = "us-east5";

exports.storeScanResults = onRequest(
  { region: REGION, cors: false },
  async (req, res) => {
    if (req.method !== "POST") {
      res.status(405).json({ error: "method_not_allowed" });
      return;
    }

    const body = req.body || {};
    // Validation and the stored shape live in record.js, where they are tested.
    // Per-finding AI analysis is carried inside findings[]; the scan-level
    // outcome (success / unavailable / not_required) in consensus.
    const built = buildRecord(body);
    if (built.error) {
      res.status(400).json({ error: built.error });
      return;
    }
    const { clientId, scanId } = built;
    const record = { ...built.record, created_at: FieldValue.serverTimestamp() };

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
