/**
 * Iron City AttackSimPro — Cloud Functions
 *
 * storeScanResults: ingest endpoint for the scan workflows. This file is a thin
 * production shell: it wires the real Firestore Admin SDK and the Cloud Functions
 * logger into the pure handler in `handler.js`, which holds all validation and
 * write logic. The handler is exercised directly by the unit tests and by the
 * local smoke server, so the exact code that runs in production is the code the
 * tests cover.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * A storeScanResults function was deployed to `ironcity-attacksimpro` with no
 * source in the repo. It had drifted from its callers' contract: it discarded
 * scan_id and client_id and wrote the literal "Multiple targets" as the target,
 * making scans unattributable and unverifiable. handler.js is the corrected
 * source, written to the same contract threat-inspector implements.
 *
 * Region: us-east5 (Columbus) — ICIT standard, no exceptions.
 * Partitioning: clients/{client_id}/scans/{scan_id}.
 */

"use strict";

const { onRequest } = require("firebase-functions/v2/https");
const logger = require("firebase-functions/logger");
const { initializeApp, getApps } = require("firebase-admin/app");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");

const { createStoreScanResultsHandler } = require("./handler");

if (!getApps().length) initializeApp();
const firestore = getFirestore();

const REGION = "us-east5";

// Adapter: give the handler a `serverTimestamp()` alongside the Firestore API it
// already expects (collection / doc / get / set), so the handler never imports
// firebase-admin itself.
const db = {
  collection: (...a) => firestore.collection(...a),
  serverTimestamp: () => FieldValue.serverTimestamp(),
};

const handler = createStoreScanResultsHandler({
  db,
  logger,
  // Optional shared-secret ingest gate. Off unless INGEST_TOKEN is provisioned,
  // so current callers are unaffected. See docs/SDLC_STATUS.md for the rollout.
  ingestToken: process.env.INGEST_TOKEN || "",
});

exports.storeScanResults = onRequest({ region: REGION, cors: false }, handler);
