/**
 * Build the Firestore record for one stored scan. Pure: no Firebase imports, so
 * the contract can be tested without an emulator (test/record.test.js).
 *
 * The per-finding AI analysis travels inside `findings[]` (each finding's
 * `ai_analysis` / `ai_status`) and the scan-level outcome in `consensus`; both
 * are kept as sent. The one thing removed is vendor identity: the workflows
 * already strip it (tools/asp_consensus.py), and this is the second line, so a
 * caller that forgets cannot put a provider or model name on a client surface.
 */

/** Keys that name the AI providers/models behind the consensus. */
const VENDOR_KEYS = new Set(["model_responses", "failed_model_details", "provider", "model_name"]);

/** Normalize a client name into a stable, path-safe client_id slug. */
function toClientId(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/** A deep copy of `value` with every vendor-identifying key removed. */
function stripVendors(value) {
  if (Array.isArray(value)) return value.map(stripVendors);
  if (value && typeof value === "object") {
    const out = {};
    for (const [key, inner] of Object.entries(value)) {
      if (!VENDOR_KEYS.has(key)) out[key] = stripVendors(inner);
    }
    return out;
  }
  return value;
}

/**
 * Validate a POST body and build the record to store.
 * @returns {{error: string}|{clientId: string, scanId: string, record: object}}
 */
function buildRecord(body) {
  body = body || {};
  const clientId = toClientId(body.client_id || body.client_name);
  const scanId = String(body.scan_id || "").trim();

  // Both are required. The deployed function defaulted them away, which is how
  // an unattributable scan came to look like a successful one.
  if (!clientId) return { error: "client_id (or client_name) is required" };
  if (!scanId) return { error: "scan_id is required" };

  const consensus =
    body.consensus && typeof body.consensus === "object" && !Array.isArray(body.consensus)
      ? stripVendors(body.consensus)
      : null;

  return {
    clientId,
    scanId,
    record: {
      client_id: clientId,
      client_name: body.client_name || null,
      scan_id: scanId,
      scan_type: body.scan_type || "unknown",
      // The target the caller actually scanned. The deployed function wrote the
      // literal "Multiple targets" here regardless of what was sent.
      target: body.target || body.target_url || null,
      status: body.status || "completed",
      summary: body.summary || {},
      findings: Array.isArray(body.findings) ? stripVendors(body.findings) : [],
      consensus,
      error: body.error || null,
      // The dashboard orders scans by this; the workflows send it in UTC.
      timestamp: body.timestamp || null,
    },
  };
}

module.exports = { buildRecord, toClientId, stripVendors };
