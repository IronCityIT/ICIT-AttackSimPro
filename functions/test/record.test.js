// storeScanResults record contract: the consensus persists per finding, and no
// vendor identity reaches Firestore. Run: npm test (node --test).
const test = require("node:test");
const assert = require("node:assert/strict");
const { buildRecord, toClientId } = require("../record");

const analysedFinding = {
  id: "web-10038-1-0",
  name: "Content Security Policy (CSP) Header Not Set",
  severity: "medium",
  solution: "Ensure that your web server is configured to set the Content-Security-Policy header.",
  ai_status: "analysed",
  ai_analysis: {
    severity: "medium",
    remediation_steps: ["Deploy a Content-Security-Policy in report-only mode first"],
    verification_steps: ["Confirm the header is present on every response"],
    impact: "high",
    frameworks: ["SOC2", "PCI-DSS"],
    models_succeeded: 13,
    models_total: 15,
    model_responses: [{ model_name: "some-model", provider: "SomeVendor" }],
  },
};

const body = {
  scan_id: "triage-1",
  client_id: "Iron City",
  scan_type: "web-exposure-passive",
  target: "https://www.example.test",
  summary: { medium_count: 1 },
  findings: [analysedFinding, { id: "x", name: "Info", severity: "info", ai_status: "unavailable" }],
  consensus: { status: "success", findings_analysed: 1, models_succeeded: 13, models_total: 15, provider: "x" },
  timestamp: "2026-11-02T00:00:00Z",
};

test("per-finding AI analysis is stored with its finding", () => {
  const { record } = buildRecord(body);
  const csp = record.findings[0];
  assert.equal(csp.ai_status, "analysed");
  assert.deepEqual(csp.ai_analysis.remediation_steps, analysedFinding.ai_analysis.remediation_steps);
  assert.equal(csp.ai_analysis.models_succeeded, 13);
  assert.equal(csp.ai_analysis.models_total, 15);
  assert.equal(record.findings[1].ai_status, "unavailable");
  assert.equal(record.findings[1].ai_analysis, undefined);
});

test("scan-level consensus status and counts persist", () => {
  const { record } = buildRecord(body);
  assert.equal(record.consensus.status, "success");
  assert.equal(record.consensus.findings_analysed, 1);
  assert.equal(record.timestamp, "2026-11-02T00:00:00Z");
});

test("an unavailable analysis is stored as unavailable, not dropped", () => {
  const { record } = buildRecord({ ...body, consensus: { status: "unavailable", reason: "AI analysis did not complete (failure)" } });
  assert.equal(record.consensus.status, "unavailable");
});

test("vendor identity never reaches storage", () => {
  const { record } = buildRecord(body);
  const blob = JSON.stringify(record);
  for (const key of ["model_responses", "provider", "model_name", "SomeVendor"]) {
    assert.ok(!blob.includes(key), `${key} leaked into the record`);
  }
  assert.ok(body.findings[0].ai_analysis.model_responses, "the caller's object is not mutated");
});

test("partitioning keys are required and normalized", () => {
  assert.equal(buildRecord({ ...body, scan_id: "" }).error, "scan_id is required");
  assert.match(buildRecord({ ...body, client_id: "", client_name: "" }).error, /client_id/);
  const built = buildRecord(body);
  assert.equal(built.clientId, "iron-city");
  assert.equal(built.scanId, "triage-1");
  assert.equal(toClientId("  ACME Corp!! "), "acme-corp");
});

test("a non-object consensus is not stored", () => {
  assert.equal(buildRecord({ ...body, consensus: "success" }).record.consensus, null);
  assert.equal(buildRecord({ ...body, consensus: undefined }).record.consensus, null);
});
