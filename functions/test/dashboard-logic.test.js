"use strict";

// Exercises the REAL dashboard application script (public/index.html) in a
// sandboxed VM with minimal DOM/Firebase stubs, so the client-side logic —
// compliance mapping, remediation lookup, risk-score math, demo fallback and
// the corrected target-field resolution — is covered without a browser.

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function loadDashboard({ search = "", firestoreDocs = null, scans } = {}) {
  const html = fs.readFileSync(
    path.join(__dirname, "..", "..", "public", "index.html"),
    "utf8"
  );
  const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
  const app = scripts[scripts.length - 1];

  // Element double that records the last textContent/innerHTML written.
  const elements = new Map();
  function fakeEl() {
    const el = {
      _text: "",
      _html: "",
      className: "",
      style: {},
      classList: { add() {}, remove() {}, contains() { return false; }, toggle() {} },
      previousElementSibling: null,
      set textContent(v) { this._text = String(v); },
      get textContent() { return this._text; },
      set innerHTML(v) { this._html = String(v); },
      get innerHTML() { return this._html; },
      querySelector() { return fakeEl(); },
      getContext() { return {}; },
      closest() { return fakeEl(); },
      appendChild() {},
    };
    return el;
  }
  const doc = {
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, fakeEl());
      return elements.get(id);
    },
    createElement() { return fakeEl(); },
    querySelectorAll() { return []; },
    body: { appendChild() {} },
  };

  // Read API (fetch) double. `scans` (or the legacy `firestoreDocs` alias) is what a live
  // GET /clients/{cid}/scans resolves to; `null` simulates an unauthorized read (401),
  // which drives the demo fallback. Non-/clients fetches (catalog.json) 404 as in a bare
  // test env.
  const scanData = scans !== undefined ? scans : firestoreDocs;
  const fetch = async (url) => {
    const u = String(url);
    if (u.includes("/clients/")) {
      if (scanData == null) return { ok: false, status: 401, async json() { return {}; } };
      const cid = decodeURIComponent((u.match(/\/clients\/([^/?]+)/) || [])[1] || "");
      return { ok: true, status: 200, async json() { return { client_id: cid, scans: scanData }; } };
    }
    if (u.includes("remediation.json")) {
      return { ok: true, status: 200, async json() {
        return { version: 1, catalog: {
          "missing-hsts": { title: "Strict-Transport-Security not enforced",
            impact: "HSTS impact from the shared catalog.",
            steps: ["CATALOG-STEP: send the HSTS header"],
            priority: "High", effort: "Low", frameworks: ["PCI 4.1"] },
        } };
      } };
    }
    return { ok: false, status: 404, async json() { return {}; } };
  };

  const sandbox = {
    document: doc,
    fetch,
    Chart: function () { return { destroy() {} }; },
    localStorage: { getItem: () => null, setItem() {} },
    location: { search },
    URLSearchParams,
    URL,
    Blob: function () {},
    console: { info() {}, warn() {}, log() {}, error() {} },
    setTimeout,
  };
  // const/let bindings live in the script's lexical scope, not on the context
  // global. Append a closure accessor so tests can read their live values.
  const instrumented =
    app + "\n;globalThis.__state=function(){return {CLIENT_ID:CLIENT_ID,allFindings:allFindings};};";
  vm.createContext(sandbox);
  vm.runInContext(instrumented, sandbox);
  return { sandbox, elements, state: () => sandbox.__state() };
}

test("compliance mapping resolves known finding categories", () => {
  const { sandbox } = loadDashboard();
  assert.ok(sandbox.getComplianceTags("SQL Injection").includes("OWASP A03"));
  assert.ok(sandbox.getComplianceTags("Missing HSTS").includes("PCI 4.1"));
  // Unknown finding gets the documented default, never empty.
  const dflt = [...sandbox.getComplianceTags("something novel")];
  assert.deepEqual(dflt, ["NIST ID.RA-1"]);
});

test("remediation lookup returns actionable guidance", () => {
  const { sandbox } = loadDashboard();
  const hsts = sandbox.getRemediation("Missing HSTS");
  assert.equal(hsts.priority, "High");
  assert.ok(hsts.steps.length > 0);
  assert.ok(hsts.code.includes("Strict-Transport-Security"));
  // Fallback remediation for an unknown finding.
  assert.equal(sandbox.getRemediation("mystery").priority, "Medium");
});

test("demo fallback populates findings when no client is selected", () => {
  const { state } = loadDashboard({ search: "" });
  assert.equal(state().CLIENT_ID, "");
  assert.equal(state().allFindings.length, 8);
});

test("client id is parsed from the query string", () => {
  const { state } = loadDashboard({ search: "?client=acme-corp", firestoreDocs: [] });
  assert.equal(state().CLIENT_ID, "acme-corp");
});

test("live read maps stored records (target field) into findings", async () => {
  const docs = [
    {
      id: "scan-1",
      target: "https://acme.example",
      created_at: "2026-09-04T00:00:00Z",
      summary: { high_count: 1, medium_count: 2 },
      findings: [
        { name: "Missing HSTS", risk: "medium" },
        { name: "SQL Injection", risk: "critical" },
      ],
    },
  ];
  const { state } = loadDashboard({ search: "?client=acme-corp", firestoreDocs: docs });
  // loadDashboard() is async inside the script; let its promise settle.
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(state().allFindings.length, 2);
  // The corrected contract: target comes from the scan's `target` field.
  assert.equal(state().allFindings[0].target, "https://acme.example");
});

test("dashboard falls back to demo when the Read API denies (401)", async () => {
  // scans:null => the Read API stub returns 401 -> the dashboard shows demo data.
  const { state } = loadDashboard({ search: "?client=acme-corp", scans: null });
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(state().CLIENT_ID, "acme-corp");
  assert.equal(state().allFindings.length, 8); // demo set, not a live read
});
test("ATT&CK coverage panel aggregates live findings by technique", async () => {
  const scans = [
    {
      scan_id: "s1", target: "https://acme.example",
      summary: { high_count: 2, medium_count: 1 },
      findings: [
        { name: "Undetected Technique", severity: "high", attack: ["T1003"],
          evidence: { tactic: "credential-access" } },
        { name: "Undetected Technique", severity: "high", attack: ["T1003"],
          evidence: { tactic: "credential-access" } },
        { name: "Lateral Movement", severity: "medium", attack: ["T1021"],
          evidence: { tactic: "lateral-movement" } },
      ],
    },
  ];
  const { elements } = loadDashboard({ search: "?client=acme-corp", scans });
  await new Promise((r) => setTimeout(r, 20));
  const grid = elements.get("attack-grid");
  const meta = elements.get("attack-meta");
  // Two unique techniques (T1003 counted 2x, T1021 once), two tactics.
  assert.match(meta._text, /2 techniques/);
  assert.match(meta._text, /2 tactics/);
  assert.ok(grid._html.includes("T1003"));
  assert.ok(grid._html.includes("T1021"));
  assert.ok(grid._html.includes("credential-access"));
  // Output-encoded, no raw tool names.
  assert.ok(!/caldera|purplesharp/i.test(grid._html));
});

test("ATT&CK coverage panel is graceful when findings have no technique ids", async () => {
  // Demo/no-client path -> demo findings (no `attack`) -> panel shows the empty message.
  const { elements } = loadDashboard({ search: "" });
  await new Promise((r) => setTimeout(r, 20));
  const grid = elements.get("attack-grid");
  assert.ok(grid._html.includes("No ATT&CK-mapped techniques"));
});

test("dashboard renders engine-shaped findings (title/detail, no name) as live data", async () => {
  // Real Read-API findings use `title`/`detail`/`severity` and carry NO `name`.
  // Regression: previously getRemediation(undefined) threw -> demo fallback, so the client
  // saw demo data instead of their scan. The list must now show the real titles.
  const scans = [
    {
      scan_id: "s1", target: "https://acme.example",
      summary: { high_count: 1, medium_count: 1 },
      findings: [
        { title: "Missing HSTS", detail: "Strict-Transport-Security not set",
          severity: "high", attack: ["T1190"], evidence: { tactic: "initial-access" },
          remediation_key: "missing-hsts" },
        { title: "Undetected Technique: LSASS", detail: "cred dump", severity: "high",
          attack: ["T1003"], evidence: { tactic: "credential-access" } },
      ],
    },
  ];
  const { state, elements } = loadDashboard({ search: "?client=acme-corp", scans });
  await new Promise((r) => setTimeout(r, 20));
  // LIVE, not demo: exactly the two ingested findings (demo set is 8).
  assert.equal(state().allFindings.length, 2);
  const list = elements.get("findings-list");
  assert.ok(list._html.includes("Missing HSTS"), "real title rendered");
  assert.ok(!list._html.includes("Unknown Finding"), "no unknown-finding placeholder");
  // Compliance mapping resolves from the title (Missing HSTS -> a real mapping, not default).
  assert.ok(list._html.includes("compliance-tag"), "compliance tags rendered");
});

test("dashboard remediation prefers the finding's remediation_key -> shared catalog", async () => {
  const scans = [
    {
      scan_id: "s1", target: "https://acme.example", summary: { high_count: 1 },
      findings: [
        { title: "Strict-Transport-Security not enforced", detail: "no hsts",
          severity: "high", remediation_key: "missing-hsts", attack: ["T1071"],
          evidence: { tactic: "command-and-control" } },
      ],
    },
  ];
  const { elements } = loadDashboard({ search: "?client=acme-corp", scans });
  await new Promise((r) => setTimeout(r, 30));
  const list = elements.get("findings-list");
  // The remediation panel shows the CATALOG steps (resolved by remediation_key), not a
  // fuzzy inline-DB match.
  assert.ok(list._html.includes("CATALOG-STEP: send the HSTS header"),
    "catalog remediation step rendered via remediation_key");
});

test("consensus display is honest: real counts when present, no fabricated claim", async () => {
  const scans = [
    {
      scan_id: "s1", target: "https://acme.example", summary: { high_count: 1 },
      consensus: [
        { consensus_severity: "HIGH", confidence_percent: 82, total_models: 10,
          successful_models: 8, failed_models: 2 },
      ],
      findings: [
        { title: "Undetected Technique", detail: "d", severity: "high", attack: ["T1003"],
          evidence: { tactic: "credential-access" }, remediation_key: "missing-hsts" },
      ],
    },
  ];
  const { elements } = loadDashboard({ search: "?client=acme-corp", scans });
  await new Promise((r) => setTimeout(r, 30));
  const badge = elements.get("ai-engine-badge");
  const list = elements.get("findings-list");
  assert.match(badge._html, /8\/10 models responded/);
  assert.ok(list._html.includes("AI consensus engine"), "honest consensus note rendered");
  assert.ok(!/9\/10 models agree/.test(list._html), "no fabricated agreement claim");
});

test("consensus display is honest: neutral text when no consensus attached", async () => {
  const scans = [
    { scan_id: "s1", target: "t", summary: { high_count: 1 },
      findings: [{ title: "F", detail: "d", severity: "high", attack: ["T1003"],
                   evidence: { tactic: "credential-access" } }] },
  ];
  const { elements } = loadDashboard({ search: "?client=acme-corp", scans });
  await new Promise((r) => setTimeout(r, 30));
  const badge = elements.get("ai-engine-badge");
  const list = elements.get("findings-list");
  assert.match(badge._html, /Consensus not run/);
  assert.ok(list._html.includes("was not attached to this scan"), "neutral note");
  assert.ok(!/9\/10 models agree/.test(list._html), "no fabricated claim");
});
