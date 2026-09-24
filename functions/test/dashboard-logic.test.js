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
      click() {},
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
    URL: Object.assign(function (...a) { return new URL(...a); },
      { createObjectURL: () => "blob:test" }),
    Blob: function (parts) { sandbox.__lastBlob = parts; },
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

test("finding checkbox cannot be broken out of by a hostile title (no inline onclick)", async () => {
  const evil = "evil');alert(1);//";
  const scans = [
    { scan_id: "s1", target: "t", summary: { high_count: 1 },
      findings: [{ title: evil, detail: "d", severity: "high", attack: ["T1003"],
                   evidence: { tactic: "credential-access" } }] },
  ];
  const { elements } = loadDashboard({ search: "?client=acme-corp", scans });
  await new Promise((r) => setTimeout(r, 30));
  const html = elements.get("findings-list")._html;
  // The remediation toggle no longer embeds the title in an inline onclick JS string.
  assert.ok(!html.includes("toggleRemediatedItem(this,"), "no inline onclick embedding the key");
  // The raw breakout sequence (with a literal quote) must not appear anywhere — every
  // quote is HTML-entity-encoded, so it can never terminate a JS string / attribute.
  assert.ok(!html.includes("');alert(1)"), "no unescaped breakout sequence");
  // The key is carried safely as an escaped data attribute instead.
  assert.ok(html.includes("data-finding-key="), "key carried as a data attribute");
});

test("hostile severity/target from ingested findings cannot inject markup", async () => {
  // Findings are stored verbatim by the ingest handler, so severity/target are
  // untrusted. Previously both were interpolated raw into innerHTML (stored XSS).
  const scans = [
    { scan_id: "s1", target: "t", summary: { high_count: 1 },
      findings: [{ title: "F", detail: "d",
                   severity: 'high"><img src=x onerror=alert(1)>',
                   target: "<script>alert(2)</script>", attack: ["T1003"],
                   evidence: { tactic: "credential-access" } }] },
  ];
  const { elements } = loadDashboard({ search: "?client=acme-corp", scans });
  await new Promise((r) => setTimeout(r, 30));
  const html = elements.get("findings-list")._html;
  assert.ok(!html.includes("<img src=x"), "severity markup not injected");
  assert.ok(!html.includes("<script>alert(2)"), "target markup not injected");
  assert.ok(html.includes("&lt;script&gt;alert(2)&lt;/script&gt;"), "target shown encoded");
  // An unknown severity is normalised to a known class, never echoed into class=.
  assert.ok(/severity-badge severity-info"/.test(html), "unknown severity -> info");
});

test("findings do not display hardcoded AI model names (white-label, no fabrication)", async () => {
  const scans = [
    { scan_id: "s1", target: "t", summary: { high_count: 1 },
      findings: [{ title: "F", detail: "d", severity: "high", attack: ["T1003"],
                   evidence: { tactic: "credential-access" } }] },
  ];
  const { elements } = loadDashboard({ search: "?client=acme-corp", scans });
  await new Promise((r) => setTimeout(r, 30));
  const html = elements.get("findings-list")._html;
  assert.ok(!/Gemini|Claude|GPT-4o|Llama|\+6 more/.test(html),
    "no hardcoded model list shown when the consensus contract carries none");
});

test("CSV export escapes quotes and neutralises spreadsheet formulas", async () => {
  const scans = [
    { scan_id: "s1", target: "t", summary: { high_count: 1 },
      findings: [{ title: '=HYPERLINK("http://evil","x")', detail: "d", severity: "high",
                   target: '@SUM(1)', attack: ["T1003"],
                   evidence: { tactic: "credential-access" } }] },
  ];
  const { sandbox } = loadDashboard({ search: "?client=acme-corp", scans });
  await new Promise((r) => setTimeout(r, 30));
  sandbox.exportFindings();
  const csv = sandbox.__lastBlob.join("");
  const row = csv.split("\n")[1];
  // RFC 4180 quote doubling + a leading apostrophe so =,+,-,@ cells stay text.
  assert.ok(row.startsWith(`"'=HYPERLINK(""http://evil"",""x"")"`), row);
  assert.ok(row.includes(`"'@SUM(1)"`), "target formula neutralised");
});

test("static page names no third-party AI models and claims no fixed model count", () => {
  // The banner previously hardcoded ten vendor models, each marked "Active", that did not
  // match the consensus-engine roster and were never checked. The live badge (real
  // total_models/successful_models) is the only model-count surface.
  const html = fs.readFileSync(path.join(__dirname, "..", "..", "public", "index.html"), "utf8");
  assert.ok(!/gemini|claude|gpt-?4|llama|groq|mistral|qwen|deepseek|gemma/i.test(html),
    "no AI vendor/model names on the client-facing page");
  assert.ok(!/10-Model|10 AI models/.test(html), "no hardcoded model count");
});
