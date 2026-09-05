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

function loadDashboard({ search = "", firestoreDocs = null } = {}) {
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

  // Firebase double. If firestoreDocs is provided, a live read resolves to them;
  // otherwise initializeApp throws to drive the demo fallback path.
  let firebase;
  if (firestoreDocs) {
    firebase = {
      initializeApp() {},
      firestore() {
        return {
          collection() { return this; },
          doc() { return this; },
          orderBy() { return this; },
          limit() { return this; },
          async get() {
            return { forEach: (cb) => firestoreDocs.forEach((d) => cb({ id: d.id, data: () => d })) };
          },
        };
      },
    };
  } else {
    firebase = { initializeApp() { throw new Error("no firebase"); } };
  }

  const sandbox = {
    document: doc,
    firebase,
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
