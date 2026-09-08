"""Tests for the endpoint atomic-test (Atomic Red Team) execution-log adapter."""

import json
import tempfile
import unittest
from pathlib import Path

from simcore import evidence, runner
from simcore.adapters import registry
from simcore.adapters.atomic import AtomicAdapter
from simcore.remediation import guidance_for

FIXTURE = Path(__file__).parent / "fixtures" / "atomic_report.json"


def load():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class TestAtomicAdapter(unittest.TestCase):
    def setUp(self):
        self.data = load()
        self.findings = AtomicAdapter().parse(self.data)

    def _by_tid(self, tid):
        return next(f for f in self.findings if f.attack[0] == tid)

    def test_only_executed_become_findings(self):
        # Executed+mapped: T1059.001, T1003.001, T1021.002, T1486, T1082 (outcome success).
        # T1055 (exit 1), T1057 (error) excluded; no-tid marker skipped.
        self.assertEqual(sorted(f.attack[0] for f in self.findings),
                         ["T1003.001", "T1021.002", "T1059.001", "T1082", "T1486"])

    def test_nonzero_exit_not_reported(self):
        self.assertFalse(any(f.attack[0] == "T1055" for f in self.findings))

    def test_error_outcome_not_reported(self):
        self.assertFalse(any(f.attack[0] == "T1057" for f in self.findings))

    def test_supplied_tactic_wins(self):
        self.assertEqual(self._by_tid("T1003.001").evidence["tactic"], "credential access")
        self.assertEqual(self._by_tid("T1003.001").severity, "high")

    def test_tactic_fallback_and_severity(self):
        self.assertEqual(self._by_tid("T1486").severity, "critical")      # impact
        self.assertEqual(self._by_tid("T1021.002").severity, "high")      # lateral-movement
        self.assertEqual(self._by_tid("T1059.001").evidence["tactic"], "execution")
        self.assertEqual(self._by_tid("T1082").severity, "medium")        # discovery

    def test_test_name_and_host_captured(self):
        f = self._by_tid("T1003.001")
        self.assertEqual(f.evidence["test_name"], "Dump LSASS with comsvcs.dll")
        self.assertEqual(f.evidence["host"], "WIN-DC01")

    def test_remediation_key_reused_and_resolvable(self):
        for f in self.findings:
            self.assertEqual(f.remediation_key, "endpoint-technique-undetected")
        self.assertEqual(guidance_for("endpoint-technique-undetected")["priority"], "High")

    def test_white_label_no_tool_name(self):
        blob = json.dumps([f.to_dict() for f in self.findings]).lower()
        for bad in ("atomic red team", "invoke-atomic", "redcanary", "red canary"):
            self.assertNotIn(bad, blob)

    def test_coverage(self):
        cov = AtomicAdapter().coverage(self.data)
        self.assertEqual(cov["executed"], 5)
        self.assertEqual(cov["failed"], 2)
        self.assertEqual(cov["techniques"],
                         {"T1059.001": 1, "T1003.001": 1, "T1021.002": 1, "T1486": 1, "T1082": 1})

    def test_top_level_list_and_results_key(self):
        self.assertEqual(len(AtomicAdapter().parse(self.data["atomics"])), 5)
        self.assertEqual(len(AtomicAdapter().parse({"results": self.data["atomics"]})), 5)

    def test_bad_report_rejected(self):
        with self.assertRaises(ValueError):
            AtomicAdapter().parse("not-json-structure")


class TestAtomicRegistryAndPipeline(unittest.TestCase):
    def test_registered(self):
        self.assertIn("atomic", registry.discover())

    def test_catalog_entry_white_label(self):
        entry = next(a for a in registry.catalog() if a["name"] == "atomic")
        blob = (entry["title"] + entry["description"]).lower()
        self.assertNotIn("atomic red team", blob)
        self.assertNotIn("invoke-atomic", blob)
        self.assertEqual(entry["title"], "Endpoint Technique Emulation")

    def test_ingest_pipeline_bundle(self):
        adapter = AtomicAdapter()
        findings = adapter.parse(load())
        run_doc = runner.build_ingest_run(
            findings, client_name="Acme Corp", scan_id="atomic-op-1",
            scan_type="endpoint-technique-emulation", source="atomic",
            coverage=adapter.coverage(load()))
        self.assertEqual(run_doc["summary"]["critical_count"], 1)
        self.assertEqual(run_doc["summary"]["high_count"], 2)
        self.assertEqual(run_doc["summary"]["medium_count"], 2)
        with tempfile.TemporaryDirectory() as t:
            runner.write_evidence_bundle(run_doc, t)
            ok, problems = evidence.verify_bundle(t)
            self.assertTrue(ok, problems)


if __name__ == "__main__":
    unittest.main()
