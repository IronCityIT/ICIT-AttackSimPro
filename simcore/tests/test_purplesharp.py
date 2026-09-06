"""Tests for the Windows endpoint attack simulation report adapter."""

import json
import tempfile
import unittest
from pathlib import Path

from simcore import evidence, runner
from simcore.adapters import registry
from simcore.adapters.purplesharp import PurpleSharpAdapter
from simcore.remediation import guidance_for

FIXTURE = Path(__file__).parent / "fixtures" / "purplesharp_report.json"


def load():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class TestPurpleSharpAdapter(unittest.TestCase):
    def setUp(self):
        self.data = load()
        self.findings = PurpleSharpAdapter().parse(self.data)

    def _by_tid(self, tid):
        return next(f for f in self.findings if f.attack[0] == tid)

    def test_only_simulated_become_findings(self):
        # Simulated+mapped: T1003.001, T1059.001, T1021.002, T1057, T1071 (navigator).
        # T1055 failed, T1490 navigator-disabled, no-id marker -> excluded.
        tids = sorted(f.attack[0] for f in self.findings)
        self.assertEqual(tids, ["T1003.001", "T1021.002", "T1057", "T1059.001", "T1071"])

    def test_failed_simulation_not_reported(self):
        self.assertFalse(any(f.attack[0] == "T1055" for f in self.findings))

    def test_navigator_disabled_not_reported(self):
        self.assertFalse(any(f.attack[0] == "T1490" for f in self.findings))

    def test_no_technique_id_skipped(self):
        self.assertTrue(all(f.attack[0] for f in self.findings))

    def test_supplied_tactic_wins(self):
        self.assertEqual(self._by_tid("T1003.001").evidence["tactic"], "credential access")
        self.assertEqual(self._by_tid("T1003.001").severity, "high")

    def test_tactic_fallback_by_base_technique(self):
        # No tactic supplied; T1021.002 -> base T1021 -> lateral-movement (high).
        self.assertEqual(self._by_tid("T1021.002").evidence["tactic"], "lateral-movement")
        self.assertEqual(self._by_tid("T1021.002").severity, "high")
        # T1057 -> discovery (medium); T1059.001 -> base T1059 -> execution (medium).
        self.assertEqual(self._by_tid("T1057").severity, "medium")
        self.assertEqual(self._by_tid("T1059.001").evidence["tactic"], "execution")

    def test_navigator_shape_simulated(self):
        self.assertEqual(self._by_tid("T1071").evidence["tactic"], "command-and-control")
        self.assertEqual(self._by_tid("T1071").severity, "high")

    def test_host_captured(self):
        self.assertEqual(self._by_tid("T1003.001").evidence["host"], "WIN-DC01")
        self.assertEqual(self._by_tid("T1057").evidence["host"], "WIN-WKS01")

    def test_remediation_key_set_and_resolvable(self):
        for f in self.findings:
            self.assertEqual(f.remediation_key, "endpoint-technique-undetected")
        self.assertEqual(guidance_for("endpoint-technique-undetected")["priority"], "High")

    def test_white_label_no_tool_name(self):
        blob = json.dumps([f.to_dict() for f in self.findings]).lower()
        self.assertNotIn("purplesharp", blob)
        self.assertNotIn("purple sharp", blob)

    def test_coverage(self):
        cov = PurpleSharpAdapter().coverage(self.data)
        self.assertEqual(cov["simulated"], 5)
        self.assertEqual(cov["failed"], 2)   # T1055 failed + T1490 navigator-disabled
        self.assertEqual(cov["tactics"], {
            "credential access": 1, "execution": 1, "lateral-movement": 1,
            "discovery": 1, "command-and-control": 1})

    def test_top_level_list_shape(self):
        self.assertEqual(len(PurpleSharpAdapter().parse(self.data["techniques"])), 5)

    def test_results_key_shape(self):
        self.assertEqual(len(PurpleSharpAdapter().parse({"results": self.data["techniques"]})), 5)

    def test_bad_report_rejected(self):
        with self.assertRaises(ValueError):
            PurpleSharpAdapter().parse("not-json-structure")

    def test_unrecognized_outcome_not_a_finding(self):
        data = {"techniques": [{"technique_id": "T1059", "outcome": "queued"}]}
        self.assertEqual(PurpleSharpAdapter().parse(data), [])


class TestPurpleSharpRegistryAndPipeline(unittest.TestCase):
    def test_registered(self):
        self.assertIn("purplesharp", registry.discover())

    def test_catalog_entry_white_label(self):
        entry = next(a for a in registry.catalog() if a["name"] == "purplesharp")
        self.assertNotIn("purplesharp", (entry["title"] + entry["description"]).lower())
        self.assertEqual(entry["title"], "Endpoint Attack Simulation")

    def test_ingest_pipeline_bundle(self):
        adapter = PurpleSharpAdapter()
        findings = adapter.parse(load())
        run_doc = runner.build_ingest_run(
            findings, client_name="Acme Corp", scan_id="endpoint-op-1",
            scan_type="endpoint-attack-simulation", source="purplesharp",
            coverage=adapter.coverage(load()))
        self.assertEqual(run_doc["summary"]["high_count"], 3)
        self.assertEqual(run_doc["summary"]["medium_count"], 2)
        with tempfile.TemporaryDirectory() as t:
            runner.write_evidence_bundle(run_doc, t)
            ok, problems = evidence.verify_bundle(t)
            self.assertTrue(ok, problems)


if __name__ == "__main__":
    unittest.main()
