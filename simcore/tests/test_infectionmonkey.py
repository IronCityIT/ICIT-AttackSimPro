"""Tests for the network BAS (Infection Monkey) report adapter."""

import json
import tempfile
import unittest
from pathlib import Path

from simcore import evidence, runner
from simcore.adapters import registry
from simcore.adapters.infectionmonkey import InfectionMonkeyAdapter
from simcore.remediation import guidance_for

FIXTURE = Path(__file__).parent / "fixtures" / "infectionmonkey_report.json"


def load():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class TestInfectionMonkeyAdapter(unittest.TestCase):
    def setUp(self):
        self.data = load()
        self.findings = InfectionMonkeyAdapter().parse(self.data)

    def _by_type(self, t):
        return [f for f in self.findings if f.evidence.get("type") == t]

    def test_only_successful_become_findings(self):
        # 5 successes: exploitation, segmentation, propagation, credential_reuse, technique.
        # 1 failed exploitation + 1 indeterminate (no success flag) excluded.
        self.assertEqual(len(self.findings), 5)

    def test_failed_event_not_reported(self):
        self.assertFalse(any(f.evidence.get("target") == "10.0.3.1" for f in self.findings))

    def test_indeterminate_event_skipped(self):
        self.assertFalse(any(f.evidence.get("target") == "10.0.9.9" for f in self.findings))

    def test_segmentation_finding(self):
        seg = self._by_type("segmentation")
        self.assertEqual(len(seg), 1)
        self.assertEqual(seg[0].severity, "high")
        self.assertEqual(seg[0].remediation_key, "network-segmentation-gap")
        self.assertIn("workstations", seg[0].title)
        self.assertIn("servers", seg[0].title)

    def test_lateral_movement_high_severity(self):
        expl = self._by_type("exploitation")[0]
        self.assertEqual(expl.severity, "high")      # lateral-movement
        self.assertEqual(expl.attack, ("T1210",))
        self.assertEqual(expl.remediation_key, "network-propagation-unprevented")

    def test_credential_reuse_tactic(self):
        cr = self._by_type("credential_reuse")[0]
        self.assertEqual(cr.severity, "high")        # credential-access
        self.assertEqual(cr.attack, ("T1078",))

    def test_supplied_tactic_wins(self):
        tech = self._by_type("technique")[0]
        self.assertEqual(tech.evidence["tactic"], "discovery")
        self.assertEqual(tech.severity, "medium")

    def test_remediation_keys_resolvable(self):
        self.assertEqual(guidance_for("network-propagation-unprevented")["priority"], "High")
        self.assertEqual(guidance_for("network-segmentation-gap")["frameworks"][0], "NIST SC-7")

    def test_white_label_no_tool_name(self):
        blob = json.dumps([f.to_dict() for f in self.findings]).lower()
        for bad in ("infection monkey", "infectionmonkey", "guardicore", "akamai"):
            self.assertNotIn(bad, blob)

    def test_coverage(self):
        cov = InfectionMonkeyAdapter().coverage(self.data)
        self.assertEqual(cov["succeeded"], 5)
        self.assertEqual(cov["blocked"], 1)
        self.assertEqual(cov["types"], {"exploitation": 1, "segmentation": 1,
                                        "propagation": 1, "credential_reuse": 1, "technique": 1})

    def test_top_level_list_and_results_key(self):
        self.assertEqual(len(InfectionMonkeyAdapter().parse(self.data["events"])), 5)
        self.assertEqual(len(InfectionMonkeyAdapter().parse({"results": self.data["events"]})), 5)

    def test_bad_report_rejected(self):
        with self.assertRaises(ValueError):
            InfectionMonkeyAdapter().parse("not-json-structure")


class TestInfectionMonkeyRegistryAndPipeline(unittest.TestCase):
    def test_registered(self):
        self.assertIn("infectionmonkey", registry.discover())

    def test_catalog_entry_white_label(self):
        entry = next(a for a in registry.catalog() if a["name"] == "infectionmonkey")
        blob = (entry["title"] + entry["description"]).lower()
        for bad in ("infection monkey", "guardicore", "akamai"):
            self.assertNotIn(bad, blob)
        self.assertEqual(entry["title"], "Network Attack Simulation")

    def test_ingest_pipeline_bundle(self):
        adapter = InfectionMonkeyAdapter()
        findings = adapter.parse(load())
        run_doc = runner.build_ingest_run(
            findings, client_name="Acme Corp", scan_id="net-op-1",
            scan_type="network-attack-simulation", source="infectionmonkey",
            coverage=adapter.coverage(load()))
        self.assertEqual(run_doc["summary"]["high_count"], 4)
        self.assertEqual(run_doc["summary"]["medium_count"], 1)
        with tempfile.TemporaryDirectory() as t:
            runner.write_evidence_bundle(run_doc, t)
            ok, problems = evidence.verify_bundle(t)
            self.assertTrue(ok, problems)


if __name__ == "__main__":
    unittest.main()
