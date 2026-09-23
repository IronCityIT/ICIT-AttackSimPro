"""Tests for the malicious-traffic simulation (flightsim) report adapter."""

import json
import tempfile
import unittest
from pathlib import Path

from simcore import evidence, runner
from simcore.adapters import registry
from simcore.adapters.flightsim import FlightsimAdapter
from simcore.remediation import guidance_for

FIXTURE = Path(__file__).parent / "fixtures" / "flightsim_report.json"


def load():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class TestFlightsimAdapter(unittest.TestCase):
    def setUp(self):
        self.data = load()
        self.findings = FlightsimAdapter().parse(self.data)

    def _by_module(self, m):
        return next(f for f in self.findings if f.evidence["module"] == m)

    def test_only_generated_become_findings(self):
        # generated: c2, dga, dns-tunnel, ssh-exfil, scan, custom-thing, miner (no status
        # but a mapped module -> run). tor failed -> excluded.
        mods = sorted(f.evidence["module"] for f in self.findings)
        self.assertEqual(mods, ["c2", "custom-thing", "dga", "dns-tunnel", "miner", "scan", "ssh-exfil"])

    def test_failed_module_not_reported(self):
        self.assertFalse(any(f.evidence["module"] == "tor" for f in self.findings))

    def test_c2_and_exfil_high_severity(self):
        self.assertEqual(self._by_module("c2").severity, "high")          # command-and-control
        self.assertEqual(self._by_module("dga").attack, ("T1568.002",))
        self.assertEqual(self._by_module("ssh-exfil").severity, "high")   # exfiltration
        self.assertEqual(self._by_module("scan").severity, "medium")      # discovery

    def test_entry_supplied_attack_overrides(self):
        f = self._by_module("custom-thing")
        self.assertEqual(f.attack, ("T1105",))
        self.assertEqual(f.severity, "high")

    def test_destinations_captured(self):
        self.assertEqual(self._by_module("c2").evidence["destinations"], 2)

    def test_remediation_key(self):
        for f in self.findings:
            self.assertEqual(f.remediation_key, "network-traffic-undetected")
        self.assertEqual(guidance_for("network-traffic-undetected")["priority"], "High")

    def test_white_label_no_tool_name(self):
        blob = json.dumps([f.to_dict() for f in self.findings]).lower()
        for bad in ("flightsim", "alphasoc"):
            self.assertNotIn(bad, blob)

    def test_coverage(self):
        cov = FlightsimAdapter().coverage(self.data)
        self.assertEqual(cov["generated"], 7)
        self.assertEqual(cov["failed"], 1)   # tor
        self.assertEqual(cov["modules"]["c2"], 1)

    def test_list_and_results_shapes(self):
        self.assertEqual(len(FlightsimAdapter().parse(self.data["modules"])), 7)
        self.assertEqual(len(FlightsimAdapter().parse({"results": self.data["modules"]})), 7)

    def test_bad_report_rejected(self):
        with self.assertRaises(ValueError):
            FlightsimAdapter().parse("nope")


class TestFlightsimRegistryAndPipeline(unittest.TestCase):
    def test_registered(self):
        self.assertIn("flightsim", registry.discover())

    def test_catalog_entry_white_label(self):
        entry = next(a for a in registry.catalog() if a["name"] == "flightsim")
        blob = (entry["title"] + entry["description"]).lower()
        for bad in ("flightsim", "alphasoc"):
            self.assertNotIn(bad, blob)
        self.assertEqual(entry["title"], "Malicious Traffic Simulation")

    def test_ingest_pipeline_bundle(self):
        adapter = FlightsimAdapter()
        findings = adapter.parse(load())
        run_doc = runner.build_ingest_run(
            findings, client_name="Acme Corp", scan_id="traffic-op-1",
            scan_type="malicious-traffic-simulation", source="flightsim",
            coverage=adapter.coverage(load()))
        self.assertGreaterEqual(run_doc["summary"]["high_count"], 4)
        with tempfile.TemporaryDirectory() as t:
            runner.write_evidence_bundle(run_doc, t)
            ok, problems = evidence.verify_bundle(t)
            self.assertTrue(ok, problems)


if __name__ == "__main__":
    unittest.main()
