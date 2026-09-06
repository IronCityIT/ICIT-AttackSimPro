"""Tests for the Stratus Red Team (cloud attack simulation) report adapter."""

import json
import tempfile
import unittest
from pathlib import Path

from simcore import evidence, runner
from simcore.adapters import registry
from simcore.adapters.stratus import StratusAdapter

FIXTURE = Path(__file__).parent / "fixtures" / "stratus_report.json"


def load():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class TestStratusAdapter(unittest.TestCase):
    def setUp(self):
        self.data = load()
        self.findings = StratusAdapter().parse(self.data)

    def test_only_detonated_become_findings(self):
        # 3 DETONATED (cred-access, discovery, execution). COLD + metadata-only skipped.
        self.assertEqual(len(self.findings), 3)

    def test_cold_technique_skipped(self):
        self.assertFalse(any("share-ami" in f.evidence.get("technique_ref", "") for f in self.findings))

    def test_metadata_only_skipped(self):
        self.assertFalse(any("iam-backdoor" in f.evidence.get("technique_ref", "") for f in self.findings))

    def test_severity_by_tactic(self):
        cred = next(f for f in self.findings if "get-password" in f.evidence["technique_ref"])
        disc = next(f for f in self.findings if "enumerate" in f.evidence["technique_ref"])
        self.assertEqual(cred.severity, "high")     # credential-access
        self.assertEqual(disc.severity, "medium")   # discovery

    def test_attack_id_carried_when_present(self):
        cred = next(f for f in self.findings if "get-password" in f.evidence["technique_ref"])
        self.assertEqual(cred.attack, ("T1552.004",))
        disc = next(f for f in self.findings if "enumerate" in f.evidence["technique_ref"])
        self.assertEqual(disc.attack, ())  # fixture has no explicit ATT&CK id here

    def test_platform_captured(self):
        platforms = {f.evidence["platform"] for f in self.findings}
        self.assertEqual(platforms, {"AWS", "Azure"})

    def test_white_label_no_tool_name(self):
        blob = json.dumps([f.to_dict() for f in self.findings]).lower()
        self.assertNotIn("stratus", blob)

    def test_remediation_key(self):
        for f in self.findings:
            self.assertEqual(f.remediation_key, "cloud-technique-detonated")

    def test_coverage(self):
        cov = StratusAdapter().coverage(self.data)
        self.assertEqual(cov["detonated"], 3)
        self.assertEqual(cov["not_run"], 2)
        self.assertEqual(cov["platforms"], {"AWS": 2, "Azure": 1})

    def test_wrapped_results_key(self):
        wrapped = {"results": self.data}
        self.assertEqual(len(StratusAdapter().parse(wrapped)), 3)

    def test_bad_report_rejected(self):
        with self.assertRaises(ValueError):
            StratusAdapter().parse("not-json-structure")


class TestStratusRegistryAndPipeline(unittest.TestCase):
    def test_registered(self):
        self.assertIn("stratus", registry.discover())

    def test_ingest_pipeline_bundle(self):
        adapter = StratusAdapter()
        findings = adapter.parse(load())
        run_doc = runner.build_ingest_run(
            findings, client_name="Acme Corp", scan_id="cloud-op-1",
            scan_type="cloud-attack-simulation", source="stratus",
            coverage=adapter.coverage(load()))
        self.assertEqual(run_doc["summary"]["high_count"], 1)
        self.assertEqual(run_doc["summary"]["medium_count"], 2)
        with tempfile.TemporaryDirectory() as t:
            runner.write_evidence_bundle(run_doc, t)
            ok, problems = evidence.verify_bundle(t)
            self.assertTrue(ok, problems)


if __name__ == "__main__":
    unittest.main()
