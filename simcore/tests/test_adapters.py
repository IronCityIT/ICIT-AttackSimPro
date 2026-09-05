"""Tests for report adapters (CALDERA operation-report ingestion)."""

import json
import tempfile
import unittest
from pathlib import Path

from simcore import runner
from simcore.adapters import registry
from simcore.adapters.base import tactic_severity
from simcore.adapters.caldera import CalderaAdapter

FIXTURE = Path(__file__).parent / "fixtures" / "caldera_report.json"


def load():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class TestCalderaAdapter(unittest.TestCase):
    def setUp(self):
        self.data = load()
        self.findings = CalderaAdapter().parse(self.data)

    def test_only_successful_mapped_links_become_findings(self):
        # T1057, T1003, T1018 succeeded and are mapped (3). T1021 was blocked
        # (status 1) and the cleanup link has no technique — neither is a finding.
        tids = sorted(f.attack[0] for f in self.findings)
        self.assertEqual(tids, ["T1003", "T1018", "T1057"])

    def test_blocked_technique_not_reported(self):
        self.assertFalse(any(f.attack[0] == "T1021" for f in self.findings))

    def test_severity_by_tactic(self):
        cred = next(f for f in self.findings if f.attack[0] == "T1003")
        disc = next(f for f in self.findings if f.attack[0] == "T1057")
        self.assertEqual(cred.severity, "high")      # credential-access
        self.assertEqual(disc.severity, "medium")    # discovery

    def test_white_label_no_tool_name(self):
        blob = json.dumps([f.to_dict() for f in self.findings]).lower()
        self.assertNotIn("caldera", blob)

    def test_remediation_key_set(self):
        for f in self.findings:
            self.assertEqual(f.remediation_key, "adversary-technique-unprevented")

    def test_coverage(self):
        cov = CalderaAdapter().coverage(self.data)
        self.assertEqual(cov["executed"], 3)   # T1057, T1003, T1018
        self.assertEqual(cov["prevented"], 1)  # T1021 blocked
        self.assertEqual(len(cov["techniques"]), 4)

    def test_bad_report_rejected(self):
        with self.assertRaises(ValueError):
            CalderaAdapter().parse(["not", "a", "dict"])


class TestAdapterRegistry(unittest.TestCase):
    def test_discover_and_get(self):
        self.assertIn("caldera", registry.discover())
        self.assertEqual(registry.get("caldera").name, "caldera")

    def test_unknown_adapter(self):
        with self.assertRaises(KeyError):
            registry.get("nope")

    def test_tactic_severity_default(self):
        self.assertEqual(tactic_severity("unknown-tactic"), "medium")


class TestIngestPipeline(unittest.TestCase):
    def test_ingest_run_builds_bundle(self):
        findings = CalderaAdapter().parse(load())
        cov = CalderaAdapter().coverage(load())
        run_doc = runner.build_ingest_run(
            findings, client_name="Acme Corp", scan_id="op-1",
            scan_type="adversary-emulation", source="caldera", coverage=cov)
        self.assertEqual(run_doc["client_id"], "acme-corp")
        self.assertEqual(run_doc["summary"]["high_count"], 1)   # T1003
        self.assertEqual(run_doc["summary"]["medium_count"], 2)  # T1057, T1018
        self.assertIn("WIN-01", run_doc["targets"])
        with tempfile.TemporaryDirectory() as t:
            from simcore import evidence
            runner.write_evidence_bundle(run_doc, t)
            ok, problems = evidence.verify_bundle(t)
            self.assertTrue(ok, problems)


if __name__ == "__main__":
    unittest.main()
