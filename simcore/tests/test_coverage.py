"""Tests for the cross-adapter ATT&CK coverage aggregator."""

import json
import unittest
from pathlib import Path

from simcore import coverage, runner
from simcore.adapters.caldera import CalderaAdapter
from simcore.adapters.stratus import StratusAdapter
from simcore.adapters.maad import MaadAdapter
from simcore.adapters.purplesharp import PurpleSharpAdapter
from simcore.adapters.atomic import AtomicAdapter
from simcore.adapters.infectionmonkey import InfectionMonkeyAdapter

FX = Path(__file__).parent / "fixtures"


def _doc(adapter, fixture, source, scan_type):
    data = json.loads((FX / fixture).read_text(encoding="utf-8"))
    findings = adapter.parse(data)
    cov = adapter.coverage(data) if hasattr(adapter, "coverage") else {}
    return runner.build_ingest_run(findings, client_name="Acme", scan_id=source + "-1",
                                   scan_type=scan_type, source=source, coverage=cov)


def all_docs():
    return [
        _doc(CalderaAdapter(), "caldera_report.json", "caldera", "adversary-emulation"),
        _doc(StratusAdapter(), "stratus_report.json", "stratus", "cloud-attack-simulation"),
        _doc(MaadAdapter(), "maad_report.json", "maad", "identity-attack-simulation"),
        _doc(PurpleSharpAdapter(), "purplesharp_report.json", "purplesharp", "endpoint-attack-simulation"),
        _doc(AtomicAdapter(), "atomic_report.json", "atomic", "endpoint-technique-emulation"),
        _doc(InfectionMonkeyAdapter(), "infectionmonkey_report.json", "infectionmonkey", "network-attack-simulation"),
    ]


class TestCoverageAggregate(unittest.TestCase):
    def setUp(self):
        self.summary = coverage.aggregate(all_docs())

    def test_all_six_sources_present_by_white_label_title(self):
        titles = set(self.summary["sources"])
        for t in ("Automated Adversary Emulation", "Cloud Attack Simulation",
                  "Identity Attack Simulation", "Endpoint Attack Simulation",
                  "Endpoint Technique Emulation", "Network Attack Simulation"):
            self.assertIn(t, titles)
        self.assertEqual(self.summary["totals"]["sources"], 6)

    def test_no_internal_tool_names_in_output(self):
        blob = json.dumps(self.summary).lower()
        for bad in ("caldera", "stratus", "maad", "purplesharp", "purple sharp",
                    "atomic red team", "invoke-atomic", "infection monkey", "guardicore"):
            self.assertNotIn(bad, blob)

    def test_techniques_aggregated_with_sources_and_tactics(self):
        techs = {t["technique_id"]: t for t in self.summary["techniques"]}
        self.assertIn("T1003", techs)          # from CALDERA (credential access)
        self.assertIn("T1003.001", techs)      # from PurpleSharp/Atomic (LSASS)
        # every technique lists at least one source and a valid max_severity
        for t in self.summary["techniques"]:
            self.assertTrue(t["sources"])
            self.assertIn(t["max_severity"], ("info", "low", "medium", "high", "critical"))

    def test_severity_and_technique_totals_are_sane(self):
        tot = self.summary["totals"]
        self.assertGreater(tot["unique_techniques"], 5)
        sev = tot["findings_by_severity"]
        self.assertGreaterEqual(sev["critical"], 1)  # e.g. Atomic T1486 / Monkey / MAAD
        self.assertGreater(sum(sev.values()), 10)

    def test_per_source_coverage_counts_preserved(self):
        # CALDERA reports executed/prevented; those verbatim counts survive aggregation.
        cov = self.summary["sources"]["Automated Adversary Emulation"]["coverage"]
        self.assertEqual(cov.get("executed"), 3)
        self.assertEqual(cov.get("prevented"), 1)

    def test_markdown_render_is_white_labeled(self):
        md = coverage.render_markdown(self.summary)
        self.assertIn("# ATT&CK Coverage Report", md)
        self.assertIn("Network Attack Simulation", md)
        low = md.lower()
        for bad in ("caldera", "guardicore", "purplesharp"):
            self.assertNotIn(bad, low)

    def test_empty_input(self):
        s = coverage.aggregate([])
        self.assertEqual(s["totals"]["sources"], 0)
        self.assertEqual(s["techniques"], [])


if __name__ == "__main__":
    unittest.main()
