"""Tests for the M365 / Entra ID identity attack simulation report adapter."""

import json
import tempfile
import unittest
from pathlib import Path

from simcore import evidence, runner
from simcore.adapters import registry
from simcore.adapters.maad import MaadAdapter
from simcore.remediation import guidance_for

FIXTURE = Path(__file__).parent / "fixtures" / "maad_report.json"


def load():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class TestMaadAdapter(unittest.TestCase):
    def setUp(self):
        self.data = load()
        self.findings = MaadAdapter().parse(self.data)

    def _by_module(self, mod):
        return next(f for f in self.findings if f.evidence["module"] == mod)

    def test_only_executed_mapped_actions_become_findings(self):
        # 6 executed+mapped: DisableMFA, Backdoor, MailForwarding, RemoveAccess,
        # AssignRole (alias), CustomTenantTTP (own id). BruteForce blocked, two
        # recon/unmapped actions skipped.
        self.assertEqual(len(self.findings), 6)

    def test_blocked_action_not_reported(self):
        self.assertFalse(any(f.evidence["module"] == "bruteforce" for f in self.findings))

    def test_recon_and_unmapped_skipped(self):
        mods = {f.evidence["module"] for f in self.findings}
        self.assertNotIn("azureadrecon", mods)
        self.assertFalse(any("named locations" in f.title.lower() for f in self.findings))

    def test_alias_resolves_to_canonical_module(self):
        # "Setup Email Forwarding" -> mailforwarding; "Assign Azure AD Role" -> assignrole
        self._by_module("mailforwarding")
        self._by_module("assignrole")

    def test_severity_by_tactic(self):
        self.assertEqual(self._by_module("removeaccess").severity, "critical")   # impact
        self.assertEqual(self._by_module("disablemfa").severity, "medium")       # defense-evasion
        self.assertEqual(self._by_module("mailforwarding").severity, "medium")   # collection
        self.assertEqual(self._by_module("customtenantttp").severity, "high")    # credential-access

    def test_attack_id_from_builtin_map(self):
        self.assertEqual(self._by_module("disablemfa").attack, ("T1556.006",))
        self.assertEqual(self._by_module("backdooraccountcreation").attack, ("T1136.003",))

    def test_entry_supplied_attack_id_overrides(self):
        self.assertEqual(self._by_module("customtenantttp").attack, ("T1621",))

    def test_service_captured(self):
        services = {f.evidence["service"] for f in self.findings}
        self.assertIn("Entra ID", services)
        self.assertIn("Exchange Online", services)

    def test_target_carried(self):
        self.assertEqual(self._by_module("disablemfa").evidence["target"], "cfo@acme.com")

    def test_remediation_key_set_and_resolvable(self):
        for f in self.findings:
            self.assertEqual(f.remediation_key, "identity-technique-unprevented")
        # The remediation catalog actually has an entry for that key.
        self.assertEqual(guidance_for("identity-technique-unprevented")["priority"], "High")

    def test_white_label_no_tool_name(self):
        blob = json.dumps([f.to_dict() for f in self.findings]).lower()
        self.assertNotIn("maad", blob)

    def test_coverage(self):
        cov = MaadAdapter().coverage(self.data)
        self.assertEqual(cov["executed"], 6)
        self.assertEqual(cov["prevented"], 1)   # BruteForce blocked
        self.assertEqual(cov["services"], {"Entra ID": 5, "Exchange Online": 1})

    def test_top_level_list_shape(self):
        as_list = self.data["modules"]
        self.assertEqual(len(MaadAdapter().parse(as_list)), 6)

    def test_wrapped_results_key(self):
        self.assertEqual(len(MaadAdapter().parse({"results": self.data["modules"]})), 6)

    def test_bad_report_rejected(self):
        with self.assertRaises(ValueError):
            MaadAdapter().parse("not-json-structure")

    def test_unknown_outcome_not_a_finding(self):
        data = {"modules": [{"module": "DisableMFA", "target": "x@acme.com",
                             "outcome": "pending"}]}
        self.assertEqual(MaadAdapter().parse(data), [])


class TestMaadRegistryAndPipeline(unittest.TestCase):
    def test_registered(self):
        self.assertIn("maad", registry.discover())

    def test_catalog_entry_white_label(self):
        entry = next(a for a in registry.catalog() if a["name"] == "maad")
        self.assertNotIn("maad-af", (entry["title"] + entry["description"]).lower())
        self.assertEqual(entry["title"], "Identity Attack Simulation")

    def test_ingest_pipeline_bundle(self):
        adapter = MaadAdapter()
        findings = adapter.parse(load())
        run_doc = runner.build_ingest_run(
            findings, client_name="Acme Corp", scan_id="identity-op-1",
            scan_type="identity-attack-simulation", source="maad",
            coverage=adapter.coverage(load()))
        self.assertEqual(run_doc["summary"]["critical_count"], 1)
        self.assertEqual(run_doc["summary"]["high_count"], 1)
        self.assertEqual(run_doc["summary"]["medium_count"], 4)
        with tempfile.TemporaryDirectory() as t:
            runner.write_evidence_bundle(run_doc, t)
            ok, problems = evidence.verify_bundle(t)
            self.assertTrue(ok, problems)


if __name__ == "__main__":
    unittest.main()
