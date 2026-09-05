"""Unit tests for base, remediation, rbac, ingest_client, registry."""

import unittest

from simcore import ingest_client, rbac, registry
from simcore.base import Finding, severity_rank
from simcore.remediation import export, guidance_for


class TestFinding(unittest.TestCase):
    def test_bad_severity_rejected(self):
        with self.assertRaises(ValueError):
            Finding("s", "t", "sever", "x")

    def test_remediation_key_derived(self):
        f = Finding("s", "t", "high", "Missing HSTS Header")
        self.assertEqual(f.remediation_key, "missing-hsts-header")

    def test_severity_rank_order(self):
        self.assertLess(severity_rank("low"), severity_rank("critical"))


class TestRemediation(unittest.TestCase):
    def test_known_key(self):
        g = guidance_for("missing-hsts")
        self.assertIn("frameworks", g)
        self.assertTrue(g["steps"])

    def test_unknown_key_defaults(self):
        g = guidance_for("does-not-exist")
        self.assertTrue(g["steps"])

    def test_export_shape(self):
        self.assertEqual(export()["version"], 1)


class TestRbac(unittest.TestCase):
    def test_viewer_cannot_run(self):
        with self.assertRaises(rbac.AccessDenied):
            rbac.require("viewer", "run_simulation")

    def test_operator_can_run(self):
        rbac.require("operator", "run_simulation")  # no raise

    def test_only_admin_manages_authorizations(self):
        self.assertTrue(rbac.can("admin", "manage_authorizations"))
        self.assertFalse(rbac.can("operator", "manage_authorizations"))

    def test_unknown_role_denied(self):
        with self.assertRaises(rbac.AccessDenied):
            rbac.require("wizard", "view_results")


class TestIngestClient(unittest.TestCase):
    def test_payload_counts(self):
        run = {"client_name": "Acme", "client_id": "acme", "scan_id": "s1",
               "targets": ["http://127.0.0.1"], "scenario_count": 2,
               "findings": [{"severity": "high"}, {"severity": "high"}, {"severity": "low"}]}
        p = ingest_client.build_payload(run)
        self.assertEqual(p["summary"]["high_count"], 2)
        self.assertEqual(p["summary"]["low_count"], 1)
        self.assertEqual(p["scan_id"], "s1")


class TestRegistrySelection(unittest.TestCase):
    def test_group_select(self):
        names = {s.name for s in registry.select(group="quick")}
        self.assertIn("security_headers", names)

    def test_explicit_select(self):
        got = registry.select(names=["security_headers", "tls_posture"])
        self.assertEqual([s.name for s in got], ["security_headers", "tls_posture"])

    def test_unknown_scenario_raises(self):
        with self.assertRaises(KeyError):
            registry.select(names=["nope"])

    def test_unknown_group_raises(self):
        with self.assertRaises(KeyError):
            registry.select(group="nope")

    def test_catalog_matches_discover(self):
        cat = registry.catalog()
        self.assertEqual(len(cat["scenarios"]), len(registry.discover()))


if __name__ == "__main__":
    unittest.main()
