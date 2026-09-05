"""Integration tests: runner + scope + rbac + audit + evidence, no network."""

import tempfile
import unittest
from pathlib import Path

from simcore import evidence, rbac, registry, runner
from simcore.audit import AuditLog
from simcore.scope import Scope
from simcore.tests.fakes import make_ctx, vulnerable_response


def fake_factory(target, auth):
    return make_ctx(default=vulnerable_response(), open_ports=set(), host=auth.host)


class TestRunnerIntegration(unittest.TestCase):
    def test_run_produces_findings_and_bundle(self):
        scenarios = registry.select(group="standard")
        with tempfile.TemporaryDirectory() as t:
            audit = AuditLog(Path(t) / "audit.log")
            run_doc = runner.run(
                scenarios, ["http://127.0.0.1:9101"],
                scope=Scope(), client_name="Acme Corp", scan_id="sim-1",
                actor="tester", role="operator", audit=audit,
                probe_factory=fake_factory,
            )
            self.assertEqual(run_doc["client_id"], "acme-corp")
            self.assertGreater(len(run_doc["findings"]), 0)
            self.assertEqual(run_doc["targets"], ["http://127.0.0.1:9101"])

            manifest = runner.write_evidence_bundle(run_doc, Path(t) / "bundle")
            self.assertIn("bundle_digest", manifest)
            ok, problems = evidence.verify_bundle(Path(t) / "bundle")
            self.assertTrue(ok, problems)

            ok, _ = audit.verify()
            self.assertTrue(ok)
            self.assertTrue(any(e["action"] == "run_simulation" for e in audit.entries()))

    def test_external_target_refused_and_audited(self):
        with tempfile.TemporaryDirectory() as t:
            audit = AuditLog(Path(t) / "audit.log")
            run_doc = runner.run(
                registry.select(group="quick"), ["https://8.8.8.8"],
                scope=Scope(allow_external=False), client_name="X", scan_id="s2",
                audit=audit, probe_factory=fake_factory,
            )
            self.assertEqual(run_doc["targets"], [])
            self.assertEqual(len(run_doc["refusals"]), 1)
            self.assertTrue(any(e["outcome"] == "denied" for e in audit.entries()))

    def test_viewer_role_cannot_run(self):
        with self.assertRaises(rbac.AccessDenied):
            runner.run(registry.select(group="quick"), ["http://127.0.0.1"],
                       scope=Scope(), client_name="X", scan_id="s3", role="viewer",
                       probe_factory=fake_factory)

    def test_mixed_targets_partial_authorization(self):
        run_doc = runner.run(
            registry.select(names=["security_headers"]),
            ["http://127.0.0.1:9101", "https://8.8.8.8"],
            scope=Scope(allow_external=False), client_name="Acme", scan_id="s4",
            probe_factory=fake_factory,
        )
        self.assertEqual(run_doc["targets"], ["http://127.0.0.1:9101"])
        self.assertEqual(len(run_doc["refusals"]), 1)


if __name__ == "__main__":
    unittest.main()
