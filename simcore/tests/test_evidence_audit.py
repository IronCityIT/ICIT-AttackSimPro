"""Tests for evidence bundles (integrity) and the audit hash chain (tamper-evidence)."""

import json
import tempfile
import unittest
from pathlib import Path

from simcore import evidence
from simcore.audit import AuditLog


class TestEvidenceBundle(unittest.TestCase):
    def _bundle(self, d: Path):
        evidence.write_json(d / "run.json", {"scan_id": "s1", "findings": []})
        evidence.write_json(d / "findings.json", [])
        (d / "report.md").write_text("# report", encoding="utf-8")
        return evidence.write_manifest(d)

    def test_manifest_and_verify(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t)
            manifest = self._bundle(d)
            self.assertIn("bundle_digest", manifest)
            ok, problems = evidence.verify_bundle(d)
            self.assertTrue(ok, problems)

    def test_tamper_detected(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t)
            self._bundle(d)
            (d / "report.md").write_text("# tampered", encoding="utf-8")
            ok, problems = evidence.verify_bundle(d)
            self.assertFalse(ok)
            self.assertTrue(any("hash mismatch" in p for p in problems))

    def test_added_file_detected(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t)
            self._bundle(d)
            (d / "sneaky.txt").write_text("x", encoding="utf-8")
            ok, problems = evidence.verify_bundle(d)
            self.assertFalse(ok)

    def test_deterministic_digest(self):
        with tempfile.TemporaryDirectory() as t1, tempfile.TemporaryDirectory() as t2:
            m1 = self._bundle(Path(t1))
            m2 = self._bundle(Path(t2))
            self.assertEqual(m1["bundle_digest"], m2["bundle_digest"])


class TestAuditChain(unittest.TestCase):
    def test_append_and_verify(self):
        with tempfile.TemporaryDirectory() as t:
            log = AuditLog(Path(t) / "audit.log")
            log.append("alice", "operator", "run_simulation", "http://127.0.0.1")
            log.append("alice", "operator", "export_evidence", "s1")
            ok, idx = log.verify()
            self.assertTrue(ok)
            self.assertIsNone(idx)
            self.assertEqual(len(log.entries()), 2)

    def test_chain_links(self):
        with tempfile.TemporaryDirectory() as t:
            log = AuditLog(Path(t) / "audit.log")
            r1 = log.append("a", "operator", "run_simulation")
            r2 = log.append("a", "operator", "run_simulation")
            self.assertEqual(r2["prev_hash"], r1["hash"])

    def test_tamper_breaks_chain(self):
        with tempfile.TemporaryDirectory() as t:
            path = Path(t) / "audit.log"
            log = AuditLog(path)
            log.append("a", "operator", "run_simulation", "x")
            log.append("a", "operator", "run_simulation", "y")
            # Rewrite the first record's target — chain must fail at index 0.
            lines = path.read_text().splitlines()
            rec = json.loads(lines[0])
            rec["target"] = "z"
            lines[0] = json.dumps(rec, separators=(",", ":"))
            path.write_text("\n".join(lines) + "\n")
            ok, idx = log.verify()
            self.assertFalse(ok)
            self.assertEqual(idx, 0)


if __name__ == "__main__":
    unittest.main()
