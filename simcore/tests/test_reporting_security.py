"""Security-focused tests: report output encoding + net safe-method enforcement."""

import unittest

from simcore import reporting
from simcore.net import HttpProbe


class TestReportEscaping(unittest.TestCase):
    def _run_with_xss(self):
        return {
            "client_name": "<script>alert(1)</script>",
            "scan_id": "s1",
            "targets": ["http://127.0.0.1"],
            "scenario_count": 1,
            "findings": [{
                "severity": "high",
                "title": "<img src=x onerror=alert(1)>",
                "target": "http://127.0.0.1/<svg onload=alert(1)>",
                "remediation_key": "missing-hsts",
            }],
        }

    def test_html_escapes_hostile_finding(self):
        out = reporting.render_html(self._run_with_xss())
        self.assertNotIn("<img src=x onerror=alert(1)>", out)
        self.assertNotIn("<script>alert(1)</script>", out)
        self.assertIn("&lt;img src=x", out)

    def test_markdown_renders(self):
        out = reporting.render_markdown(self._run_with_xss())
        self.assertIn("Iron City AttackSimPro", out)
        # No underlying tool names leak into the report (white-label).
        for tool in ("nuclei", "zap", "metasploit", "nmap"):
            self.assertNotIn(tool, out.lower())


class TestSafeMethods(unittest.TestCase):
    def test_unsafe_method_rejected(self):
        probe = HttpProbe("http://127.0.0.1")
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.assertRaises(ValueError):
                probe.fetch("/", method=method)


if __name__ == "__main__":
    unittest.main()
