"""Unit tests for the scenario library (against in-memory probe contexts)."""

import unittest

from simcore.net import HttpResponse
from simcore.registry import discover
from simcore.scenarios.cookie_hardening import CookieHardeningScenario
from simcore.scenarios.cors_policy import CorsPolicyScenario
from simcore.scenarios.directory_listing import DirectoryListingScenario
from simcore.scenarios.http_methods import HttpMethodsScenario
from simcore.scenarios.open_ports import OpenPortsScenario
from simcore.scenarios.security_headers import SecurityHeadersScenario
from simcore.scenarios.sensitive_paths import SensitivePathsScenario
from simcore.scenarios.server_disclosure import ServerDisclosureScenario
from simcore.scenarios.tls_posture import TlsPostureScenario
from simcore.tests.fakes import hardened_response, make_ctx, vulnerable_response


class TestSecurityHeaders(unittest.TestCase):
    def test_vulnerable_flags_all_headers(self):
        ctx = make_ctx(default=vulnerable_response())
        res = SecurityHeadersScenario().simulate("http://t", ctx)
        titles = {f.title for f in res.findings}
        self.assertIn("Missing HSTS", titles)
        self.assertIn("Missing Content-Security-Policy", titles)
        self.assertFalse(res.control_passed)

    def test_hardened_passes(self):
        ctx = make_ctx(default=hardened_response())
        res = SecurityHeadersScenario().simulate("http://t", ctx)
        self.assertEqual(res.findings, [])
        self.assertTrue(res.control_passed)

    def test_no_response_is_error_not_crash(self):
        ctx = make_ctx(default=HttpResponse(status=0, error="refused"))
        res = SecurityHeadersScenario().simulate("http://t", ctx)
        self.assertFalse(res.control_passed)
        self.assertIsNotNone(res.error)


class TestCookieAndServer(unittest.TestCase):
    def test_insecure_cookie_flagged(self):
        res = CookieHardeningScenario().simulate("http://t", make_ctx(default=vulnerable_response()))
        self.assertEqual(len(res.findings), 1)

    def test_hardened_cookie_ok(self):
        res = CookieHardeningScenario().simulate("http://t", make_ctx(default=hardened_response()))
        self.assertEqual(res.findings, [])

    def test_server_version_disclosure(self):
        res = ServerDisclosureScenario().simulate("http://t", make_ctx(default=vulnerable_response()))
        self.assertTrue(any("Server Version" in f.title for f in res.findings))


class TestTls(unittest.TestCase):
    def test_expired_cert_is_critical(self):
        ctx = make_ctx(tls={"version": "TLSv1.3", "days_left": -3, "not_after": "x"})
        res = TlsPostureScenario().simulate("https://t", ctx)
        self.assertTrue(any(f.severity == "critical" for f in res.findings))

    def test_weak_version_flagged(self):
        ctx = make_ctx(tls={"version": "TLSv1", "days_left": 200})
        res = TlsPostureScenario().simulate("https://t", ctx)
        self.assertTrue(any("Legacy TLS" in f.title for f in res.findings))

    def test_no_tls_is_not_applicable(self):
        res = TlsPostureScenario().simulate("http://t", make_ctx(tls=None))
        self.assertTrue(res.control_passed)
        self.assertEqual(res.findings, [])


class TestPathsPortsMethods(unittest.TestCase):
    def test_sensitive_path_reachable(self):
        ctx = make_ctx(responses={"/.env": HttpResponse(status=200)},
                       default=HttpResponse(status=404))
        res = SensitivePathsScenario().simulate("http://t", ctx)
        self.assertTrue(any("/.env" in f.title for f in res.findings))

    def test_security_txt_not_a_finding(self):
        ctx = make_ctx(default=HttpResponse(status=200))  # everything 200
        res = SensitivePathsScenario().simulate("http://t", ctx)
        self.assertFalse(any("security.txt" in f.title for f in res.findings))

    def test_open_port_flagged(self):
        res = OpenPortsScenario().simulate("host", make_ctx(open_ports={6379}))
        self.assertTrue(any(f.evidence.get("port") == 6379 for f in res.findings))

    def test_risky_methods(self):
        ctx = make_ctx(responses={"OPTIONS:/": HttpResponse(status=200, headers={"allow": "GET, TRACE, PUT"})})
        res = HttpMethodsScenario().simulate("http://t", ctx)
        self.assertTrue(any("Risky HTTP" in f.title for f in res.findings))


class TestCorsAndListing(unittest.TestCase):
    def test_wildcard_with_credentials_is_high(self):
        ctx = make_ctx(default=HttpResponse(status=200, headers={
            "access-control-allow-origin": "*", "access-control-allow-credentials": "true"}))
        res = CorsPolicyScenario().simulate("http://t", ctx)
        self.assertTrue(any(f.severity == "high" for f in res.findings))

    def test_directory_listing_signature(self):
        ctx = make_ctx(responses={"/files/": HttpResponse(status=200, body="<h1>Index of /files</h1>")},
                       default=HttpResponse(status=404))
        res = DirectoryListingScenario().simulate("http://t", ctx)
        self.assertTrue(any("Directory Listing" in f.title for f in res.findings))


class TestRegistryContract(unittest.TestCase):
    def test_all_scenarios_safe_and_named(self):
        for name, scen in discover().items():
            self.assertTrue(scen.safe, name)
            self.assertTrue(scen.name and scen.title, name)
            self.assertTrue(scen.attack, f"{name} missing ATT&CK mapping")

    def test_library_has_at_least_eight(self):
        self.assertGreaterEqual(len(discover()), 8)


if __name__ == "__main__":
    unittest.main()
