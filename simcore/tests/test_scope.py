"""Unit + security tests for the scope/authorization gate."""

import unittest
from datetime import datetime, timezone

from simcore.scope import (
    AuthorizationRecord,
    Scope,
    ScopeError,
    host_of,
    is_private_or_loopback,
)
import ipaddress


class TestHostParsing(unittest.TestCase):
    def test_host_of_url(self):
        self.assertEqual(host_of("https://example.com:8443/path"), "example.com")

    def test_host_of_bare(self):
        self.assertEqual(host_of("10.0.0.5"), "10.0.0.5")

    def test_private_ranges(self):
        self.assertTrue(is_private_or_loopback(ipaddress.ip_address("127.0.0.1")))
        self.assertTrue(is_private_or_loopback(ipaddress.ip_address("10.1.2.3")))
        self.assertFalse(is_private_or_loopback(ipaddress.ip_address("8.8.8.8")))


class TestSandboxGate(unittest.TestCase):
    def test_loopback_always_allowed(self):
        auth = Scope().authorize("http://127.0.0.1:9101")
        self.assertTrue(auth.sandbox)
        self.assertEqual(auth.roe_id, "SANDBOX")

    def test_private_allowed(self):
        auth = Scope().authorize("http://10.0.0.9")
        self.assertTrue(auth.sandbox)

    def test_external_denied_without_opt_in(self):
        with self.assertRaises(ScopeError):
            Scope().authorize("https://8.8.8.8")

    def test_external_denied_even_with_opt_in_but_no_record(self):
        with self.assertRaises(ScopeError):
            Scope(allow_external=True).authorize("https://8.8.8.8")


class TestAuthorizationRecords(unittest.TestCase):
    def _scope(self, **kw):
        rec = AuthorizationRecord(
            roe_id="ROE-1", client="acme", authorized_by="ciso@acme",
            hosts=["scan.acme.example"], cidrs=["93.184.216.0/24"],
            not_before="2026-01-01T00:00:00Z", not_after="2027-01-01T00:00:00Z",
            reason="signed ROE",
        )
        return Scope(records=[rec], allow_external=True,
                     now=datetime(2026, 6, 1, tzinfo=timezone.utc), **kw)

    def test_host_in_record_allowed(self):
        auth = self._scope().authorize("https://scan.acme.example")
        self.assertFalse(auth.sandbox)
        self.assertEqual(auth.roe_id, "ROE-1")

    def test_cidr_in_record_allowed(self):
        auth = self._scope().authorize("https://93.184.216.34")
        self.assertEqual(auth.roe_id, "ROE-1")

    def test_out_of_scope_host_denied(self):
        with self.assertRaises(ScopeError):
            self._scope().authorize("https://other.example")

    def test_out_of_window_denied(self):
        rec = AuthorizationRecord(
            roe_id="ROE-2", client="acme", authorized_by="x", hosts=["scan.acme.example"],
            not_after="2026-01-01T00:00:00Z")
        scope = Scope(records=[rec], allow_external=True,
                      now=datetime(2026, 6, 1, tzinfo=timezone.utc))
        with self.assertRaises(ScopeError):
            scope.authorize("https://scan.acme.example")


if __name__ == "__main__":
    unittest.main()
