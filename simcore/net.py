"""
net.py — the only place AttackSimPro touches a network, and it does so passively.

Scenarios never open sockets themselves; they call the probes bound into their run
context (``ctx['fetch']`` / ``ctx['tcp_probe']`` / ``ctx['tls_info']``). That keeps
three guarantees in one place:

  * every request goes to a host the scope gate already authorized,
  * requests are inspection-only (GET/HEAD/OPTIONS, no body, no redirects offsite),
  * tests inject deterministic doubles with the identical signature.
"""

from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

# Methods a Purple-Team validation is ever allowed to send. Anything mutating
# (POST/PUT/DELETE/PATCH) is intentionally excluded.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

USER_AGENT = "AttackSimPro-Validation/2.0"


@dataclass
class HttpResponse:
    status: int
    headers: dict[str, str] = field(default_factory=dict)  # lowercased keys
    body: str = ""
    error: str | None = None

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


class HttpProbe:
    """A loopback/authorized HTTP fetcher bound to one base target."""

    def __init__(self, base: str, timeout: float = 5.0, max_body: int = 65536):
        self.base = base if "://" in base else "http://" + base
        self.timeout = timeout
        self.max_body = max_body

    def fetch(self, path: str = "/", method: str = "GET") -> HttpResponse:
        method = method.upper()
        if method not in SAFE_METHODS:
            raise ValueError(f"unsafe method {method!r}; only {sorted(SAFE_METHODS)}")
        url = urljoin(self.base + "/", path.lstrip("/"))
        req = urllib.request.Request(
            url, method=method, headers={"User-Agent": USER_AGENT}
        )
        # Do not follow redirects offsite; capture the first response verbatim.
        opener = urllib.request.build_opener(_NoRedirect())
        try:
            with opener.open(req, timeout=self.timeout) as r:
                headers = {k.lower(): v for k, v in r.getheaders()}
                body = r.read(self.max_body).decode("utf-8", "replace")
                return HttpResponse(status=r.status, headers=headers, body=body)
        except urllib.error.HTTPError as e:
            headers = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
            body = ""
            try:
                body = e.read(self.max_body).decode("utf-8", "replace")
            except Exception:
                pass
            return HttpResponse(status=e.code, headers=headers, body=body)
        except Exception as e:  # noqa: BLE001 — surface as an inert error result
            return HttpResponse(status=0, error=str(e))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # noqa: D401
        return None


def tcp_probe(host: str, port: int, timeout: float = 2.0) -> bool:
    """Return True if a TCP connect to host:port succeeds. Connect-only; the socket
    is closed immediately — no data is sent."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def tls_info(host: str, port: int = 443, timeout: float = 5.0) -> dict[str, Any] | None:
    """Return TLS metadata (negotiated version, cert not-after) or None on failure.
    Performs a normal handshake only; sends no application data."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
    except Exception:
        return None
    not_after = None
    days_left = None
    if cert and cert.get("notAfter"):
        try:
            exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            not_after = exp.isoformat()
            days_left = (exp - datetime.now(timezone.utc)).days
        except Exception:
            pass
    return {"version": version, "not_after": not_after, "days_left": days_left}


def default_https_port(target: str) -> int:
    parsed = urlparse(target if "://" in target else "//" + target)
    return parsed.port or (443 if str(parsed.scheme).lower() == "https" else 443)
