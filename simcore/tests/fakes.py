"""Deterministic test doubles: an HTTP response fixture and a probe context."""

from __future__ import annotations

from typing import Any

from simcore.net import HttpResponse
from simcore.scope import Authorization


def make_ctx(
    responses: dict[str, HttpResponse] | None = None,
    default: HttpResponse | None = None,
    open_ports: set[int] | None = None,
    tls: dict[str, Any] | None = None,
    host: str = "127.0.0.1",
    scheme: str = "http",
) -> dict[str, Any]:
    """Build a scenario ctx whose probes are fully in-memory."""
    responses = responses or {}
    default = default or HttpResponse(status=200, headers={}, body="")
    open_ports = open_ports or set()

    def fetch(path: str = "/", method: str = "GET") -> HttpResponse:
        return responses.get(f"{method}:{path}", responses.get(path, default))

    return {
        "host": host,
        "scheme": scheme,
        "fetch": fetch,
        "tcp_probe": lambda port: port in open_ports,
        "tls_info": lambda: tls,
        "authorization": Authorization(
            target=f"{scheme}://{host}", host=host, roe_id="SANDBOX",
            authorized_by="test", reason="test", sandbox=True),
    }


def vulnerable_response() -> HttpResponse:
    return HttpResponse(
        status=200,
        headers={"server": "OldServer/1.2.3", "set-cookie": "session=abc; Path=/"},
        body="hello",
    )


def hardened_response() -> HttpResponse:
    return HttpResponse(
        status=200,
        headers={
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
            "set-cookie": "session=abc; Path=/; Secure; HttpOnly; SameSite=Strict",
        },
        body="hello",
    )
