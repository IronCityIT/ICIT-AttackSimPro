"""
scope.py — authorization & scope enforcement (the safety core).

AttackSimPro must only ever act against targets it is *authorized* to touch. This
module is the single gate every run passes through. Nothing in the engine reaches a
target without ``Scope.authorize(target)`` returning an ``Authorization``.

Two independent guards, both must pass:

  1. **Sandbox guard (default-deny for the internet).** Unless a run explicitly opts
     into external targets (``allow_external=True``) AND a matching authorization
     record exists, only loopback and RFC-1918 / RFC-4193 private targets are
     permitted. A bare ``asp`` run can never reach a public host by accident.

  2. **Authorization record (Rules of Engagement).** An authorization file declares
     who authorized the assessment, the ROE reference, the exact in-scope hosts /
     CIDRs, and an optional time window. External targets require a matching record;
     a target outside every record's scope is refused.

A refusal is a hard error (``ScopeError``) — never a warning that a run can ignore.
"""

from __future__ import annotations

import ipaddress
import json
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


class ScopeError(Exception):
    """Raised when a target is not authorized. Runs must treat this as fatal."""


@dataclass(frozen=True)
class Authorization:
    """The recorded permission under which a target may be assessed."""

    target: str
    host: str
    roe_id: str
    authorized_by: str
    reason: str
    sandbox: bool  # True when permitted purely by the loopback/private-range guard

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "host": self.host,
            "roe_id": self.roe_id,
            "authorized_by": self.authorized_by,
            "reason": self.reason,
            "sandbox": self.sandbox,
        }


@dataclass
class AuthorizationRecord:
    """One ROE / authorization document loaded from ``authorizations/``."""

    roe_id: str
    client: str
    authorized_by: str
    hosts: list[str] = field(default_factory=list)  # exact hostnames / IPs
    cidrs: list[str] = field(default_factory=list)  # CIDR blocks
    not_before: str | None = None  # ISO 8601
    not_after: str | None = None  # ISO 8601
    reason: str = ""

    def window_ok(self, now: datetime) -> bool:
        if self.not_before and now < _parse_iso(self.not_before):
            return False
        if self.not_after and now > _parse_iso(self.not_after):
            return False
        return True

    def matches(self, host: str, ip: ipaddress._BaseAddress | None) -> bool:
        if host in self.hosts:
            return True
        if ip is not None:
            for cidr in self.cidrs:
                try:
                    if ip in ipaddress.ip_network(cidr, strict=False):
                        return True
                except ValueError:
                    continue
        return False


def _parse_iso(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def host_of(target: str) -> str:
    """Extract the host from a URL, or return the bare host/IP unchanged."""
    t = target.strip()
    if "://" in t:
        parsed = urlparse(t)
        return parsed.hostname or ""
    # host:port or bare host
    if t.count(":") == 1 and not t.startswith("["):
        return t.split(":", 1)[0]
    return t


def _resolve_ip(host: str) -> ipaddress._BaseAddress | None:
    """Resolve a host to an IP for range checks. Literal IPs pass straight through."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
        # If a host resolves to multiple addresses, use the first; range checks
        # below still see every record.
        return ipaddress.ip_address(infos[0][4][0])
    except Exception:
        return None


def is_private_or_loopback(ip: ipaddress._BaseAddress | None) -> bool:
    if ip is None:
        return False
    return bool(ip.is_loopback or ip.is_private or ip.is_link_local)


class Scope:
    """Loads authorization records and authorizes individual targets.

    Parameters
    ----------
    allow_external:
        When False (default) only loopback/private targets are permitted, even if an
        authorization record would otherwise allow a public host. This is the belt to
        the authorization record's braces: an operator must consciously opt in.
    records:
        Loaded ``AuthorizationRecord`` list (usually via :meth:`from_dir`).
    now:
        Injectable clock for deterministic window tests.
    """

    def __init__(
        self,
        records: list[AuthorizationRecord] | None = None,
        allow_external: bool = False,
        now: datetime | None = None,
    ) -> None:
        self.records = records or []
        self.allow_external = allow_external
        self._now = now or datetime.now(timezone.utc)

    @classmethod
    def from_dir(
        cls,
        directory: str | Path,
        allow_external: bool = False,
        now: datetime | None = None,
    ) -> "Scope":
        records: list[AuthorizationRecord] = []
        d = Path(directory)
        if d.is_dir():
            for path in sorted(d.iterdir()):
                if path.suffix.lower() in (".yaml", ".yml", ".json"):
                    records.extend(_load_records(path))
        return cls(records=records, allow_external=allow_external, now=now)

    def authorize(self, target: str) -> Authorization:
        """Return an :class:`Authorization` or raise :class:`ScopeError`."""
        host = host_of(target)
        if not host:
            raise ScopeError(f"cannot determine host for target {target!r}")

        ip = _resolve_ip(host)
        sandbox = is_private_or_loopback(ip)

        # Guard 1: sandbox. Loopback/private is always allowed (that is the point of
        # the sandbox: safe, self-contained fixtures).
        if sandbox:
            return Authorization(
                target=target,
                host=host,
                roe_id="SANDBOX",
                authorized_by="sandbox-policy",
                reason="loopback/private-range fixture",
                sandbox=True,
            )

        # Beyond the sandbox, an explicit opt-in is mandatory.
        if not self.allow_external:
            raise ScopeError(
                f"refusing external target {host!r}: not loopback/private and "
                "--allow-external was not given"
            )

        # Guard 2: a matching, in-window authorization record must exist.
        for rec in self.records:
            if not rec.window_ok(self._now):
                continue
            if rec.matches(host, ip):
                return Authorization(
                    target=target,
                    host=host,
                    roe_id=rec.roe_id,
                    authorized_by=rec.authorized_by,
                    reason=rec.reason or "matched authorization record",
                    sandbox=False,
                )

        raise ScopeError(
            f"refusing target {host!r}: no in-scope, in-window authorization record "
            "matched (declare it under authorizations/)"
        )


def _load_records(path: Path) -> list[AuthorizationRecord]:
    text = path.read_text(encoding="utf-8")
    data: Any
    if path.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        import yaml  # PyYAML is present in the ICIT toolchain

        data = yaml.safe_load(text)
    if data is None:
        return []
    items = data if isinstance(data, list) else [data]
    records = []
    for item in items:
        records.append(
            AuthorizationRecord(
                roe_id=str(item.get("roe_id", path.stem)),
                client=str(item.get("client", "")),
                authorized_by=str(item.get("authorized_by", "")),
                hosts=list(item.get("hosts", []) or []),
                cidrs=list(item.get("cidrs", []) or []),
                not_before=item.get("not_before"),
                not_after=item.get("not_after"),
                reason=str(item.get("reason", "")),
            )
        )
    return records
