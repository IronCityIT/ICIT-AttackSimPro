"""
base.py — the contract every AttackSimPro simulation implements.

AttackSimPro is a Purple-Team *validation* product: it runs non-destructive,
audit-defensible simulations that check whether a control is present and correctly
configured, and produces repeatable evidence. It is NOT an exploit framework.

Every capability is one ``SimulationScenario`` (mirrors the shared ICIT
module_framework ScanModule pattern: one capability = one module, no monoliths).
A scenario:

  * declares what target kinds it applies to and which groups it belongs to,
  * declares its MITRE ATT&CK technique(s) so evidence is framework-mappable,
  * is SAFE by construction — it inspects/validates; it never exploits, never
    delivers a payload, never mutates the target,
  * returns a list of normalized ``Finding`` objects plus structured ``Evidence``.

The registry drives BOTH the CLI selection (``--scenarios`` / ``--group``) and the
dashboard's scenario catalog from this one source of truth.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any

# Ordered least→most severe. The engine, report, and dashboard all agree on these.
SEVERITIES: tuple[str, ...] = ("info", "low", "medium", "high", "critical")

# Scenario groups (presets). A scenario may belong to several.
GROUPS: tuple[str, ...] = ("quick", "standard", "deep", "compliance")


@dataclass
class Finding:
    """One normalized, white-labeled result. No underlying tool names leak here."""

    scenario: str
    target: str
    severity: str  # one of SEVERITIES
    title: str
    detail: str = ""
    # MITRE ATT&CK technique ids this finding validates against, e.g. ("T1190",).
    attack: tuple[str, ...] = ()
    # Machine-checkable proof of the observation (headers seen, port state, etc.).
    evidence: dict[str, Any] = field(default_factory=dict)
    # Stable key used to look up remediation guidance (see remediation.py).
    remediation_key: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(
                f"bad severity {self.severity!r}; use one of {SEVERITIES}"
            )
        if not self.remediation_key:
            # Derive a stable key from the title so remediation always resolves.
            self.remediation_key = _slug(self.title)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["attack"] = list(self.attack)
        return d


@dataclass
class ScenarioResult:
    """What a scenario hands back: findings + a passed/failed control verdict."""

    scenario: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    # True when the control being validated is present/correct (no gaps found).
    control_passed: bool = True
    # Free-form evidence captured for the bundle (request/response metadata, etc.).
    raw_evidence: dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "target": self.target,
            "control_passed": self.control_passed,
            "findings": [f.to_dict() for f in self.findings],
            "raw_evidence": self.raw_evidence,
            "duration_ms": self.duration_ms,
            "error": self.error,
        }


class SimulationScenario(ABC):
    """Base class for every safe simulation. Subclasses set the metadata and
    implement :meth:`simulate`."""

    # --- metadata (set on each subclass) -------------------------------------
    name: str = ""  # short id, e.g. "security_headers"
    title: str = ""  # client-safe display name, e.g. "Web Security Baseline"
    description: str = ""  # one line, white-labeled
    target_kinds: tuple[str, ...] = ("url", "domain", "hostname", "ip")
    groups: tuple[str, ...] = ("standard",)
    attack: tuple[str, ...] = ()  # MITRE ATT&CK technique ids covered
    # A scenario is SAFE if it only inspects/validates. This must be True for a
    # scenario to run under AttackSimPro; the runner refuses anything else.
    safe: bool = True

    def applies_to(self, kind: str) -> bool:
        return kind in self.target_kinds

    @abstractmethod
    def simulate(self, target: str, ctx: dict[str, Any]) -> ScenarioResult:
        """Run one safe simulation against ``target``.

        ``ctx`` carries run-scoped services (a ``fetcher`` HTTP callable, timeouts,
        the scope object). Implementations MUST NOT reach the network directly;
        they call ``ctx['fetcher']`` so tests can inject a deterministic double and
        the scope gate is always enforced upstream.
        """
        raise NotImplementedError

    # Convenience for building results with timing.
    def _timed(self, fn):
        start = time.monotonic()
        result = fn()
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result

    def catalog_entry(self) -> dict[str, Any]:
        """Single source of truth for CLI help + dashboard scenario library."""
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "target_kinds": list(self.target_kinds),
            "groups": list(self.groups),
            "attack": list(self.attack),
            "safe": self.safe,
        }


def _slug(text: str) -> str:
    out = []
    for ch in str(text).lower().strip():
        if ch.isalnum():
            out.append(ch)
        elif out and out[-1] != "-":
            out.append("-")
    return "".join(out).strip("-")


def severity_rank(sev: str) -> int:
    """Numeric rank for sorting/scoring; unknown severities sort as info."""
    try:
        return SEVERITIES.index(sev)
    except ValueError:
        return 0
