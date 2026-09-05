"""base.py — the report-adapter contract + shared ATT&CK severity mapping."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from simcore.base import Finding

# Which ATT&CK tactic a successfully-executed technique belongs to drives severity:
# the more damaging the tactic, the more serious an *unblocked* execution is.
_TACTIC_SEVERITY = {
    "impact": "critical",
    "exfiltration": "high",
    "credential-access": "high",
    "lateral-movement": "high",
    "privilege-escalation": "high",
    "command-and-control": "high",
    "initial-access": "high",
    "persistence": "medium",
    "defense-evasion": "medium",
    "collection": "medium",
    "discovery": "medium",
    "execution": "medium",
    "credential access": "high",
    "lateral movement": "high",
    "privilege escalation": "high",
    "command and control": "high",
    "initial access": "high",
    "defense evasion": "medium",
    "reconnaissance": "low",
    "resource-development": "low",
    "resource development": "low",
}


def tactic_severity(tactic: str) -> str:
    return _TACTIC_SEVERITY.get(str(tactic or "").strip().lower(), "medium")


class ReportAdapter(ABC):
    """Base class for a BAS/adversary-emulation report adapter.

    Subclasses set ``name`` / ``title`` (white-labeled) and implement :meth:`parse`,
    which turns already-collected operation output into normalized ``Finding`` objects.
    Adapters NEVER execute anything — they read a report that already exists.
    """

    name: str = ""  # internal id, e.g. "caldera"
    title: str = ""  # white-labeled display, e.g. "Automated Adversary Emulation"
    description: str = ""

    @abstractmethod
    def parse(self, data: Any, target_label: str = "") -> list[Finding]:
        """Normalize a parsed report object into findings (may be empty)."""
        raise NotImplementedError

    def catalog_entry(self) -> dict[str, Any]:
        return {"name": self.name, "title": self.title, "description": self.description}
