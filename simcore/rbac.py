"""
rbac.py — role-based access control for AttackSimPro actions.

Three roles, least-privilege by default:

  * ``viewer``   — read results and reports only.
  * ``operator`` — run and schedule simulations, export evidence.
  * ``admin``    — everything, plus manage authorization records and roles.

Actions are checked with :func:`require`, which raises :class:`AccessDenied` (and the
caller is expected to audit the denial). This is deliberately simple and explicit —
authorization decisions in a security product must be readable at a glance.
"""

from __future__ import annotations

ROLES = ("viewer", "operator", "admin")

# action -> minimum roles permitted
_PERMISSIONS: dict[str, set[str]] = {
    "view_results": {"viewer", "operator", "admin"},
    "export_evidence": {"viewer", "operator", "admin"},
    "run_simulation": {"operator", "admin"},
    "schedule_simulation": {"operator", "admin"},
    "ingest_results": {"operator", "admin"},
    "manage_authorizations": {"admin"},
    "manage_roles": {"admin"},
}


class AccessDenied(Exception):
    """Raised when a role is not permitted to perform an action."""


def can(role: str, action: str) -> bool:
    if action not in _PERMISSIONS:
        raise KeyError(f"unknown action {action!r}")
    return role in _PERMISSIONS[action]


def require(role: str, action: str) -> None:
    if role not in ROLES:
        raise AccessDenied(f"unknown role {role!r}")
    if not can(role, action):
        raise AccessDenied(f"role {role!r} may not {action}")


def actions() -> list[str]:
    return sorted(_PERMISSIONS)
