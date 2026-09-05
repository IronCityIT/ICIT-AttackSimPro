"""
AttackSimPro safe simulation engine (``simcore``).

A modular, authorized, non-destructive Purple-Team validation engine. Each capability
is one scenario (``simcore.scenarios``); a scope gate (``simcore.scope``) authorizes
every target; runs emit signed evidence bundles (``simcore.evidence``) and white-
labeled reports (``simcore.reporting``); actions are RBAC-gated (``simcore.rbac``) and
recorded in a tamper-evident audit trail (``simcore.audit``).

Stdlib-only at runtime (PyYAML optional, for YAML authorization/schedule files), so
the engine runs and tests deterministically with no network and no external services.
"""

__version__ = "2.0.0"
