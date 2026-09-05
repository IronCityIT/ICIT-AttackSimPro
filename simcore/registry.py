"""
registry.py — discover scenarios and resolve selections.

Selection is the product surface: run one scenario, a few (``--scenarios a,b``), or a
named group (``--group deep``). This module discovers every ``SimulationScenario`` in
``simcore.scenarios`` and powers BOTH the CLI selection and the dashboard's scenario
library (via :func:`catalog`), so the two can never drift.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import Any

from simcore import scenarios as scenarios_pkg
from simcore.base import GROUPS, SimulationScenario


def discover() -> dict[str, SimulationScenario]:
    """Instantiate every concrete SimulationScenario under simcore.scenarios."""
    found: dict[str, SimulationScenario] = {}
    for _, modname, _ in pkgutil.iter_modules(scenarios_pkg.__path__):
        module = importlib.import_module(f"{scenarios_pkg.__name__}.{modname}")
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, SimulationScenario)
                and obj is not SimulationScenario
                and not inspect.isabstract(obj)
            ):
                inst = obj()
                if not inst.name:
                    raise ValueError(f"{obj.__name__} has no name")
                if not inst.safe:
                    # A non-safe scenario must never be registered in this product.
                    raise ValueError(f"scenario {inst.name!r} is not marked safe")
                if inst.name in found:
                    raise ValueError(f"duplicate scenario name {inst.name!r}")
                found[inst.name] = inst
    return found


def select(
    names: list[str] | None = None,
    group: str | None = None,
) -> list[SimulationScenario]:
    """Resolve a selection into an ordered list of scenarios.

    * ``names`` — explicit scenario ids (unknown ids raise).
    * ``group`` — a named preset; all scenarios in that group.
    * neither  — the ``standard`` group.
    """
    catalog = discover()
    if names:
        missing = [n for n in names if n not in catalog]
        if missing:
            raise KeyError(f"unknown scenario(s): {', '.join(missing)}")
        return [catalog[n] for n in names]
    grp = group or "standard"
    if grp not in GROUPS:
        raise KeyError(f"unknown group {grp!r}; choose from {GROUPS}")
    chosen = [s for s in catalog.values() if grp in s.groups]
    return sorted(chosen, key=lambda s: s.name)


def all_groups() -> list[str]:
    return list(GROUPS)


def catalog() -> dict[str, Any]:
    """The scenario library as data — the shared CLI/UI source of truth."""
    scen = discover()
    return {
        "version": 1,
        "groups": list(GROUPS),
        "scenarios": [s.catalog_entry() for s in sorted(scen.values(), key=lambda s: s.name)],
    }
