"""registry.py — discover report adapters (parallel to the scenario registry)."""

from __future__ import annotations

import importlib
import inspect
import pkgutil

from simcore import adapters as adapters_pkg
from simcore.adapters.base import ReportAdapter


def discover() -> dict[str, ReportAdapter]:
    found: dict[str, ReportAdapter] = {}
    for _, modname, _ in pkgutil.iter_modules(adapters_pkg.__path__):
        if modname in ("base", "registry"):
            continue
        module = importlib.import_module(f"{adapters_pkg.__name__}.{modname}")
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (issubclass(obj, ReportAdapter) and obj is not ReportAdapter
                    and not inspect.isabstract(obj)):
                inst = obj()
                if inst.name:
                    found[inst.name] = inst
    return found


def get(name: str) -> ReportAdapter:
    adapters = discover()
    if name not in adapters:
        raise KeyError(f"unknown adapter {name!r}; have {sorted(adapters)}")
    return adapters[name]


def catalog() -> list[dict]:
    return [a.catalog_entry() for a in sorted(discover().values(), key=lambda a: a.name)]
