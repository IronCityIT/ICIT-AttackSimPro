"""
scheduler.py — scenario scheduling (cron expressions) and run planning.

A schedule file declares named entries: a cron expression, a scenario selection, and
the targets. The scheduler computes the next run time for each entry and emits a plan.
Scheduling NEVER bypasses safety: the scheduler only decides *when*; every execution
still goes through runner.run, which enforces RBAC and the scope/authorization gate.

The cron parser is a small, dependency-free 5-field implementation
(minute hour day-of-month month day-of-week) supporting ``*``, ``*/n``, ``a-b``,
and comma lists.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

_FIELD_RANGES = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 6)]  # min hr dom mon dow


def _parse_field(spec: str, lo: int, hi: int) -> set[int]:
    values: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        step = 1
        if "/" in part:
            part, step_s = part.split("/", 1)
            step = int(step_s)
            if step <= 0:
                raise ValueError("cron step must be positive")
        if part in ("*", ""):
            start, end = lo, hi
        elif "-" in part:
            a, b = part.split("-", 1)
            start, end = int(a), int(b)
        else:
            start = end = int(part)
        if start < lo or end > hi or start > end:
            raise ValueError(f"cron field out of range: {spec!r}")
        values.update(range(start, end + 1, step))
    return values


@dataclass
class CronSchedule:
    minute: set[int]
    hour: set[int]
    dom: set[int]
    month: set[int]
    dow: set[int]
    expr: str = ""

    @classmethod
    def parse(cls, expr: str) -> "CronSchedule":
        fields = expr.split()
        if len(fields) != 5:
            raise ValueError(f"cron must have 5 fields, got {len(fields)}: {expr!r}")
        parsed = [
            _parse_field(f, lo, hi)
            for f, (lo, hi) in zip(fields, _FIELD_RANGES)
        ]
        return cls(*parsed, expr=expr)  # type: ignore[arg-type]

    def matches(self, dt: datetime) -> bool:
        # cron day-of-week: Sunday is 0; Python weekday() has Monday 0.
        dow = (dt.weekday() + 1) % 7
        return (
            dt.minute in self.minute
            and dt.hour in self.hour
            and dt.day in self.dom
            and dt.month in self.month
            and dow in self.dow
        )

    def next_run(self, after: datetime) -> datetime:
        # Step minute by minute up to ~1 year ahead; simple and correct.
        cur = after.replace(second=0, microsecond=0) + timedelta(minutes=1)
        for _ in range(367 * 24 * 60):
            if self.matches(cur):
                return cur
            cur += timedelta(minutes=1)
        raise ValueError(f"no run time within a year for {self.expr!r}")


@dataclass
class ScheduleEntry:
    name: str
    cron: str
    targets: list[str]
    scenarios: list[str] = field(default_factory=list)
    group: str | None = None
    client_name: str = ""
    role: str = "operator"
    enabled: bool = True

    def schedule(self) -> CronSchedule:
        return CronSchedule.parse(self.cron)


def load_schedule(path: str | Path) -> list[ScheduleEntry]:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        import yaml

        data = yaml.safe_load(text)
    items = data.get("schedules", data) if isinstance(data, dict) else data
    entries = []
    for item in items or []:
        entries.append(ScheduleEntry(
            name=str(item["name"]),
            cron=str(item["cron"]),
            targets=list(item.get("targets", []) or []),
            scenarios=list(item.get("scenarios", []) or []),
            group=item.get("group"),
            client_name=str(item.get("client_name", "")),
            role=str(item.get("role", "operator")),
            enabled=bool(item.get("enabled", True)),
        ))
    return entries


def plan(entries: list[ScheduleEntry], now: datetime | None = None) -> list[dict[str, Any]]:
    now = now or datetime.now(timezone.utc)
    out = []
    for e in entries:
        if not e.enabled:
            out.append({"name": e.name, "enabled": False, "next_run": None})
            continue
        nxt = e.schedule().next_run(now)
        out.append({
            "name": e.name,
            "enabled": True,
            "cron": e.cron,
            "next_run": nxt.isoformat(),
            "targets": e.targets,
            "selection": e.scenarios or f"group:{e.group or 'standard'}",
        })
    return out
