"""Exposed-service validation (safe TCP connect probe of a fixed port set)."""

from __future__ import annotations

from typing import Any

from simcore.base import Finding, ScenarioResult, SimulationScenario

# Connect-only probes: the socket opens and closes immediately, no data is sent.
# Ports commonly expected to be internal-only; reachable = surface to review.
WATCH_PORTS = {
    3306: "database (MySQL)",
    5432: "database (PostgreSQL)",
    6379: "cache (Redis)",
    27017: "database (MongoDB)",
    9200: "search cluster",
    2375: "container daemon",
    5601: "ops dashboard",
}


class OpenPortsScenario(SimulationScenario):
    name = "open_ports"
    title = "Exposed Service Surface"
    description = "Connect-probes a fixed set of ports that should not be public."
    target_kinds = ("hostname", "ip", "domain")
    groups = ("deep",)
    attack = ("T1046",)  # Network Service Discovery (bounded, connect-only)

    def simulate(self, target: str, ctx: dict[str, Any]) -> ScenarioResult:
        def run() -> ScenarioResult:
            findings: list[Finding] = []
            state = {}
            for port, label in WATCH_PORTS.items():
                reachable = ctx["tcp_probe"](port)
                state[port] = reachable
                if reachable:
                    findings.append(Finding(
                        scenario=self.name, target=target, severity="medium",
                        title=f"Reachable Service Port {port}",
                        detail=f"Port {port} ({label}) accepted a TCP connection.",
                        attack=self.attack, remediation_key="open-service-port",
                        evidence={"port": port, "label": label},
                    ))
            return ScenarioResult(self.name, target, findings=findings,
                                  control_passed=not findings,
                                  raw_evidence={"ports": state})

        return self._timed(run)
