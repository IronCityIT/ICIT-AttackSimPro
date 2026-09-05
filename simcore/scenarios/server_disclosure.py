"""Server/software version disclosure check (passive)."""

from __future__ import annotations

from typing import Any

from simcore.base import Finding, ScenarioResult, SimulationScenario


class ServerDisclosureScenario(SimulationScenario):
    name = "server_disclosure"
    title = "Software Version Exposure"
    description = "Detects server/software version banners that aid fingerprinting."
    target_kinds = ("url", "domain", "hostname", "ip")
    groups = ("quick", "standard")
    attack = ("T1592.002",)  # Gather Victim Host Information: Software

    def simulate(self, target: str, ctx: dict[str, Any]) -> ScenarioResult:
        def run() -> ScenarioResult:
            resp = ctx["fetch"]("/")
            if resp.status == 0:
                return ScenarioResult(self.name, target, control_passed=False,
                                      error=resp.error or "no response")
            findings: list[Finding] = []
            server = resp.header("server")
            powered = resp.header("x-powered-by")
            if server and any(c.isdigit() for c in server):
                findings.append(Finding(
                    scenario=self.name, target=target, severity="info",
                    title="Server Version Disclosure",
                    detail=f"Server header reveals version: {server}",
                    attack=self.attack, remediation_key="server-version-disclosure",
                    evidence={"server": server},
                ))
            if powered:
                findings.append(Finding(
                    scenario=self.name, target=target, severity="info",
                    title="Framework Version Disclosure",
                    detail=f"X-Powered-By reveals: {powered}",
                    attack=self.attack, remediation_key="server-version-disclosure",
                    evidence={"x_powered_by": powered},
                ))
            return ScenarioResult(self.name, target, findings=findings,
                                  control_passed=not findings,
                                  raw_evidence={"server": server, "x_powered_by": powered})

        return self._timed(run)
