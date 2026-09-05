"""Risky HTTP method validation (OPTIONS inspection only)."""

from __future__ import annotations

from typing import Any

from simcore.base import Finding, ScenarioResult, SimulationScenario

RISKY = {"TRACE", "TRACK", "CONNECT", "PUT", "DELETE", "PATCH"}


class HttpMethodsScenario(SimulationScenario):
    name = "http_methods"
    title = "HTTP Method Hygiene"
    description = "Inspects advertised HTTP methods for risky verbs (via OPTIONS)."
    target_kinds = ("url", "domain", "hostname", "ip")
    groups = ("standard", "deep")
    attack = ("T1190",)

    def simulate(self, target: str, ctx: dict[str, Any]) -> ScenarioResult:
        def run() -> ScenarioResult:
            resp = ctx["fetch"]("/", method="OPTIONS")
            if resp.status == 0:
                return ScenarioResult(self.name, target, control_passed=True,
                                      raw_evidence={"allow": None,
                                                    "note": resp.error or "no OPTIONS"})
            allow = resp.header("allow")
            advertised = {m.strip().upper() for m in allow.split(",") if m.strip()}
            risky = sorted(advertised & RISKY)
            findings: list[Finding] = []
            if risky:
                findings.append(Finding(
                    scenario=self.name, target=target, severity="low",
                    title="Risky HTTP Methods Advertised",
                    detail="OPTIONS advertises: " + ", ".join(risky),
                    attack=self.attack, remediation_key="open-service-port",
                    evidence={"risky_methods": risky, "allow": allow},
                ))
            return ScenarioResult(self.name, target, findings=findings,
                                  control_passed=not findings,
                                  raw_evidence={"allow": allow})

        return self._timed(run)
