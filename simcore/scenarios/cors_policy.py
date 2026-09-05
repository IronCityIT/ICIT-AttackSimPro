"""CORS policy validation (passive header inspection)."""

from __future__ import annotations

from typing import Any

from simcore.base import Finding, ScenarioResult, SimulationScenario


class CorsPolicyScenario(SimulationScenario):
    name = "cors_policy"
    title = "Cross-Origin Policy"
    description = "Detects over-permissive CORS (wildcard origin with credentials)."
    target_kinds = ("url", "domain", "hostname", "ip")
    groups = ("standard", "deep")
    attack = ("T1190",)

    def simulate(self, target: str, ctx: dict[str, Any]) -> ScenarioResult:
        def run() -> ScenarioResult:
            resp = ctx["fetch"]("/")
            if resp.status == 0:
                return ScenarioResult(self.name, target, control_passed=False,
                                      error=resp.error or "no response")
            origin = resp.header("access-control-allow-origin")
            creds = resp.header("access-control-allow-credentials").lower()
            findings: list[Finding] = []
            if origin == "*" and creds == "true":
                findings.append(Finding(
                    scenario=self.name, target=target, severity="high",
                    title="Over-Permissive CORS Policy",
                    detail="Wildcard origin combined with credentials is unsafe.",
                    attack=self.attack, remediation_key="exposed-sensitive-path",
                    evidence={"allow_origin": origin, "allow_credentials": creds},
                ))
            elif origin == "*":
                findings.append(Finding(
                    scenario=self.name, target=target, severity="low",
                    title="Wildcard CORS Origin",
                    detail="Access-Control-Allow-Origin is '*'.",
                    attack=self.attack, remediation_key="exposed-sensitive-path",
                    evidence={"allow_origin": origin},
                ))
            return ScenarioResult(self.name, target, findings=findings,
                                  control_passed=not findings,
                                  raw_evidence={"allow_origin": origin,
                                                "allow_credentials": creds})

        return self._timed(run)
