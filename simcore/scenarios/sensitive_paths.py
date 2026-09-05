"""Sensitive-path exposure validation (passive GET probes of a fixed allowlist)."""

from __future__ import annotations

from typing import Any

from simcore.base import Finding, ScenarioResult, SimulationScenario

# A small, fixed set of well-known sensitive paths. GET only; a reachable (<400)
# response is reported as an exposure. No content is submitted, nothing is altered.
PATHS = [
    "/.git/HEAD",
    "/.env",
    "/server-status",
    "/actuator/health",
    "/.well-known/security.txt",
    "/admin",
    "/phpinfo.php",
    "/config.json",
]


class SensitivePathsScenario(SimulationScenario):
    name = "sensitive_paths"
    title = "Sensitive Path Exposure"
    description = "Checks whether well-known sensitive paths are reachable."
    target_kinds = ("url", "domain", "hostname", "ip")
    groups = ("standard", "deep")
    attack = ("T1595.003",)  # Active Scanning: Wordlist Scanning (bounded, safe)

    def simulate(self, target: str, ctx: dict[str, Any]) -> ScenarioResult:
        def run() -> ScenarioResult:
            findings: list[Finding] = []
            probed = {}
            for path in PATHS:
                resp = ctx["fetch"](path)
                probed[path] = resp.status
                # security.txt being present is good hygiene, not a finding.
                if path == "/.well-known/security.txt":
                    continue
                if 200 <= resp.status < 400:
                    findings.append(Finding(
                        scenario=self.name, target=target, severity="medium",
                        title=f"Sensitive Path Reachable: {path}",
                        detail=f"{path} returned HTTP {resp.status}.",
                        attack=self.attack, remediation_key="exposed-sensitive-path",
                        evidence={"path": path, "status": resp.status},
                    ))
            return ScenarioResult(self.name, target, findings=findings,
                                  control_passed=not findings,
                                  raw_evidence={"probed": probed})

        return self._timed(run)
