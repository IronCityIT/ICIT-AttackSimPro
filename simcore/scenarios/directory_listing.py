"""Directory-listing / autoindex validation (passive GET, signature match)."""

from __future__ import annotations

from typing import Any

from simcore.base import Finding, ScenarioResult, SimulationScenario

# Signatures a server autoindex page emits. Body inspection only; nothing submitted.
SIGNATURES = ("Index of /", "<title>Directory listing for", "Parent Directory")
PROBE_PATHS = ("/", "/uploads/", "/files/", "/backup/")


class DirectoryListingScenario(SimulationScenario):
    name = "directory_listing"
    title = "Directory Listing Exposure"
    description = "Detects server directory autoindex pages that leak file structure."
    target_kinds = ("url", "domain", "hostname", "ip")
    groups = ("deep",)
    attack = ("T1083",)  # File and Directory Discovery (control validation)

    def simulate(self, target: str, ctx: dict[str, Any]) -> ScenarioResult:
        def run() -> ScenarioResult:
            findings: list[Finding] = []
            checked = {}
            for path in PROBE_PATHS:
                resp = ctx["fetch"](path)
                hit = 200 <= resp.status < 300 and any(s in resp.body for s in SIGNATURES)
                checked[path] = {"status": resp.status, "listing": hit}
                if hit:
                    findings.append(Finding(
                        scenario=self.name, target=target, severity="medium",
                        title=f"Directory Listing Enabled: {path}",
                        detail=f"{path} returns an autoindex page.",
                        attack=self.attack, remediation_key="exposed-sensitive-path",
                        evidence={"path": path, "status": resp.status},
                    ))
            return ScenarioResult(self.name, target, findings=findings,
                                  control_passed=not findings,
                                  raw_evidence={"checked": checked})

        return self._timed(run)
