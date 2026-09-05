"""Web security-header baseline validation (passive)."""

from __future__ import annotations

from typing import Any

from simcore.base import Finding, ScenarioResult, SimulationScenario

# (header, finding title, severity, remediation_key)
REQUIRED = [
    ("strict-transport-security", "Missing HSTS", "medium", "missing-hsts"),
    ("content-security-policy", "Missing Content-Security-Policy", "medium",
     "missing-content-security-policy"),
    ("x-frame-options", "Missing X-Frame-Options", "medium", "missing-x-frame-options"),
    ("x-content-type-options", "Missing X-Content-Type-Options", "low",
     "missing-x-content-type-options"),
    ("referrer-policy", "Missing Referrer-Policy", "low", "missing-referrer-policy"),
    ("permissions-policy", "Missing Permissions-Policy", "info",
     "missing-permissions-policy"),
]


class SecurityHeadersScenario(SimulationScenario):
    name = "security_headers"
    title = "Web Security Baseline"
    description = "Validates that standard HTTP security response headers are enforced."
    target_kinds = ("url", "domain", "hostname", "ip")
    groups = ("quick", "standard", "compliance")
    attack = ("T1190",)  # Exploit Public-Facing Application (control validation)

    def simulate(self, target: str, ctx: dict[str, Any]) -> ScenarioResult:
        def run() -> ScenarioResult:
            resp = ctx["fetch"]("/")
            if resp.status == 0:
                return ScenarioResult(self.name, target, control_passed=False,
                                      error=resp.error or "no response")
            findings: list[Finding] = []
            for hdr, title, sev, key in REQUIRED:
                if not resp.header(hdr):
                    findings.append(Finding(
                        scenario=self.name, target=target, severity=sev, title=title,
                        detail=f"Response omits the {hdr} header.",
                        attack=self.attack, remediation_key=key,
                        evidence={"header": hdr, "present": False},
                    ))
            return ScenarioResult(
                self.name, target, findings=findings,
                control_passed=not findings,
                raw_evidence={"status": resp.status,
                              "observed_headers": sorted(resp.headers.keys())},
            )

        return self._timed(run)
