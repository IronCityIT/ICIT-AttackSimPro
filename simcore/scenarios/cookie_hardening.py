"""Session-cookie hardening validation (passive)."""

from __future__ import annotations

from typing import Any

from simcore.base import Finding, ScenarioResult, SimulationScenario


class CookieHardeningScenario(SimulationScenario):
    name = "cookie_hardening"
    title = "Session Cookie Hardening"
    description = "Checks Set-Cookie for Secure, HttpOnly, and SameSite attributes."
    target_kinds = ("url", "domain", "hostname", "ip")
    groups = ("standard", "compliance")
    attack = ("T1539",)  # Steal Web Session Cookie (control validation)

    def simulate(self, target: str, ctx: dict[str, Any]) -> ScenarioResult:
        def run() -> ScenarioResult:
            resp = ctx["fetch"]("/")
            if resp.status == 0:
                return ScenarioResult(self.name, target, control_passed=False,
                                      error=resp.error or "no response")
            cookie = resp.header("set-cookie")
            findings: list[Finding] = []
            if cookie:
                low = cookie.lower()
                missing = [a for a in ("secure", "httponly", "samesite")
                           if a not in low]
                if missing:
                    findings.append(Finding(
                        scenario=self.name, target=target, severity="low",
                        title="Session Cookie Missing Hardening Flags",
                        detail="Set-Cookie is missing: " + ", ".join(missing),
                        attack=self.attack, remediation_key="cookie-without-secure-flag",
                        evidence={"missing_attributes": missing},
                    ))
            return ScenarioResult(self.name, target, findings=findings,
                                  control_passed=not findings,
                                  raw_evidence={"set_cookie_present": bool(cookie)})

        return self._timed(run)
