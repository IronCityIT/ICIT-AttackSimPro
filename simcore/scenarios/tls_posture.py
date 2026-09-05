"""TLS posture validation (passive handshake only)."""

from __future__ import annotations

from typing import Any

from simcore.base import Finding, ScenarioResult, SimulationScenario

WEAK_VERSIONS = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"}
EXPIRY_WARN_DAYS = 30


class TlsPostureScenario(SimulationScenario):
    name = "tls_posture"
    title = "Transport Security Posture"
    description = "Validates TLS version and certificate validity via a handshake."
    target_kinds = ("url", "domain", "hostname", "ip")
    groups = ("standard", "deep", "compliance")
    attack = ("T1040",)  # Network Sniffing (control validation)

    def simulate(self, target: str, ctx: dict[str, Any]) -> ScenarioResult:
        def run() -> ScenarioResult:
            info = ctx["tls_info"]()
            if not info:
                # No TLS reachable is not a finding by itself (target may be HTTP
                # loopback fixture); record it as evidence, control not applicable.
                return ScenarioResult(self.name, target, control_passed=True,
                                      raw_evidence={"tls": None})
            findings: list[Finding] = []
            version = info.get("version") or ""
            if version in WEAK_VERSIONS:
                findings.append(Finding(
                    scenario=self.name, target=target, severity="high",
                    title="Legacy TLS Version Offered",
                    detail=f"Negotiated {version}; require TLS 1.2+.",
                    attack=self.attack, remediation_key="weak-tls-version",
                    evidence={"version": version},
                ))
            days = info.get("days_left")
            if isinstance(days, int):
                if days < 0:
                    sev, title = "critical", "TLS Certificate Expired"
                elif days <= EXPIRY_WARN_DAYS:
                    sev, title = "high", "TLS Certificate Expiring Soon"
                else:
                    sev = title = None
                if sev:
                    findings.append(Finding(
                        scenario=self.name, target=target, severity=sev, title=title,
                        detail=f"Certificate expires in {days} day(s).",
                        attack=self.attack, remediation_key="tls-certificate-expiring",
                        evidence={"days_left": days, "not_after": info.get("not_after")},
                    ))
            return ScenarioResult(self.name, target, findings=findings,
                                  control_passed=not findings, raw_evidence={"tls": info})

        return self._timed(run)
