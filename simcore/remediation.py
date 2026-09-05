"""
remediation.py — the shared remediation & compliance catalog.

One source of truth for "what does this finding mean and how do I fix it", consumed
by the engine's reports AND (exported to JSON) by the dashboard. Keyed by a scenario
finding's ``remediation_key``. White-labeled: guidance names controls and frameworks,
never the tooling that detected the gap.
"""

from __future__ import annotations

from typing import Any

# key -> guidance. `frameworks` are compliance references; `attack` is informational.
CATALOG: dict[str, dict[str, Any]] = {
    "missing-hsts": {
        "title": "Strict-Transport-Security not enforced",
        "impact": "Without HSTS a client can be downgraded to plaintext HTTP, "
        "enabling interception of session material on the first request.",
        "steps": [
            "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on all HTTPS responses.",
            "Preload only after verifying every subdomain supports HTTPS.",
            "Redirect all HTTP to HTTPS at the edge.",
        ],
        "priority": "High",
        "effort": "Low",
        "frameworks": ["OWASP A05", "NIST SC-8", "CIS 3.10", "PCI 4.1"],
    },
    "missing-content-security-policy": {
        "title": "Content-Security-Policy absent",
        "impact": "No CSP means injected script executes freely, raising the impact "
        "of any cross-site scripting flaw to full session compromise.",
        "steps": [
            "Deploy a `Content-Security-Policy` starting from `default-src 'self'`.",
            "Remove inline scripts/handlers; move to external files or nonces.",
            "Roll out in `Content-Security-Policy-Report-Only` first, then enforce.",
        ],
        "priority": "High",
        "effort": "Medium",
        "frameworks": ["OWASP A03", "NIST SC-18", "CIS 18", "ISO A.14"],
    },
    "missing-x-frame-options": {
        "title": "Clickjacking protection missing",
        "impact": "The page can be framed by an attacker to trick users into "
        "clicking hidden controls (UI redress).",
        "steps": [
            "Send `X-Frame-Options: DENY` (or SAMEORIGIN where framing is required).",
            "Prefer a CSP `frame-ancestors` directive for modern browsers.",
        ],
        "priority": "Medium",
        "effort": "Low",
        "frameworks": ["OWASP A05", "NIST SC-18", "CIS 18"],
    },
    "missing-x-content-type-options": {
        "title": "MIME-sniffing not disabled",
        "impact": "Browsers may reinterpret a response's content type, turning an "
        "uploaded file into executable content.",
        "steps": ["Send `X-Content-Type-Options: nosniff` on every response."],
        "priority": "Low",
        "effort": "Low",
        "frameworks": ["OWASP A05", "NIST SC-18"],
    },
    "server-version-disclosure": {
        "title": "Server/software version disclosed",
        "impact": "Version banners let an attacker fingerprint the stack and target "
        "known vulnerabilities precisely.",
        "steps": [
            "Suppress or genericize the `Server` header at the web tier.",
            "Remove `X-Powered-By` and framework version banners.",
        ],
        "priority": "Low",
        "effort": "Low",
        "frameworks": ["OWASP A05", "NIST CM-6", "CIS 4"],
    },
    "cookie-without-secure-flag": {
        "title": "Session cookie missing hardening flags",
        "impact": "A cookie without Secure/HttpOnly can be sent over plaintext or "
        "read by injected script, exposing the session.",
        "steps": [
            "Set `Secure`, `HttpOnly`, and `SameSite=Strict|Lax` on session cookies.",
            "Scope cookies with an explicit `Path` and `Domain`.",
        ],
        "priority": "Medium",
        "effort": "Low",
        "frameworks": ["OWASP A05", "NIST SC-23", "PCI 6.5"],
    },
    "tls-certificate-expiring": {
        "title": "TLS certificate near expiry",
        "impact": "An expired certificate breaks trust and availability and can "
        "train users to click through warnings.",
        "steps": [
            "Renew before expiry and automate renewal (e.g. ACME).",
            "Alert at 30/14/7 days remaining.",
        ],
        "priority": "High",
        "effort": "Low",
        "frameworks": ["NIST SC-12", "CIS 3.10", "PCI 4.1"],
    },
    "weak-tls-version": {
        "title": "Legacy TLS version offered",
        "impact": "TLS 1.0/1.1 carry known weaknesses and fail modern compliance "
        "baselines.",
        "steps": [
            "Disable TLS 1.0/1.1; require TLS 1.2+ (prefer 1.3).",
            "Restrict to strong AEAD cipher suites.",
        ],
        "priority": "High",
        "effort": "Medium",
        "frameworks": ["PCI 4.1", "NIST SC-8", "OWASP A02"],
    },
    "exposed-sensitive-path": {
        "title": "Sensitive path reachable",
        "impact": "An exposed admin/config/metadata path widens the attack surface "
        "and may leak configuration or credentials.",
        "steps": [
            "Restrict the path by authentication and network ACL.",
            "Return 404 for probes from untrusted networks; monitor access.",
        ],
        "priority": "Medium",
        "effort": "Medium",
        "frameworks": ["OWASP A01", "NIST AC-3", "CIS 4"],
    },
    "open-service-port": {
        "title": "Unexpected service port reachable",
        "impact": "An exposed service enlarges the attack surface and may be an "
        "unmanaged or forgotten listener.",
        "steps": [
            "Confirm the service is required and hardened.",
            "Restrict access with host/network firewalls to known clients.",
        ],
        "priority": "Medium",
        "effort": "Medium",
        "frameworks": ["CIS 4", "NIST SC-7", "OWASP A05"],
    },
    "missing-referrer-policy": {
        "title": "Referrer-Policy not set",
        "impact": "Full referrer URLs may leak to third parties, exposing internal "
        "paths or tokens embedded in URLs.",
        "steps": ["Send `Referrer-Policy: no-referrer` or `strict-origin-when-cross-origin`."],
        "priority": "Low",
        "effort": "Low",
        "frameworks": ["OWASP A05", "NIST SC-8"],
    },
    "missing-permissions-policy": {
        "title": "Permissions-Policy not set",
        "impact": "Powerful browser features (camera, geolocation) are not "
        "explicitly constrained.",
        "steps": ["Send a restrictive `Permissions-Policy` disabling unused features."],
        "priority": "Low",
        "effort": "Low",
        "frameworks": ["OWASP A05"],
    },
}

_DEFAULT = {
    "title": "Security control gap",
    "impact": "Review this finding and validate the affected control.",
    "steps": ["Review the finding detail and apply your control baseline."],
    "priority": "Medium",
    "effort": "Medium",
    "frameworks": ["OWASP", "NIST"],
}


def guidance_for(key: str) -> dict[str, Any]:
    """Return remediation guidance for a finding key (never raises)."""
    return dict(CATALOG.get(key, _DEFAULT))


def export() -> dict[str, Any]:
    """Full catalog for the dashboard to consume as JSON."""
    return {"version": 1, "catalog": CATALOG}
