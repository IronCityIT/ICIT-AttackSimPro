#!/usr/bin/env python3
"""
Passive security-header scanner — AttackSimPro safe simulation module.

Fetches a URL with a single GET and inspects response headers ONLY. It sends no
payloads, follows no redirects offsite, performs no exploitation. This mirrors
what the product's header/TLS validation does conceptually: non-destructive,
audit-defensible posture checks. Output is a scan payload in the exact shape the
storeScanResults ingest expects, so a simulation can flow end to end:

    target -> passive scan -> findings -> POST /storeScanResults -> Firestore shape

Usage:
    python3 passive_header_scan.py --target http://127.0.0.1:9101 \
        --client "Acme Corp" --scan-id scan-local-1 [--post http://127.0.0.1:8088/]

Only http/https URLs are accepted, and (unless --allow-remote) only loopback
hosts, so a simulation cannot be pointed at a third-party system by accident.
"""
import argparse
import ipaddress
import json
import socket
import sys
import urllib.request
import urllib.error
from urllib.parse import urlparse

# (header, finding name, severity) for headers whose ABSENCE is a finding.
REQUIRED_HEADERS = [
    ("strict-transport-security", "Missing HSTS", "medium"),
    ("content-security-policy", "Missing Content-Security-Policy", "medium"),
    ("x-frame-options", "Missing X-Frame-Options", "medium"),
    ("x-content-type-options", "Missing X-Content-Type-Options", "low"),
]


def is_loopback(host):
    try:
        for res in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(res[4][0])
            if not ip.is_loopback:
                return False
        return True
    except Exception:
        return False


def scan(target):
    """Return (findings, summary) from a single passive GET."""
    req = urllib.request.Request(target, method="GET", headers={"User-Agent": "AttackSimPro-PassiveScan/1.0"})
    findings = []
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            headers = {k.lower(): v for k, v in r.getheaders()}
            status = r.status
    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in e.headers.items()}
        status = e.code
    except Exception as e:
        return [], {"error": str(e)}

    for hdr, name, sev in REQUIRED_HEADERS:
        if hdr not in headers:
            findings.append({"name": name, "risk": sev, "evidence": f"response has no {hdr} header"})

    server = headers.get("server", "")
    if server and any(c.isdigit() for c in server):
        findings.append({"name": "Server Disclosure", "risk": "info",
                         "evidence": f"Server: {server}"})

    cookie = headers.get("set-cookie", "")
    if cookie and "secure" not in cookie.lower():
        findings.append({"name": "Cookie Without Secure Flag", "risk": "low",
                         "evidence": "Set-Cookie missing Secure attribute"})

    summary = {"http_status": status}
    for sev in ("critical", "high", "medium", "low", "info"):
        summary[f"{sev}_count"] = sum(1 for f in findings if f["risk"] == sev)
    return findings, summary


def build_payload(args, findings, summary):
    return {
        "client_name": args.client,
        "scan_id": args.scan_id,
        "scan_type": "web-header-baseline",
        "target": args.target,
        "status": "completed",
        "summary": summary,
        "findings": findings,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--client", required=True)
    ap.add_argument("--scan-id", required=True)
    ap.add_argument("--post", help="storeScanResults URL to POST the payload to")
    ap.add_argument("--allow-remote", action="store_true",
                    help="permit a non-loopback target (requires explicit authorization)")
    args = ap.parse_args()

    u = urlparse(args.target)
    if u.scheme not in ("http", "https"):
        print("refusing non-http(s) target", file=sys.stderr)
        return 2
    if not args.allow_remote and not is_loopback(u.hostname or ""):
        print(f"refusing non-loopback target {u.hostname!r} without --allow-remote "
              "(authorized simulation targets only)", file=sys.stderr)
        return 2

    findings, summary = scan(args.target)
    payload = build_payload(args, findings, summary)
    print(json.dumps(payload, indent=2))

    if args.post:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(args.post, data=data, method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                print(f"\nPOST {args.post} -> {r.status}: {r.read().decode()}", file=sys.stderr)
        except urllib.error.HTTPError as e:
            print(f"\nPOST {args.post} -> {e.code}: {e.read().decode()}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
