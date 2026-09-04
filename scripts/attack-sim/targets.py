#!/usr/bin/env python3
"""
Local synthetic targets for AttackSimPro safe simulation.

Spins up TWO local HTTP servers on 127.0.0.1 ONLY:
  * :9101  "vulnerable" — omits security headers, leaks a Server banner, sets an
           insecure cookie. Represents a misconfigured app.
  * :9102  "hardened"   — sets HSTS/CSP/X-Frame-Options/X-Content-Type-Options,
           no Server banner, Secure+HttpOnly cookie.

These are inert fixtures for passive header inspection. They serve a static page,
do nothing destructive, and bind to loopback so nothing leaves the host. This is
the ONLY kind of target AttackSimPro's simulations run against here — authorized,
local, non-destructive.

Usage:
    python3 targets.py &            # starts both, prints PIDs, waits
    python3 targets.py --self-test  # start, probe once, print result, exit
"""
import sys
import http.server
import socketserver
import threading
import urllib.request

VULN_PORT = 9101
HARD_PORT = 9102
PAGE = b"<!doctype html><title>synthetic target</title><h1>AttackSimPro fixture</h1>"


class VulnHandler(http.server.BaseHTTPRequestHandler):
    server_version = "OldServer/1.2.3"  # deliberate version disclosure
    sys_version = ""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        # Insecure cookie: no Secure, no HttpOnly.
        self.send_header("Set-Cookie", "session=abc123; Path=/")
        self.send_header("Content-Length", str(len(PAGE)))
        self.end_headers()
        self.wfile.write(PAGE)

    def log_message(self, *a):
        pass


class HardHandler(http.server.BaseHTTPRequestHandler):
    server_version = ""
    sys_version = ""

    def version_string(self):
        return "server"  # suppress version disclosure

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Set-Cookie", "session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict")
        self.send_header("Content-Length", str(len(PAGE)))
        self.end_headers()
        self.wfile.write(PAGE)

    def log_message(self, *a):
        pass


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start():
    v = Server(("127.0.0.1", VULN_PORT), VulnHandler)
    h = Server(("127.0.0.1", HARD_PORT), HardHandler)
    threading.Thread(target=v.serve_forever, daemon=True).start()
    threading.Thread(target=h.serve_forever, daemon=True).start()
    return v, h


def main():
    v, h = start()
    print(f"vulnerable  -> http://127.0.0.1:{VULN_PORT}")
    print(f"hardened    -> http://127.0.0.1:{HARD_PORT}", flush=True)
    if "--self-test" in sys.argv:
        for port in (VULN_PORT, HARD_PORT):
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=3) as r:
                print(f"  :{port} responded {r.status}", flush=True)
        v.shutdown(); h.shutdown()
        return
    threading.Event().wait()


if __name__ == "__main__":
    main()
