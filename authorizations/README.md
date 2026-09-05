# Authorizations (Rules of Engagement)

AttackSimPro refuses any non-loopback / non-private target unless **both**:

1. the run is invoked with `--allow-external`, **and**
2. a matching, in-window authorization record in this directory permits the host.

Loopback (`127.0.0.0/8`) and private ranges (RFC 1918 / RFC 4193 / link-local) are
always permitted as sandbox targets and need no record.

## Record format (`*.yaml` / `*.json`)

```yaml
roe_id: ROE-2026-ACME-01          # your signed engagement reference
client: Acme Corp
authorized_by: ciso@acme.example  # who signed off
hosts:                            # exact hostnames / IPs in scope
  - scan.acme.example
cidrs:                            # CIDR blocks in scope
  - 198.51.100.0/24
not_before: 2026-09-01T00:00:00Z  # optional window
not_after:  2026-09-30T23:59:59Z
reason: Quarterly purple-team control validation (signed SOW-1234)
```

Only files ending in `.yaml`, `.yml`, or `.json` are loaded. The `*.sample` template
below is intentionally **not** loaded, so this repo ships with zero live external
authorizations — the default posture is sandbox-only. Copy it, fill in a real signed
engagement, and rename to `.yaml` to activate it.
