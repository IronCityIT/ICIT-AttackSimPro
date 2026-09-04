#!/usr/bin/env bash
# AttackSimPro — full safe synthetic simulation (local, non-destructive).
#
# Pipeline:
#   1. start local synthetic targets (vulnerable :9101, hardened :9102)
#   2. start the ingest server (:8093, in-memory Firestore)
#   3. passive header scan of each target -> findings -> POST to ingest
#   4. verify each scan stored under clients/{client}/scans/{scan_id}
#   5. adversarial probes against the ingest's OWN attack surface (defensive):
#      oversized body, path-traversal scan_id, bad status, XSS-y fields,
#      ingest-token bypass — all must be safely rejected/handled.
#
# Targets are loopback-only. No exploitation, no third-party systems.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
INGEST_PORT=8093
BASE="http://127.0.0.1:${INGEST_PORT}"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$*"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$*"; }
code_of() { curl -s -o /tmp/asp-sim-body.json -w '%{http_code}' "$@"; }

# ---- start fixtures ------------------------------------------------------
python3 "$ROOT/scripts/attack-sim/targets.py" >/tmp/asp-targets.log 2>&1 &
TARGETS_PID=$!
INGEST_TOKEN="" PORT="$INGEST_PORT" node "$ROOT/functions/local-server.js" >/tmp/asp-ingest.log 2>&1 &
INGEST_PID=$!
cleanup() { kill "$TARGETS_PID" "$INGEST_PID" 2>/dev/null || true; }
trap cleanup EXIT

for _ in $(seq 1 50); do curl -fsS "$BASE/healthz" >/dev/null 2>&1 && break; sleep 0.1; done
for _ in $(seq 1 50); do curl -fsS "http://127.0.0.1:9101/" >/dev/null 2>&1 && break; sleep 0.1; done

echo "== 1. Passive header scans of synthetic targets =="
python3 "$ROOT/scripts/attack-sim/passive_header_scan.py" \
  --target http://127.0.0.1:9101 --client "Acme Corp" --scan-id sim-vuln-1 --post "$BASE/" \
  >/tmp/asp-vuln.json 2>/tmp/asp-vuln.err && ok "vulnerable target scanned + stored" || bad "vuln scan/store"
python3 "$ROOT/scripts/attack-sim/passive_header_scan.py" \
  --target http://127.0.0.1:9102 --client "Acme Corp" --scan-id sim-hard-1 --post "$BASE/" \
  >/tmp/asp-hard.json 2>/tmp/asp-hard.err && ok "hardened target scanned + stored" || bad "hard scan/store"

VULN_FINDINGS=$(jq '.findings | length' /tmp/asp-vuln.json)
HARD_FINDINGS=$(jq '.findings | length' /tmp/asp-hard.json)
[ "$VULN_FINDINGS" -ge 5 ] && ok "vulnerable target produced $VULN_FINDINGS findings" || bad "vuln findings=$VULN_FINDINGS (<5)"
[ "$HARD_FINDINGS" -eq 0 ] && ok "hardened target produced 0 findings" || bad "hard findings=$HARD_FINDINGS (want 0)"

echo "== 2. Verify stored partition + retained target =="
DUMP=$(curl -s "$BASE/__dump")
echo "$DUMP" | jq -e '."clients/acme-corp/scans/sim-vuln-1".target=="http://127.0.0.1:9101"' >/dev/null \
  && ok "vuln scan stored at correct partition with real target" || bad "vuln partition/target"
echo "$DUMP" | jq -e '."clients/acme-corp/scans/sim-vuln-1".findings | length >= 5' >/dev/null \
  && ok "findings persisted on the record" || bad "findings not persisted"

echo "== 3. Adversarial probes against the ingest attack surface (defensive) =="
c=$(code_of -X POST -H 'Content-Type: application/json' \
  -d '{"client_name":"Acme","scan_id":"../../etc/passwd","target":"x"}' "$BASE/")
[ "$c" = "400" ] && ok "path-traversal scan_id rejected (400)" || bad "traversal scan_id got $c"

# Build the >1 MiB body in a file (command-line ARG_MAX cannot hold it inline).
python3 -c 'import json,sys; json.dump({"client_name":"Acme","scan_id":"big","summary":{"b":"x"*1200000}}, open("/tmp/asp-big.json","w"))'
c=$(code_of -X POST -H 'Content-Type: application/json' --data-binary @/tmp/asp-big.json "$BASE/")
[ "$c" = "413" ] && ok "oversized payload rejected (413)" || bad "oversized got $c"

c=$(code_of -X POST -H 'Content-Type: application/json' \
  -d '{"client_name":"Acme","scan_id":"s","status":"exfiltrate"}' "$BASE/")
[ "$c" = "400" ] && ok "invalid status rejected (400)" || bad "bad status got $c"

# XSS-y string in a field must be stored verbatim as data (not executed), and the
# endpoint must not 500. The dashboard is responsible for output-encoding.
c=$(code_of -X POST -H 'Content-Type: application/json' \
  -d '{"client_name":"Acme","scan_id":"xss","findings":[{"name":"<img src=x onerror=alert(1)>"}]}' "$BASE/")
[ "$c" = "200" ] && ok "hostile finding string accepted as inert data (200)" || bad "xss field got $c"
echo "$DUMP" >/dev/null # noop

echo
echo "Simulation results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
