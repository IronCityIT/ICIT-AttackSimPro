#!/usr/bin/env bash
# End-to-end smoke test for the storeScanResults ingest endpoint.
#
# Boots functions/local-server.js (the real handler + an in-memory Firestore
# double) on a real socket, then drives the full ingest contract with curl and
# asserts every status code. No GCP credentials, no deploy, no network egress.
#
#   bash scripts/smoke.sh
#
# Exit 0 = every case behaved as specified; non-zero = a contract regression.
set -euo pipefail

PORT="${PORT:-8091}"
BASE="http://127.0.0.1:${PORT}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0
FAIL=0

log()  { printf '  %s\n' "$*"; }
ok()   { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$*"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$*"; }

# start server
PORT="$PORT" node "$ROOT/functions/local-server.js" >/tmp/asp-smoke.log 2>&1 &
SRV_PID=$!
cleanup() { kill "$SRV_PID" 2>/dev/null || true; }
trap cleanup EXIT

# wait for listen (up to ~5s)
for _ in $(seq 1 50); do
  if curl -fsS "$BASE/healthz" >/dev/null 2>&1; then break; fi
  sleep 0.1
done

# helper: expect an HTTP status for a request
# args: <label> <expected> <curl args...>
expect() {
  local label="$1" expected="$2"; shift 2
  local code
  code="$(curl -s -o /tmp/asp-smoke-body.json -w '%{http_code}' "$@")"
  if [ "$code" = "$expected" ]; then ok "$label ($code)"; else
    bad "$label (got $code, want $expected): $(cat /tmp/asp-smoke-body.json)"
  fi
}

echo "AttackSimPro storeScanResults — smoke test @ $BASE"

expect "healthz is up"              200 "$BASE/healthz"
expect "GET / rejected"             405 -X GET  "$BASE/"
expect "missing client rejected"    400 -X POST -H 'Content-Type: application/json' -d '{"scan_id":"s1"}' "$BASE/"
expect "missing scan_id rejected"   400 -X POST -H 'Content-Type: application/json' -d '{"client_name":"Acme"}' "$BASE/"
expect "bad status rejected"        400 -X POST -H 'Content-Type: application/json' -d '{"client_name":"Acme","scan_id":"s1","status":"pwned"}' "$BASE/"
expect "valid scan stored"          200 -X POST -H 'Content-Type: application/json' \
  -d '{"client_name":"Acme Corp","scan_id":"scan-100","scan_type":"web-baseline","target":"https://acme.example","status":"completed","findings":[{"name":"Missing HSTS","risk":"medium"}],"summary":{"medium_count":1}}' "$BASE/"
expect "late failure ignored"       200 -X POST -H 'Content-Type: application/json' \
  -d '{"client_name":"Acme Corp","scan_id":"scan-100","status":"failed","error":{"message":"ai died"}}' "$BASE/"

# verify the store contents reflect the monotonic rule
DUMP="$(curl -s "$BASE/__dump")"
if echo "$DUMP" | jq -e '."clients/acme-corp/scans/scan-100".status == "completed"' >/dev/null; then
  ok "stored scan retained completed status"
else
  bad "stored scan status wrong: $DUMP"
fi
if echo "$DUMP" | jq -e '."clients/acme-corp/scans/scan-100".target == "https://acme.example"' >/dev/null; then
  ok "stored scan retained real target"
else
  bad "stored scan target wrong: $DUMP"
fi

echo
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
