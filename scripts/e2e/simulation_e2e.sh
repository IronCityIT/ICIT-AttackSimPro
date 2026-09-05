#!/usr/bin/env bash
# AttackSimPro — end-to-end safe simulation (loopback only, non-destructive).
#
# Exercises the whole product path with real processes over real sockets:
#   simcore engine  ->  evidence bundle + report  ->  storeScanResults ingest
#
#   1. start sandbox fixtures (vulnerable :9101, hardened :9102)
#   2. start the ingest server (:8094, in-memory Firestore)
#   3. run the `standard` group against the vulnerable fixture, write an evidence
#      bundle, and POST findings to the ingest
#   4. run against the hardened fixture (expect far fewer findings)
#   5. verify the evidence bundle integrity + audit-log hash chain
#   6. safety checks: an external target is REFUSED; the report escapes hostile input
#
# No exploitation, no third-party systems, no secrets required.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PORT=8094
BASE="http://127.0.0.1:${PORT}"
WORK="$(mktemp -d)"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$*"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$*"; }

python3 "$ROOT/scripts/attack-sim/targets.py" >"$WORK/targets.log" 2>&1 & TPID=$!
INGEST_TOKEN="" PORT="$PORT" node "$ROOT/functions/local-server.js" >"$WORK/ingest.log" 2>&1 & IPID=$!
cleanup(){ kill "$TPID" "$IPID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

for _ in $(seq 1 50); do curl -fsS "$BASE/healthz" >/dev/null 2>&1 && break; sleep 0.1; done
for _ in $(seq 1 50); do curl -fsS "http://127.0.0.1:9101/" >/dev/null 2>&1 && break; sleep 0.1; done

cd "$ROOT"

echo "== 1. Standard validation of the vulnerable fixture + ingest =="
python3 -m simcore run --targets http://127.0.0.1:9101 --group standard \
  --client "Acme Corp" --scan-id e2e-vuln --out "$WORK/vuln" \
  --audit-log "$WORK/audit.log" --post "$BASE/" >"$WORK/vuln.json" 2>"$WORK/vuln.err" \
  && ok "vulnerable fixture validated + posted" || bad "vuln run failed"
VF=$(jq '.summary.medium_count + .summary.low_count + .summary.info_count' "$WORK/vuln.json")
[ "${VF:-0}" -ge 5 ] && ok "vulnerable fixture produced $VF findings" || bad "vuln findings=$VF (<5)"
grep -q "e2e-vuln" "$WORK/vuln.err" && ok "POST to ingest acknowledged" || bad "ingest POST not acknowledged"

echo "== 2. Verify the ingest stored the scan at the tenant partition =="
DUMP=$(curl -s "$BASE/__dump")
echo "$DUMP" | jq -e '."clients/acme-corp/scans/e2e-vuln".target=="http://127.0.0.1:9101"' >/dev/null \
  && ok "stored at clients/acme-corp/scans/e2e-vuln with real target" || bad "partition/target wrong"

echo "== 3. Hardened fixture should be near-clean =="
python3 -m simcore run --targets http://127.0.0.1:9102 --group standard \
  --client "Acme Corp" --scan-id e2e-hard --out "$WORK/hard" >"$WORK/hard.json" 2>/dev/null \
  && ok "hardened fixture validated" || bad "hard run failed"
HF=$(jq '.summary.critical_count + .summary.high_count + .summary.medium_count' "$WORK/hard.json")
[ "${HF:-9}" -le 1 ] && ok "hardened fixture had $HF significant findings" || bad "hardened findings=$HF (>1)"

echo "== 4. Evidence bundle integrity + audit chain =="
python3 -m simcore verify --bundle "$WORK/vuln" >/dev/null && ok "evidence bundle verified" || bad "bundle verify failed"
python3 -c "from simcore.audit import AuditLog;import sys;ok,i=AuditLog('$WORK/audit.log').verify();sys.exit(0 if ok else 1)" \
  && ok "audit hash chain verified" || bad "audit chain broken"
for f in run.json findings.json report.md report.html manifest.json; do
  [ -s "$WORK/vuln/$f" ] && ok "bundle has $f" || bad "bundle missing $f"
done

echo "== 5. Safety: external target refused, report escapes hostile input =="
set +e
python3 -m simcore run --targets https://8.8.8.8 --group quick --client X --scan-id e2e-ext \
  >/dev/null 2>"$WORK/ext.err"; RC=$?
set -e
[ "$RC" -eq 4 ] && ok "external target refused (exit 4)" || bad "external target not refused (exit $RC)"
grep -q "REFUSED" "$WORK/ext.err" && ok "refusal reported to operator" || bad "refusal not reported"
grep -q "onerror" "$WORK/vuln/report.html" && bad "report contains unescaped script" || ok "report has no unescaped script payload"

echo
echo "E2E results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
