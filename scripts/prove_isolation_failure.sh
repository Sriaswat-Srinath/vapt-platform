#!/usr/bin/env bash
# I10/V3 — prove the isolation check can FAIL, then revert and prove it passes.
# A check that cannot fail is not a check.
#
# Induced misconfiguration: attach the ZAP container to the default `bridge`
# network, which HAS egress. No compose file is edited; the change is reverted.
set -uo pipefail
cd "$(dirname "$0")/.."
OUT="${LAB_STATE_DIR:-.lab-state}"; mkdir -p "$OUT"
say() { printf '\n=== %s ===\n' "$1"; }

say "PHASE 1 — baseline: isolation check must PASS"
./scripts/lab_isolation_check.sh > "$OUT/evidence-1-baseline.json" 2>&1
base=$?; echo "exit=$base ($([ $base -eq 0 ] && echo PASS || echo FAIL))"
[ $base -eq 0 ] || { echo "ABORT: baseline is not clean; fix the lab before proving failure"; exit 1; }

say "PHASE 2 — induce misconfiguration: attach vapt_zap to the egress-capable 'bridge' network"
docker network connect bridge vapt_zap
docker exec vapt_zap bash -c "awk 'NR>1 && \$2==\"00000000\"{print \"  default route now present via\",\$1}' /proc/net/route"

say "PHASE 3 — isolation check must now FAIL"
./scripts/lab_isolation_check.sh > "$OUT/evidence-2-induced-failure.json" 2>&1
bad=$?; echo "exit=$bad ($([ $bad -ne 0 ] && echo 'FAILED AS REQUIRED' || echo 'DID NOT FAIL — CHECK IS BROKEN'))"
python3 - "$OUT/evidence-2-induced-failure.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
print("  passed:", d["passed"], "| egress_blocked:", d["egress_blocked"], "| dns_contained:", d["dns_contained"])
for p in d["probe_results"]:
    if not p["pass"]: print(f"  FAILING PROBE  {p['id']:<16} required={p['required']!r} observed={p['observed']!r}")
PY

say "PHASE 4 — revert: detach from 'bridge'"
docker network disconnect bridge vapt_zap
docker exec vapt_zap bash -c "awk 'NR>1 && \$2==\"00000000\"{f=1} END{print (f?\"  default route STILL present\":\"  no default route — reverted\")}' /proc/net/route"

say "PHASE 5 — isolation check must PASS again"
./scripts/lab_isolation_check.sh > "$OUT/evidence-3-reverted.json" 2>&1
rev=$?; echo "exit=$rev ($([ $rev -eq 0 ] && echo PASS || echo FAIL))"

say "VERDICT"
if [ $base -eq 0 ] && [ $bad -ne 0 ] && [ $rev -eq 0 ]; then
  echo "PROVEN: check passes clean, FAILS under induced misconfiguration, passes after revert."
  echo "evidence: $OUT/evidence-{1-baseline,2-induced-failure,3-reverted}.json"; exit 0
else
  echo "NOT PROVEN (baseline=$base induced=$bad reverted=$rev)"; exit 1
fi
