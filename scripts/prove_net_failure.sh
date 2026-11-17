#!/usr/bin/env bash
# M1.5 — prove net_verify can FAIL, then revert and prove it passes.
# Induced misconfiguration: attach the WORKER to vapt_wan, which has a WAN route.
# This is the exact failure the architecture exists to prevent.
set -uo pipefail
cd "$(dirname "$0")/.."
OUT="${LAB_STATE_DIR:-.lab-state}"; mkdir -p "$OUT"
say() { printf '\n=== %s ===\n' "$1"; }

say "PHASE 1 — baseline: net_verify must PASS"
./scripts/net_verify.sh > "$OUT/net-evidence-1-baseline.json" 2>&1; base=$?
echo "exit=$base ($([ $base -eq 0 ] && echo PASS || echo FAIL))"
[ $base -eq 0 ] || { echo "ABORT: baseline is not clean"; exit 1; }

say "PHASE 2 — induce: attach vapt_worker to vapt_wan (a network WITH egress)"
docker network connect vapt_wan vapt_worker
docker exec vapt_worker python3 -c "
rows=[l.split() for l in open('/proc/net/route').read().splitlines()[1:] if l.strip()]
print('  worker default route:', [r[0] for r in rows if r[1]=='00000000'] or 'none')"

say "PHASE 3 — net_verify must now FAIL"
./scripts/net_verify.sh > "$OUT/net-evidence-2-induced-failure.json" 2>&1; bad=$?
echo "exit=$bad ($([ $bad -ne 0 ] && echo 'FAILED AS REQUIRED' || echo 'DID NOT FAIL — CHECK IS BROKEN'))"
python3 - "$OUT/net-evidence-2-induced-failure.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
print("  net_passed:", d["net_passed"])
for p in d["probe_results"]:
    if not p["pass"]: print(f"  FAILING PROBE  {p['id']:<22} required={p['required']!r} observed={p['observed']!r}")
PY

say "PHASE 4 — revert: detach vapt_worker from vapt_wan"
docker network disconnect vapt_wan vapt_worker
docker exec vapt_worker python3 -c "
rows=[l.split() for l in open('/proc/net/route').read().splitlines()[1:] if l.strip()]
print('  worker default route:', [r[0] for r in rows if r[1]=='00000000'] or 'none (reverted)')"

say "PHASE 5 — net_verify must PASS again"
./scripts/net_verify.sh > "$OUT/net-evidence-3-reverted.json" 2>&1; rev=$?
echo "exit=$rev ($([ $rev -eq 0 ] && echo PASS || echo FAIL))"

say "VERDICT"
if [ $base -eq 0 ] && [ $bad -ne 0 ] && [ $rev -eq 0 ]; then
  echo "PROVEN: passes clean, FAILS under induced egress, passes after revert."
  echo "evidence: $OUT/net-evidence-{1-baseline,2-induced-failure,3-reverted}.json"; exit 0
else
  echo "NOT PROVEN (baseline=$base induced=$bad reverted=$rev)"; exit 1
fi
