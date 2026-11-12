#!/usr/bin/env bash
# M1 script-level reference implementation of the ADR-0008 R3 §10 reset
# sequence. The API endpoint (POST /system/scanner/reset) is M5; this proves the
# property now: THE DIRTY FLAG IS NEVER CLEARED WITHOUT FULL VERIFICATION.
#
#   zap_daemon_state.sh status            show dirty state
#   zap_daemon_state.sh mark-dirty <why>  set dirty
#   zap_daemon_state.sh ack-restart       record an OPERATOR-AUTHORISED restart (one-shot)
#   zap_daemon_state.sh reset             R2..R7 verification; clears ONLY on full pass
#
# R3 identity semantics (clarifies ADR-0008 R3 §10, which did not say how an
# authorised restart is told apart from an unexplained one):
#   marker absent + container restarted + NO acknowledgement -> FAIL (state
#       untrusted; an unexplained restart must never silently clear dirty)
#   marker absent + container restarted + acknowledgement     -> pass, and the
#       acknowledgement is CONSUMED (one-shot, recorded, cannot be left open)
# Only `make lab-zap-restart` writes an acknowledgement.
#
# The platform cannot start/stop/restart containers: Docker socket access is
# prohibited (ADR-0008 R3 §9). Container restart is an operator action:
#   make lab-zap-restart
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] && { set -a; . ./.env; set +a; }
STATE_DIR="${LAB_STATE_DIR:-.lab-state}"; STATE="$STATE_DIR/zap-daemon-state.json"
ZAP_IP="${ZAP_IP:-172.30.10.10}"; LAB_NET="${LAB_NETWORK_NAME:-vapt_lab}"
mkdir -p "$STATE_DIR"
[ -f "$STATE" ] || echo '{"is_dirty": false, "dirty_reason": null, "requires_operator_restart": false, "instance_marker": null, "marker_container_started_at": null, "operator_restart_ack": null}' > "$STATE"
AUDIT="$STATE_DIR/zap-daemon-audit.log"
audit() { printf '%s actor=%s action=%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${USER:-operator}" "$1" "${2:-}" >> "$AUDIT"; }
jget() { python3 -c "import json,sys;print(json.load(open('$STATE')).get('$1'))"; }
jset() { STATE_FILE="$STATE" python3 - "$@" <<'PY'
import json,os,sys
p=os.environ["STATE_FILE"]; d=json.load(open(p))
for kv in sys.argv[1:]:
    k,v=kv.split("=",1)
    d[k]=json.loads(v) if v in ("true","false","null") or v.startswith(('{','[','"')) else v
json.dump(d,open(p,"w"),indent=2)
PY
}
api() { # in-lab, allowlisted client at .30 — the host (.1) is not allowlisted
  local img; img=$(docker inspect vapt_juiceshop --format '{{.Image}}' 2>/dev/null)
  docker run --rm --network "$LAB_NET" --ip 172.30.10.30 --entrypoint "${JS_NODE_PATH:-/nodejs/bin/node}" "$img" -e "
const u=new URL('http://$ZAP_IP:8080$1');
require('http').get({host:u.hostname,port:u.port,path:u.pathname+u.search,timeout:10000},
 r=>{let b='';r.on('data',d=>b+=d);r.on('end',()=>{console.log(r.statusCode+'|'+b.slice(0,200).replace(/\n/g,' '))})})
 .on('error',e=>console.log('0|'+e.code)).on('timeout',()=>console.log('0|TIMEOUT'));" 2>/dev/null || echo "0|RUN_FAILED"
}
step() { printf '  %-28s %s\n' "$1" "$2"; }

case "${1:-status}" in
status)
  echo "dirty=$(jget is_dirty) reason=$(jget dirty_reason) requires_operator_restart=$(jget requires_operator_restart) marker=$(jget instance_marker) operator_restart_ack=$(jget operator_restart_ack)";;
ack-restart)
  started=$(docker inspect vapt_zap --format '{{.State.StartedAt}}' 2>/dev/null)
  jset "operator_restart_ack=${started:-unknown}"
  audit ack_restart "container_started_at=${started:-unknown}"
  echo "recorded operator-authorised restart at ${started:-unknown} (one-shot; consumed by the next reset)";;
mark-dirty)
  jset "is_dirty=true" "dirty_reason=${2:-unspecified}"
  audit mark_dirty "reason=${2:-unspecified}"
  echo "daemon marked DIRTY: ${2:-unspecified} — gate 13 would now deny every job on every asset";;
reset)
  echo "scanner reset: ADR-0008 R3 §10 verification sequence"
  ok=true; failing=""
  # R2 health
  r=$(api "/JSON/core/view/version/?apikey=${ZAP_API_KEY}"); code=${r%%|*}
  if [ "$code" = 200 ]; then step "R2 health" "pass ($r)"; else step "R2 health" "FAIL ($r)"; ok=false; failing=R2; fi
  if [ "$ok" = true ]; then
    # R3 identity: is the daemon the one we last verified?
    marker=$(jget instance_marker); ack=$(jget operator_restart_ack)
    started=$(docker inspect vapt_zap --format '{{.State.StartedAt}}' 2>/dev/null)
    r=$(api "/JSON/context/view/contextList/?apikey=${ZAP_API_KEY}")
    if [ "$marker" = "None" ] || [ "$marker" = "null" ]; then
      step "R3 identity" "pass (no prior marker; first verification)"
    elif echo "$r" | grep -q "$marker"; then
      step "R3 identity" "pass (marker $marker present — same daemon instance)"
    elif [ "$ack" != "None" ] && [ "$ack" != "null" ] && [ "$ack" = "$started" ]; then
      step "R3 identity" "pass (marker absent, but restart at $started is operator-authorised)"
      jset "operator_restart_ack=null"       # one-shot: consumed here
      audit ack_consumed "container_started_at=$started"
    else
      step "R3 identity" "FAIL (marker $marker absent and the restart is NOT authorised — daemon state untrusted)"
      ok=false; failing=R3
    fi
  fi
  if [ "$ok" = true ]; then
    r=$(api "/JSON/core/action/newSession/?apikey=${ZAP_API_KEY}&name=reset-$(date +%s)&overwrite=true")
    [ "${r%%|*}" = 200 ] && step "R4 newSession" "pass" || { step "R4 newSession" "FAIL ($r)"; ok=false; failing=R4; }
  fi
  if [ "$ok" = true ]; then
    a=$(api "/JSON/core/view/alerts/?apikey=${ZAP_API_KEY}&start=0&count=1")
    s=$(api "/JSON/core/view/sites/?apikey=${ZAP_API_KEY}")
    if echo "$a" | grep -q '"alerts":\[\]' && echo "$s" | grep -q '"sites":\[\]'
      then step "R5 stores empty" "pass"
      else step "R5 stores empty" "FAIL (alerts=$a sites=$s)"; ok=false; failing=R5; fi
  fi
  if [ "$ok" = true ]; then
    probe="vapt-probe-$(date +%s)"
    c=$(api "/JSON/context/action/newContext/?apikey=${ZAP_API_KEY}&contextName=$probe")
    l=$(api "/JSON/context/view/contextList/?apikey=${ZAP_API_KEY}")
    d=$(api "/JSON/context/action/removeContext/?apikey=${ZAP_API_KEY}&contextName=$probe")
    if [ "${c%%|*}" = 200 ] && echo "$l" | grep -q "$probe" && [ "${d%%|*}" = 200 ]
      then step "R6 api probe" "pass"
      else step "R6 api probe" "FAIL (create=$c list=$l remove=$d)"; ok=false; failing=R6; fi
  fi
  if [ "$ok" = true ]; then
    nm="vapt-instance-$(date +%s)"
    c=$(api "/JSON/context/action/newContext/?apikey=${ZAP_API_KEY}&contextName=$nm")
    started=$(docker inspect vapt_zap --format '{{.State.StartedAt}}' 2>/dev/null)
    if [ "${c%%|*}" = 200 ]; then jset "instance_marker=$nm" "marker_container_started_at=${started:-unknown}"; step "R7 new marker" "pass ($nm)"
    else step "R7 new marker" "FAIL ($c)"; ok=false; failing=R7; fi
  fi
  if [ "$ok" = true ]; then
    jset "is_dirty=false" "dirty_reason=null" "requires_operator_restart=false"
    audit reset_verified "outcome=cleared marker=$(jget instance_marker)"
    echo "R8 RESULT: all steps passed → dirty flag CLEARED"; exit 0
  else
    jset "is_dirty=true" "dirty_reason=reset_failed_at_$failing"
    { [ "$failing" = R2 ] || [ "$failing" = R3 ]; } && jset "requires_operator_restart=true"
    audit reset_failed "failing_step=$failing outcome=dirty_retained"
    echo "R8 RESULT: verification FAILED at $failing → dirty flag RETAINED (not cleared)"
    echo "           operator action required: make lab-zap-restart && make lab-check"
    exit 1
  fi;;
*) echo "usage: $0 {status|mark-dirty <reason>|reset}"; exit 2;;
esac
