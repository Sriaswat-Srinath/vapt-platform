#!/usr/bin/env bash
# VAPT lab isolation verification (M1).
#
# Emits the machine-readable payload that becomes a `lab_isolation_checks` row
# in M3. Exit 0 only when every probe produced its REQUIRED result.
#
# This check must be able to FAIL. See `make lab-prove-failure`.
set -uo pipefail
# --require all          (default) exit 0 only when containment AND access AND
#                        host hygiene all pass.
# --require containment  exit 0 when container->internet/->LAN containment holds,
#                        regardless of foreign host listeners or the optional
#                        workstation forwarder. Used by recovery paths, which must
#                        not be blocked by an unrelated service on the host.
REQUIRE="all"
[ "${1:-}" = "--require" ] && { REQUIRE="${2:-all}"; shift 2 || true; }
cd "$(dirname "$0")/.."
[ -f .env ] && { set -a; . ./.env; set +a; }
mkdir -p "${LAB_STATE_DIR:-.lab-state}"
LAB_CLIENT_IP="${LAB_CLIENT_IP:-172.30.10.39}"   # inside ZAP_API_CLIENT_ALLOWLIST (.3x);
                                                 # .30 belongs to the worker from phase 3

LAB_NET="${LAB_NETWORK_NAME:-vapt_lab}"
SUBNET="${LAB_SUBNET:-172.30.10.0/24}"
ZAP_C=vapt_zap
JS_C=vapt_juiceshop
HOSTNAME_ALIAS="${MOCK_TARGET_HOSTNAME:-shop.brakes-vapt.test}"
PUBLISH_PORT="${MOCK_TARGET_PUBLISH_PORT:-3000}"
TARGETS="${ISOLATION_PROBE_TARGETS:-1.1.1.1:443,8.8.8.8:53}"
DNS_NAME="${ISOLATION_PROBE_DNS_NAME:-example.com}"
TTL_MIN="${ISOLATION_CHECK_TTL_MINUTES:-60}"
JS_IMAGE="$(docker inspect "$JS_C" --format '{{.Image}}' 2>/dev/null || echo '')"
# The Juice Shop image is distroless: no shell, no `node` on PATH.
JS_NODE="${JS_NODE_PATH:-/nodejs/bin/node}"
# Host LAN gateway — the corporate-network direction. Probed automatically.
LAN_GW="$(ip -o -4 route show default 2>/dev/null | awk '{print $3}' | head -n1)"

RESULTS=()   # id|required|observed|pass|detail
add() {
  local id req obs ok det
  id=$(printf '%s' "$1" | tr -d '\n|"'); req=$(printf '%s' "$2" | tr -d '\n|"')
  obs=$(printf '%s' "$3" | tr -d '\n|"' | sed 's/[[:space:]]*$//')
  ok=$(printf '%s' "$4" | tr -d '\n|" '); det=$(printf '%s' "${5:-}" | tr -d '\n|"' | sed 's/\\/\\\\/g')
  obs=$(printf '%s' "$obs" | sed 's/\\/\\\\/g')
  case "$ok" in true|false) ;; *) ok=false; det="MALFORMED PROBE RESULT: $det";; esac
  RESULTS+=("$id|$req|$obs|$ok|$det")
}
pass_fail() { [ "$1" = "$2" ] && echo true || echo false; }

# --- helpers ----------------------------------------------------------------
# TCP probe from the ZAP container (debian + bash: /dev/tcp works).
zap_tcp() { docker exec "$ZAP_C" bash -c \
  "timeout 5 bash -c 'exec 3<>/dev/tcp/$1/$2' >/dev/null 2>&1 && echo REACHABLE || echo BLOCKED" 2>/dev/null || echo PROBE_ERROR; }
# TCP probe from the Juice Shop container (alpine/busybox: use node).
js_tcp() { docker exec "$JS_C" "$JS_NODE" -e "
const s=require('net').connect({host:'$1',port:$2,timeout:5000});
s.on('connect',()=>{console.log('REACHABLE');process.exit(0)});
s.on('error',()=>{console.log('BLOCKED');process.exit(0)});
s.on('timeout',()=>{console.log('BLOCKED');process.exit(0)});" 2>/dev/null || echo PROBE_ERROR; }
zap_dns() { docker exec "$ZAP_C" bash -c \
  "timeout 5 getent hosts $1 >/dev/null 2>&1 && echo RESOLVED || echo UNRESOLVED" 2>/dev/null || echo PROBE_ERROR; }
js_dns() { docker exec "$JS_C" "$JS_NODE" -e "
const done=m=>{console.log(m);process.exit(0)};
const t=setTimeout(()=>done('UNRESOLVED'),5000);
require('dns').lookup('$1',(e,a)=>{clearTimeout(t);done(e?'UNRESOLVED':'RESOLVED:'+a)});" 2>/dev/null || echo PROBE_ERROR; }
# HTTP client inside the lab at an API-allowlisted IP (.30 = worker range).
lab_client() { # $1 = url ; $2 = extra node code for status handling
  docker run --rm --name "vapt_probe_$$" --network "$LAB_NET" --ip "$LAB_CLIENT_IP" \
    --entrypoint "$JS_NODE" \
    "$JS_IMAGE" -e "
const u=new URL('$1');
require('http').get({host:u.hostname,port:u.port,path:u.pathname+u.search,timeout:8000},
  r=>{let b='';r.on('data',d=>b+=d);r.on('end',()=>console.log('HTTP_'+r.statusCode+'|'+b.slice(0,120).replace(/\n/g,' ')))})
  .on('error',e=>console.log('ERROR|'+e.code))
  .on('timeout',()=>console.log('ERROR|TIMEOUT'));" 2>/dev/null || echo "ERROR|RUN_FAILED"; }

# === I1 network is internal, no gateway route ===============================
internal=$(docker network inspect "$LAB_NET" --format '{{.Internal}}' 2>/dev/null || echo missing)
add I1a "true" "$internal" "$(pass_fail "$internal" true)" "docker network .Internal"
defroute=$(docker exec "$ZAP_C" bash -c "awk 'NR>1 && \$2==\"00000000\" {print \$1\":\"\$3; f=1} END{if(!f) print \"NONE\"}' /proc/net/route" 2>/dev/null)
defroute="${defroute:-PROBE_ERROR}"
add I1b NONE "$defroute" "$(pass_fail "$defroute" NONE)" "default route inside zap (from /proc/net/route; a probe error fails)"
jsroute=$(docker exec "$JS_C" "$JS_NODE" -e "const l=require('fs').readFileSync('/proc/net/route','utf8').split('\\n').slice(1).filter(x=>x.trim());const d=l.filter(x=>x.split(/\\s+/)[1]==='00000000');console.log(d.length?d.map(x=>x.split(/\\s+/)[0]).join(','):'NONE')" 2>/dev/null)
jsroute="${jsroute:-PROBE_ERROR}"
add I1d NONE "$jsroute" "$(pass_fail "$jsroute" NONE)" "default route inside juiceshop (from /proc/net/route)"
net_subnet=$(docker network inspect "$LAB_NET" --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null)
add I1c "$SUBNET" "$net_subnet" "$(pass_fail "$net_subnet" "$SUBNET")" "lab subnet"

# === I2 / I3 egress blocked from both containers =============================
IFS=',' read -ra TLIST <<< "$TARGETS"
for t in "${TLIST[@]}"; do
  h="${t%%:*}"; p="${t##*:}"
  r=$(zap_tcp "$h" "$p"); add "I2:$t" BLOCKED "$r" "$(pass_fail "$r" BLOCKED)" "tcp egress from zap"
  r=$(js_tcp "$h" "$p");  add "I3:$t" BLOCKED "$r" "$(pass_fail "$r" BLOCKED)" "tcp egress from juiceshop"
done

# === I2L / I3L corporate-LAN direction must also be blocked ================
if [ -n "$LAN_GW" ]; then
  r=$(zap_tcp "$LAN_GW" 80); add "I2L:$LAN_GW:80" BLOCKED "$r" "$(pass_fail "$r" BLOCKED)" "host LAN gateway from zap"
  r=$(js_tcp "$LAN_GW" 80);  add "I3L:$LAN_GW:80" BLOCKED "$r" "$(pass_fail "$r" BLOCKED)" "host LAN gateway from juiceshop"
fi

# === I4 public DNS contained ================================================
r=$(zap_dns "$DNS_NAME");  add I4a UNRESOLVED "$r" "$(pass_fail "$r" UNRESOLVED)" "public dns from zap"
r=$(js_dns "$DNS_NAME");   add I4b UNRESOLVED "$r" "$(pass_fail "$r" UNRESOLVED)" "public dns from juiceshop"

# Additional lab TARGETS beyond the primary one. Enumerated from Docker rather
# than hardcoded, so a container added to the lab cannot quietly escape these
# checks — which is exactly how a new target becomes unverified surface.
# The WORKER is excluded deliberately: it is the scanner driver, not a target.
# It is legitimately dual-homed (core + lab) and legitimately holds the evidence
# volume, and it is held to the NET-A / NET-G probes in scripts/net_verify.sh
# instead. Everything else on the lab network is a target and is checked here.
# Only `vapt_*` containers are platform components; this check's OWN transient
# probe container (vapt_probe_*) is excluded, and so is anything that is not
# ours — a foreign container on the lab network is reported by I12 below rather
# than silently measured as if it were a target.
EXTRA_TARGETS=$(docker ps --filter "network=${LAB_NET}" --format '{{.Names}}' 2>/dev/null \
  | grep '^vapt_' | grep -v '^vapt_probe_' \
  | grep -vx -e "$ZAP_C" -e "$JS_C" -e "${WORKER_C:-vapt_worker}" | tr '\n' ' ')
FOREIGN_IN_LAB=$(docker ps --filter "network=${LAB_NET}" --format '{{.Names}}' 2>/dev/null \
  | grep -v '^vapt_' | tr '\n' ' ')

# I12: nothing that is not ours shares the lab network. A foreign container
# there could reach the target, and would not be covered by any probe above.
add I12 "<none>" "${FOREIGN_IN_LAB:-<none>}" "$([ -z "$FOREIGN_IN_LAB" ] && echo true || echo false)" \
    "no non-platform container is attached to the lab network"

# === I5 docker socket absent ================================================
for c in "$ZAP_C" "$JS_C" $EXTRA_TARGETS; do
  mounts=$(docker inspect "$c" --format '{{range .Mounts}}{{.Source}}->{{.Destination}} {{end}}' 2>/dev/null)
  sock=$(echo "$mounts" | grep -c 'docker.sock' || true)
  add "I5:$c" 0 "$sock" "$(pass_fail "$sock" 0)" "docker.sock binds in mounts: ${mounts:-<none>}"
done
insock=$(docker exec "$ZAP_C" bash -c "[ -S /var/run/docker.sock ] && echo PRESENT || echo ABSENT" 2>/dev/null)
add I5c ABSENT "$insock" "$(pass_fail "$insock" ABSENT)" "/var/run/docker.sock inside zap"

# === I6 scanner container hardening ========================================
read -r zuser zro ncap nnp pids mem < <(docker inspect "$ZAP_C" --format \
 '{{.Config.User}} {{.HostConfig.ReadonlyRootfs}} {{join .HostConfig.CapDrop ","}} {{index .HostConfig.SecurityOpt 0}} {{.HostConfig.PidsLimit}} {{.HostConfig.Memory}}' 2>/dev/null)
add I6a zap "${zuser:-<root>}" "$(pass_fail "$zuser" zap)" "zap runs as non-root user"
add I6b true "${zro:-false}" "$(pass_fail "$zro" true)" "read-only rootfs"
add I6c "ALL" "${ncap:-<none>}" "$(pass_fail "$ncap" ALL)" "cap_drop must be exactly ALL"
add I6d "no-new-privileges:true" "${nnp:-<none>}" "$(pass_fail "$nnp" "no-new-privileges:true")" "security_opt"
add I6e ">0" "${pids:-0}" "$([ "${pids:-0}" -gt 0 ] && echo true || echo false)" "pids_limit"
add I6f ">0" "${mem:-0}" "$([ "${mem:-0}" -gt 0 ] && echo true || echo false)" "mem_limit bytes"

# === I7 no host binds (evidence volume cannot be mounted into a scanner) ====
# The SCANNER and the primary target must have no host binds at all: that is
# what keeps the unredacted evidence volume out of a container that talks to
# the target (ADR-0011).
for c in "$ZAP_C" "$JS_C"; do
  binds=$(docker inspect "$c" --format '{{range .HostConfig.Binds}}{{.}} {{end}}' 2>/dev/null)
  add "I7:$c" "<none>" "${binds:-<none>}" "$([ -z "$binds" ] && echo true || echo false)" "host bind mounts"
done
# An additional static target may mount its OWN configuration read-only, and
# nothing else. Every bind is checked individually: read-only, under the repo's
# lab/ directory, and never a named volume (which is how the evidence store
# would arrive).
for c in $EXTRA_TARGETS; do
  bad=0; seen=""
  while read -r b; do
    [ -z "$b" ] && continue
    seen="$seen $b"
    case "$b" in
      */lab/*:*:ro) : ;;
      *) bad=$((bad + 1));;
    esac
  done <<< "$(docker inspect "$c" --format '{{range .HostConfig.Binds}}{{println .}}{{end}}' 2>/dev/null)"
  add "I7r:$c" 0 "$bad" "$(pass_fail "$bad" 0)" \
      "additional target binds must be read-only config under lab/ (observed:${seen:-<none>})"
  nets=$(docker inspect "$c" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null | tr -d ' ')
  add "I8f:$c" "$LAB_NET" "$nets" "$(pass_fail "$nets" "$LAB_NET")" \
      "additional target attached to the internal lab network ONLY (not dual-homed)"
  pub=$(docker inspect "$c" --format '{{json .NetworkSettings.Ports}}' 2>/dev/null | grep -c '0\.0\.0\.0' || true)
  add "I8g:$c" 0 "$pub" "$(pass_fail "$pub" 0)" "additional target has no 0.0.0.0 publish"
done

# === I8 publishing: Juice Shop loopback-only; ZAP API not published =========
jsports=$(docker inspect "$JS_C" --format '{{json .NetworkSettings.Ports}}' 2>/dev/null)
nonloop=$(echo "$jsports" | grep -c '"HostIp":"0.0.0.0"' || true)
add I8a 0 "$nonloop" "$(pass_fail "$nonloop" 0)" "juiceshop docker publish on 0.0.0.0 (must be none; docker ignores publishing on internal networks: $jsports)"
jsnets=$(docker inspect "$JS_C" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null | tr -d ' ')
add I8b "$LAB_NET" "$jsnets" "$(pass_fail "$jsnets" "$LAB_NET")" "juiceshop attached to the internal lab network ONLY (not dual-homed)"
zapnets=$(docker inspect "$ZAP_C" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null | tr -d ' ')
add I8e "$LAB_NET" "$zapnets" "$(pass_fail "$zapnets" "$LAB_NET")" "zap attached to the internal lab network ONLY (not dual-homed)"
zapports=$(docker inspect "$ZAP_C" --format '{{json .NetworkSettings.Ports}}' 2>/dev/null)
zapbindings=$(echo "$zapports" | grep -c 'HostPort' || true)
add I8c 0 "$zapbindings" "$(pass_fail "$zapbindings" 0)" "ZAP host port bindings (must be none): $zapports"
hostzap=$(timeout 4 bash -c 'exec 3<>/dev/tcp/127.0.0.1/8080' >/dev/null 2>&1 && echo REACHABLE || echo REFUSED)
add I8d REFUSED "$hostzap" "$(pass_fail "$hostzap" REFUSED)" "host 127.0.0.1:8080"

# === I9 ZAP API: key required; host-range client rejected ===================
r=$(lab_client "http://${ZAP_IP:-172.30.10.10}:8080/JSON/core/view/version/?apikey=${ZAP_API_KEY}")
ok_with_key=$(echo "$r" | grep -c 'HTTP_200' || true)
add I9a 1 "$ok_with_key" "$(pass_fail "$ok_with_key" 1)" "in-lab allowlisted client + key: $r"
r2=$(lab_client "http://${ZAP_IP:-172.30.10.10}:8080/JSON/core/view/version/")
# Rejection may arrive as an HTTP error status OR as a connection reset — ZAP
# resets the connection for a missing API key. Both are rejections; the only
# unacceptable outcome is a successful 200.
granted_without_key=$(echo "$r2" | grep -c 'HTTP_200' || true)
add I9b 0 "$granted_without_key" "$(pass_fail "$granted_without_key" 0)" "in-lab client WITHOUT key must NOT get 200: $r2"
hostapi=$(timeout 6 curl -s -o /dev/null -w '%{http_code}' \
   "http://${ZAP_IP:-172.30.10.10}:8080/JSON/core/view/version/?apikey=${ZAP_API_KEY}" 2>/dev/null); hostapi="${hostapi:-000}"
add I9c "not-200" "$hostapi" "$([ "$hostapi" != "200" ] && echo true || echo false)" \
   "host (gateway .1, not in api.addrs allowlist) → ZAP API"

# === I10 hostname resolution contained ======================================
inlab=$(docker exec "$ZAP_C" bash -c "getent hosts $HOSTNAME_ALIAS | awk '{print \$1}' | head -n1" 2>/dev/null)
inlab_ok=$(python3 -c "
import ipaddress,sys
try: print('true' if ipaddress.ip_address('$inlab') in ipaddress.ip_network('$SUBNET') else 'false')
except Exception: print('false')")
add I10a "in $SUBNET" "${inlab:-<unresolved>}" "$inlab_ok" "alias resolved inside lab"
hostres=$(getent hosts "$HOSTNAME_ALIAS" >/dev/null 2>&1 && echo RESOLVED || echo UNRESOLVED)
add I10b UNRESOLVED "$hostres" "$(pass_fail "$hostres" UNRESOLVED)" "alias on the workstation (must not resolve)"

# === F1/F4 target reachability ==============================================
inlab_http=$(docker exec "$ZAP_C" bash -c \
  "timeout 6 bash -c 'exec 3<>/dev/tcp/$HOSTNAME_ALIAS/3000' >/dev/null 2>&1 && echo REACHABLE || echo BLOCKED" 2>/dev/null)
add F1 REACHABLE "$inlab_http" "$(pass_fail "$inlab_http" REACHABLE)" "juiceshop from zap via lab alias"
hosthttp=$(timeout 8 curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PUBLISH_PORT}/" 2>/dev/null); hosthttp="${hosthttp:-000}"
add F4 200 "$hosthttp" "$(pass_fail "$hosthttp" 200)" "workstation → http://127.0.0.1:${PUBLISH_PORT}/ (via make lab-publish; deviation D19)"
# The publish path must be loopback-bound ONLY — never 0.0.0.0, never the LAN IP.
pubbind=$(ss -lntH 2>/dev/null | awk -v p=":${PUBLISH_PORT}" '$4 ~ p {print $4}' | tr '\n' ' ')
nonloop_pub=$(echo "$pubbind" | tr ' ' '\n' | grep -vc '^127\.0\.0\.1:' | head -n1)
nonloop_pub=$(echo "$pubbind" | tr ' ' '\n' | grep -v '^$' | grep -vc '^127\.0\.0\.1:')
add F4b 0 "$nonloop_pub" "$(pass_fail "$nonloop_pub" 0)" "non-loopback listeners on :${PUBLISH_PORT} (bindings: ${pubbind:-<none>})"
lanip=$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)
if [ -n "$lanip" ]; then
  lanhttp=$(timeout 5 curl -s -o /dev/null -w '%{http_code}' "http://${lanip}:${PUBLISH_PORT}/" 2>/dev/null); lanhttp="${lanhttp:-000}"
  add F4c 000 "$lanhttp" "$(pass_fail "$lanhttp" 000)" "LAN interface ${lanip}:${PUBLISH_PORT} must NOT serve the app"
fi

# === PUB-* publishing probes.  NOTE: these were briefly numbered I14/I14b,
#      which collided with security invariant I14 (asset identity is immutable).
#      Renamed to the PUB-* namespace; the M1 lab probe ids I1a..I13 / F1..F4c
#      are frozen so docs/evidence/m1/ stays readable. See docs/INVARIANTS.md §0.
#      D20: containers reach host services bound on 0.0.0.0 via the lab gateway,
#      so a 0.0.0.0 publish of a VAPT component would also expose it. ==========
wild=$(docker ps --filter "name=^vapt" --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep -c '0\.0\.0\.0:' || true)
add PUB-1 0 "$wild" "$(pass_fail "$wild" 0)" "vapt containers with a 0.0.0.0 host publish"
# PUB-2 is an OBSERVATION, per assumption B10: it *reports* host-wide 0.0.0.0
# listeners, which lab containers can reach via the gateway. These are usually
# someone else's services on the operator's machine, which this platform cannot
# fix and must not silently ignore. It is therefore recorded in its own verdict
# (`host_hygiene_passed`) rather than conflated with lab containment: PUB-1
# (no VAPT container publishes on 0.0.0.0) remains fatal.
hostwild=$(ss -lntH 2>/dev/null | awk '{print $4}' | grep -E '^(0\.0\.0\.0|\*|\[::\]):' | sort -u | tr '\n' ' ')
HOST_WILDCARD_LISTENERS="${hostwild:-<none>}"
[ -z "$hostwild" ] && HOST_HYGIENE=true || HOST_HYGIENE=false
add PUB-2 "enumerated" "${hostwild:-<none>}" true "host 0.0.0.0 listeners reachable from lab containers via ${SUBNET%.*}.1 (D20/B10). Observation, not a containment failure; see host_hygiene_passed"

# === reachability matrix (D20) — observed classes, recorded not judged =======
# ECONNREFUSED to the gateway proves L3 reachability of the host without a listener;
# ENETUNREACH proves absence of a route (the actual isolation mechanism).
GW="$(docker network inspect "$LAB_NET" --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}' 2>/dev/null)"; GW="${GW:-${SUBNET%.*}.1}"
js_err() { docker exec "$JS_C" "$JS_NODE" -e "
const s=require('net').connect({host:'$1',port:$2,timeout:4000});
s.on('connect',()=>{console.log('REACHABLE');process.exit()});
s.on('error',e=>{console.log(e.code);process.exit()});s.on('timeout',()=>{console.log('TIMEOUT');process.exit()});" 2>/dev/null || echo PROBE_ERROR; }
M_INET=$(js_err 1.1.1.1 443); M_LAN=$(js_err "${LAN_GW:-192.168.1.1}" 80); M_HOSTGW=$(js_err "$GW" 9); M_HOSTLAN=$(js_err "$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)" 9); M_PEER=$(js_err "${ZAP_IP:-172.30.10.10}" 8080)
H_ZAP=$(timeout 4 bash -c "exec 3<>/dev/tcp/${ZAP_IP:-172.30.10.10}/8080" >/dev/null 2>&1 && echo REACHABLE || echo BLOCKED)
classify() { case "$1" in REACHABLE) echo reachable;; ECONNREFUSED) echo "host-reachable-at-L3 (nothing listening)";; ENETUNREACH) echo "no-route";; TIMEOUT) echo "filtered-or-dropped";; *) echo "$1";; esac; }
# PUB-2R MEASURES what PUB-2 only enumerates: can a lab container actually
# reach each wildcard host listener through the lab gateway? PUB-2 is a static
# observation and is deliberately conservative, because a listener that is
# unreachable today may become reachable after any change to host firewalling,
# Docker's rules or the other service's configuration.
#
# PUB-2R does NOT move the verdict. host_hygiene_passed still fails while a
# foreign wildcard listener exists; this probe only records whether the lab can
# presently reach it, so the owner decides with evidence rather than inference.
PUB2R_SUMMARY="not evaluated"
if [ -n "$hostwild" ]; then
  reach_list=""
  for spec in $hostwild; do
    hp="${spec##*:}"
    case "$hp" in ''|*[!0-9]*) continue;; esac
    r=$(js_err "$GW" "$hp")
    reach_list="$reach_list$hp=$r "
    case "$r" in
      REACHABLE) add "PUB-2R:$hp" "NOT-REACHABLE" "REACHABLE" false \
                     "a lab container CAN reach the host wildcard listener on port $hp through the lab gateway";;
      *)         add "PUB-2R:$hp" "NOT-REACHABLE" "$r" true \
                     "a lab container cannot presently reach the host wildcard listener on port $hp ($(classify "$r"))";;
    esac
  done
  PUB2R_SUMMARY="${reach_list:-none}"
fi

# isolation_passed : every I* probe  -> this is what the M3 scan gate consumes
# access_passed    : every F* probe  -> workstation convenience (D19 forwarder)
# passed           : both. Convenience must never move the scan gate either way.
egress_blocked=true; dns_contained=true; isolation_passed=true; access_passed=true
for r in "${RESULTS[@]}"; do
  IFS='|' read -r id req obs ok det <<< "$r"
  case "$id" in
    F*)     [ "$ok" = true ] || access_passed=false;;
    PUB-2)   : ;;  # observation only; recorded in host_hygiene_passed
    PUB-2R*) : ;;  # measurement only; recorded in host_listener_reachability
    *)      [ "$ok" = true ] || isolation_passed=false;;
  esac
  case "$id" in I2*|I3*) [ "$ok" = true ] || egress_blocked=false;; I4*) [ "$ok" = true ] || dns_contained=false;; esac
done
# `passed` keeps the strict meaning: containment AND workstation access AND host
# hygiene. The M3 scan gate consumes `isolation_passed` (containment) and is told
# `host_hygiene_passed` separately — see OPEN QUESTION in docs/MVP_PLAN.md §5.
passed=$isolation_passed
[ "$access_passed" = true ] || passed=false
[ "$HOST_HYGIENE" = true ] || passed=false
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
valid=$(date -u -d "+${TTL_MIN} minutes" +%Y-%m-%dT%H:%M:%SZ)
{
  echo "{"
  echo "  \"checked_at\": \"$now\","
  echo "  \"valid_until\": \"$valid\","
  echo "  \"network_name\": \"$LAB_NET\","
  echo "  \"subnet\": \"$SUBNET\","
  echo "  \"egress_blocked\": $egress_blocked,"
  echo "  \"dns_contained\": $dns_contained,"
  echo "  \"reachability_matrix\": {"
  echo "    \"container_to_internet\": \"$(classify "$M_INET")\","
  echo "    \"container_to_lan\": \"$(classify "$M_LAN")\","
  echo "    \"container_to_host_via_lab_gateway\": \"$(classify "$M_HOSTGW")\","
  echo "    \"container_to_host_via_lan_ip\": \"$(classify "$M_HOSTLAN")\","
  echo "    \"container_to_container_same_lab\": \"$(classify "$M_PEER")\","
  echo "    \"host_to_container\": \"$(classify "$H_ZAP")\","
  echo "    \"note\": \"internal:true is NOT host isolation: the host reaches containers, and containers reach host services bound on 0.0.0.0 via the lab gateway. Isolation claims cover container->internet and container->LAN only.\""
  echo "  },"
  echo "  \"host_wildcard_listeners\": \"$HOST_WILDCARD_LISTENERS\","
  echo "  \"host_hygiene_passed\": $HOST_HYGIENE,"
  echo "  \"host_listener_reachability\": \"$PUB2R_SUMMARY\","
  echo "  \"isolation_passed\": $isolation_passed,"
  echo "  \"access_passed\": $access_passed,"
  echo "  \"passed\": $passed,"
  echo "  \"probe_results\": ["
  n=${#RESULTS[@]}; i=0
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r id req obs ok det <<< "$r"; i=$((i+1)); c=,; [ $i -eq $n ] && c=
    printf '    {"id": "%s", "required": "%s", "observed": "%s", "pass": %s, "detail": "%s"}%s\n' \
      "$id" "$req" "$obs" "$ok" "$det" "$c"
  done
  echo "  ]"
  echo "}"
} | tee "${LAB_STATE_DIR:-.lab-state}/isolation-check.json" 2>/dev/null || true
case "$REQUIRE" in
  containment) [ "$isolation_passed" = true ];;
  *)           [ "$passed" = true ];;
esac
