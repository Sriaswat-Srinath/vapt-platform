#!/usr/bin/env bash
# M1.5 network architecture verification (NET-* probe namespace).
#
# Emits a machine-readable result. Exit 0 only when every probe produced its
# REQUIRED outcome. Probe ids are NET-* so they can never be confused with the
# security invariants I1..I14 (docs/INVARIANTS.md) or the frozen M1 lab probes.
#
# This check must be able to FAIL — see scripts/prove_net_failure.sh.
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] && { set -a; . ./.env; set +a; }
OUT_DIR="${LAB_STATE_DIR:-.lab-state}"; mkdir -p "$OUT_DIR"

EDGE_GW=172.30.20.1; CORE_GW=172.30.21.1; EGRESS_GW=172.30.22.1; WAN_GW=172.30.23.1
API_EDGE=172.30.20.20; API_CORE=172.30.21.20; API_EGRESS=172.30.22.20
FE=172.30.20.10; WK=172.30.21.30; PG=172.30.21.40; RD=172.30.21.50
PX=172.30.22.60; PX_WAN=172.30.23.60; STANDIN=172.30.23.70
LAN_IP=$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)
LAN_GW=$(ip -o -4 route show default 2>/dev/null | awk '{print $3}' | head -n1)
IP_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo unknown)

RESULTS=()
add() {
  local id req obs ok det
  id=$(printf '%s' "$1" | tr -d '\n|"'); req=$(printf '%s' "$2" | tr -d '\n|"')
  obs=$(printf '%s' "$3" | tr -d '[:cntrl:]|"' | sed 's/[[:space:]]*$//')
  ok=$(printf '%s' "$4" | tr -d '[:cntrl:]|" '); det=$(printf '%s' "${5:-}" | tr -d '[:cntrl:]|"')
  case "$ok" in true|false) ;; *) ok=false; det="MALFORMED PROBE RESULT: $det";; esac
  RESULTS+=("$id|$req|$obs|$ok|$det")
}
eq() { [ "$1" = "$2" ] && echo true || echo false; }
# "Blocked" has two legitimate observable classes:
#   ENETUNREACH            - no route at all (a source with no default route)
#   TIMEOUT / EHOSTUNREACH - the packet left via a default route and was DROPped
#                            by Docker inter-network isolation. The egress proxy
#                            MUST have a default route, so this is its class.
blocked() { case "$1" in ENETUNREACH|TIMEOUT|TimeoutError|EHOSTUNREACH) echo true;; *) echo false;; esac; }

have() { docker exec "$1" sh -c "command -v $2 >/dev/null 2>&1" >/dev/null 2>&1; }

# Route table, for images with or without python3. NO_PROBE_TOOL is a FAILURE,
# never a pass — the M1 `ip route` false-pass taught this.
route_of() {
  if have "$1" python3; then
    docker exec "$1" python3 -c "
rows=[l.split() for l in open('/proc/net/route').read().splitlines()[1:] if l.strip()]
d=[r[0] for r in rows if r[1]=='00000000']
print(('PRESENT:'+','.join(d)) if d else 'NONE')" 2>/dev/null || echo PROBE_ERROR
  elif have "$1" awk; then
    docker exec "$1" sh -c "awk 'NR>1 && \$2==\"00000000\" {print \"PRESENT:\"\$1; f=1} END{if(!f) print \"NONE\"}' /proc/net/route" 2>/dev/null || echo PROBE_ERROR
  else echo NO_PROBE_TOOL; fi
}

# Coarse reachability for images without python3 (REACHABLE | BLOCKED only).
tcp_coarse() { # $1 container  $2 host  $3 port
  if have "$1" nc; then
    docker exec "$1" sh -c "nc -z -w3 $2 $3 >/dev/null 2>&1 && echo REACHABLE || echo BLOCKED" 2>/dev/null || echo PROBE_ERROR
  else echo NO_PROBE_TOOL; fi
}

# DNS resolution of a public name from inside a container.
dns_of() {
  if have "$1" python3; then
    docker exec "$1" python3 -c "
import socket
try: socket.getaddrinfo('${ISOLATION_PROBE_DNS_NAME:-example.com}',443); print('RESOLVED')
except OSError: print('UNRESOLVED')" 2>/dev/null || echo PROBE_ERROR
  elif have "$1" nslookup; then
    docker exec "$1" sh -c "nslookup ${ISOLATION_PROBE_DNS_NAME:-example.com} >/dev/null 2>&1 && echo RESOLVED || echo UNRESOLVED" 2>/dev/null || echo PROBE_ERROR
  else echo NO_PROBE_TOOL; fi
}

# TCP connect from inside a container; prints REACHABLE | <errno class>
tcp() { # $1 container  $2 host  $3 port
  docker exec "$1" python3 -c "
import socket,sys
s=socket.socket(); s.settimeout(4)
try:
    s.connect(('$2',$3)); print('REACHABLE')
except OSError as e:
    import errno; print({errno.ENETUNREACH:'ENETUNREACH',errno.ECONNREFUSED:'ECONNREFUSED',errno.EHOSTUNREACH:'EHOSTUNREACH',errno.ETIMEDOUT:'TIMEOUT'}.get(e.errno, e.__class__.__name__))
finally: s.close()" 2>/dev/null || echo PROBE_ERROR
}
# HTTP request through the proxy from the api container; prints status|body-ish
via_proxy() { # $1 raw request line  $2 extra
  docker exec vapt_api python3 -c "
import socket
s=socket.socket(); s.settimeout(8)
try:
    s.connect(('$PX',3128))
    s.sendall(b'''$1\r\nHost: x\r\nX-Vapt-Trace: m15-probe\r\n\r\n''')
    d=s.recv(256).decode('latin-1','replace').split('\r\n')[0]
    print(d.strip() or 'EMPTY')
except OSError as e: print('ERR '+e.__class__.__name__)
finally: s.close()" 2>/dev/null || echo PROBE_ERROR
}

# ============================ Correction 5: attachments, identity, config ====
cfg=$(docker compose -f docker-compose.yml config --format json 2>/dev/null)
for spec in "vapt_frontend:vapt_edge" "vapt_api:vapt_core,vapt_edge,vapt_egress" \
            "vapt_worker:vapt_core" "vapt_postgres:vapt_core" "vapt_redis:vapt_core" \
            "vapt_egress_proxy:vapt_egress,vapt_wan" "vapt_llm_standin:vapt_wan"; do
  c="${spec%%:*}"; want="${spec##*:}"
  got=$(docker inspect "$c" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}},{{end}}' 2>/dev/null | tr ',' '\n' | grep -v '^$' | sort | paste -sd, -)
  add "NET-A:${c#vapt_}" "$want" "${got:-<none>}" "$(eq "$got" "$want")" "exact network attachment set"
done
# Image provenance. Two rules, because they are different situations:
#   third-party images  -> MUST be referenced by digest in compose, and the
#                          running container MUST match that digest.
#   first-party images  -> built from this repo, so there is no registry digest.
#                          Their Dockerfile's FROM MUST be digest-pinned, and the
#                          running container MUST match the locally built image id
#                          (no floating tag drift).
FIRST_PARTY="vapt_api"
for c in vapt_frontend vapt_api vapt_worker vapt_postgres vapt_redis vapt_egress_proxy vapt_llm_standin; do
  pinned=$(printf '%s' "$cfg" | python3 -c "
import json,sys
c=json.load(sys.stdin)
for n,s in c['services'].items():
    if s.get('container_name')=='$c': print(s['image']); break" 2>/dev/null)
  imgid=$(docker inspect "$c" --format '{{.Image}}' 2>/dev/null)
  case " $FIRST_PARTY " in
    *" $c "*)
      # FROM must be digest-pinned
      base_ok=$(grep -cE '^FROM .*@sha256:[0-9a-f]{64}' backend/Dockerfile 2>/dev/null || true)
      add "NET-B:${c#vapt_}:base-pinned" 1 "${base_ok:-0}" "$(eq "${base_ok:-0}" 1)" \
          "first-party image: Dockerfile FROM is digest-pinned"
      tagid=$(docker image inspect "$pinned" --format '{{.Id}}' 2>/dev/null)
      add "NET-B:${c#vapt_}:running" "$tagid" "$imgid" "$(eq "$imgid" "$tagid")" \
          "running container matches the locally built image id (image ref: ${pinned:-<none>})"
      ;;
    *)
      case "$pinned" in *@sha256:*) pin_ok=true;; *) pin_ok=false;; esac
      add "NET-B:${c#vapt_}:pinned" true "$pin_ok" "$pin_ok" "compose image: ${pinned:-<none>}"
      want="${pinned##*@}"
      rd=$(docker image inspect "$imgid" --format '{{json .RepoDigests}}' 2>/dev/null)
      case "$rd" in *"$want"*) run_ok=true;; *) run_ok=false;; esac
      add "NET-B:${c#vapt_}:running" true "$run_ok" "$run_ok" "running image digest matches the pin"
      ;;
  esac
done
# environment hygiene
for c in vapt_worker vapt_frontend; do
  leak=$(docker inspect "$c" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
         | grep -icE '^(LLM_|.*API_KEY|HTTPS?_PROXY|ANTHROPIC|OPENAI|ZAP_API_KEY)' || true)
  add "NET-C:${c#vapt_}" 0 "$leak" "$(eq "$leak" 0)" "no LLM/proxy/credential env in ${c#vapt_}"
done
pxleak=$(docker inspect vapt_egress_proxy --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep -icE '^(.*API_KEY|DATABASE_URL|POSTGRES_|REDIS_)' || true)
add "NET-C:proxy" 0 "$pxleak" "$(eq "$pxleak" 0)" "proxy holds no application credentials"
apiproxy=$(docker inspect vapt_api --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep -c '^HTTPS_PROXY=http://172.30.22.60:3128' || true)
add "NET-C:api-proxy" 1 "$apiproxy" "$(eq "$apiproxy" 1)" "api is configured to egress ONLY via the proxy"
apikey=$(docker inspect vapt_api --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep -icE 'API_KEY|ANTHROPIC|OPENAI' || true)
add "NET-C:api-nocred" 0 "$apikey" "$(eq "$apikey" 0)" "no provider credential in the api environment"
# published ports + docker socket + routes
for c in vapt_frontend vapt_api vapt_worker vapt_postgres vapt_redis vapt_egress_proxy vapt_llm_standin; do
  pb=$(docker inspect "$c" --format '{{json .HostConfig.PortBindings}}' 2>/dev/null)
  nonloop=$(printf '%s' "$pb" | grep -c '"HostIp": *"0\.0\.0\.0"' || true)
  add "NET-D:${c#vapt_}" 0 "$nonloop" "$(eq "$nonloop" 0)" "no 0.0.0.0 publish (bindings: $pb)"
  sock=$(docker inspect "$c" --format '{{range .Mounts}}{{.Source}} {{end}}' 2>/dev/null | grep -c 'docker.sock' || true)
  add "NET-E:${c#vapt_}" 0 "$sock" "$(eq "$sock" 0)" "docker socket absent"
done
for spec in "vapt_api:NONE" "vapt_worker:NONE" "vapt_frontend:NONE" "vapt_postgres:NONE" "vapt_redis:NONE" "vapt_egress_proxy:PRESENT"; do
  c="${spec%%:*}"; want="${spec##*:}"
  dr=$(route_of "$c"); obs="$dr"
  case "$dr" in PRESENT*) cls=PRESENT;; NONE) cls=NONE;; *) cls="$dr";; esac
  add "NET-F:${c#vapt_}" "$want" "$obs" "$(eq "$cls" "$want")" "default route (only the proxy may have one; a missing probe tool FAILS)"
done

# === NET-P* real datastores introduce no egress path (M2-N1) =================
r=$(tcp_coarse vapt_postgres 1.1.1.1 443); add NET-P1 BLOCKED "$r" "$(eq "$r" BLOCKED)" "postgres -> internet (coarse probe; busybox nc, tool verified)"
r=$(tcp_coarse vapt_redis 1.1.1.1 443);    add NET-P2 BLOCKED "$r" "$(eq "$r" BLOCKED)" "redis -> internet"
r=$(tcp_coarse vapt_postgres "${LAN_GW:-192.168.1.1}" 80); add NET-P3 BLOCKED "$r" "$(eq "$r" BLOCKED)" "postgres -> LAN gateway"
r=$(tcp_coarse vapt_redis "${LAN_GW:-192.168.1.1}" 80);    add NET-P4 BLOCKED "$r" "$(eq "$r" BLOCKED)" "redis -> LAN gateway"
r=$(tcp_coarse vapt_postgres "$PX" 3128);  add NET-P5 BLOCKED "$r" "$(eq "$r" BLOCKED)" "postgres -> egress proxy"
r=$(tcp_coarse vapt_redis "$PX" 3128);     add NET-P6 BLOCKED "$r" "$(eq "$r" BLOCKED)" "redis -> egress proxy"
pgbind=$(docker exec vapt_postgres sh -c "netstat -ltn 2>/dev/null | awk '\$4 ~ /:5432$/ {print \$4}'" 2>/dev/null | tr '\n' ' ')
pgwild=$(printf '%s' "$pgbind" | grep -c '0\.0\.0\.0:5432' || true)
add NET-P7 0 "$pgwild" "$(eq "$pgwild" 0)" "postgres listens on the core interface only (observed: ${pgbind:-<none>})"
rdbind=$(docker exec vapt_redis sh -c "netstat -ltn 2>/dev/null | awk '\$4 ~ /:6379$/ {print \$4}'" 2>/dev/null | tr '\n' ' ')
rdwild=$(printf '%s' "$rdbind" | grep -c '0\.0\.0\.0:6379' || true)
add NET-P8 0 "$rdwild" "$(eq "$rdwild" 0)" "redis listens on the core interface only (observed: ${rdbind:-<none>})"
pgauth=$(docker exec -e PGPASSWORD="${POSTGRES_PASSWORD:-}" vapt_postgres \
  psql -h "$PG" -U "${POSTGRES_USER:-vapt}" -d "${POSTGRES_DB:-vapt}" -tAc "show password_encryption" 2>/dev/null | tr -d ' \n')
add NET-P9 scram-sha-256 "${pgauth:-PROBE_ERROR}" "$(eq "$pgauth" scram-sha-256)" "postgres password encryption (authenticated query over the core interface)"
rdnoauth=$(docker exec vapt_redis sh -c "redis-cli -h 172.30.21.50 ping 2>&1" 2>/dev/null | grep -c 'NOAUTH' || true)
add NET-P10 1 "$rdnoauth" "$(eq "$rdnoauth" 1)" "redis rejects unauthenticated commands (NOAUTH)"
# `grep -c` exits 1 on zero matches, so count without letting that become an
# error, and distinguish "file unreadable" (PROBE_ERROR) from "zero matches".
pgtrust=$(docker exec vapt_postgres sh -c '
  f=/var/lib/postgresql/data/pgdata/pg_hba.conf
  [ -r "$f" ] || { echo PROBE_ERROR; exit 0; }
  awk "/^[[:space:]]*(host|local)/ && /trust/ {n++} END{print n+0}" "$f"' 2>/dev/null || echo PROBE_ERROR)
add NET-P11 0 "${pgtrust:-PROBE_ERROR}" "$(eq "$pgtrust" 0)" "no trust authentication in pg_hba.conf"

# === NET-DNS-* egress cannot be tunnelled over DNS (High concern) ===========
for c in vapt_api vapt_worker vapt_frontend; do
  r=$(dns_of "$c"); add "NET-DNS:${c#vapt_}" UNRESOLVED "$r" "$(eq "$r" UNRESOLVED)" "public DNS name must not resolve from ${c#vapt_} (no DNS-based egress)"
done
r=$(dns_of vapt_egress_proxy); add NET-DNS:proxy RESOLVED "$r" "$(eq "$r" RESOLVED)" "the proxy DOES resolve (by design — it is the boundary); its ACL, not DNS, is the control"
for c in vapt_api vapt_worker; do
  u=$(docker exec "$c" python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3)
try:
    s.sendto(b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01',('8.8.8.8',53))
    s.recvfrom(512); print('REPLIED')
except OSError as e:
    import errno; print('BLOCKED' if e.errno in (errno.ENETUNREACH,errno.EHOSTUNREACH,errno.EPERM) else 'NO_REPLY')
except Exception: print('NO_REPLY')
finally: s.close()" 2>/dev/null || echo PROBE_ERROR)
  ok=$(case "$u" in BLOCKED|NO_REPLY) echo true;; *) echo false;; esac)
  add "NET-UDP:${c#vapt_}" "BLOCKED|NO_REPLY" "$u" "$ok" "UDP/53 to a public resolver from ${c#vapt_} must not get a reply"
done

# ============================ Correction 2: host-gateway vs LAN ==============
for spec in "vapt_api:$EDGE_GW" "vapt_worker:$CORE_GW" "vapt_frontend:$EDGE_GW"; do
  c="${spec%%:*}"; gw="${spec##*:}"
  r=$(tcp "$c" "$gw" 9)      # nothing listens on 9: ECONNREFUSED proves L3 reach
  case "$r" in ECONNREFUSED|REACHABLE) ok=true;; *) ok=false;; esac
  add "NET-HG:${c#vapt_}:gateway" "ECONNREFUSED|REACHABLE" "$r" "$ok" "container -> host via its network gateway $gw (L3 reachable by design; NOT host isolation)"
  r=$(tcp "$c" "${LAN_IP:-127.0.0.1}" 9)
  add "NET-HG:${c#vapt_}:lan-ip" ENETUNREACH "$r" "$(eq "$r" ENETUNREACH)" "container -> host via the host's LAN IP ${LAN_IP} (must have no route)"
done
add "NET-K1" "recorded" "ip_forward=$IP_FORWARD" true "host net.ipv4.ip_forward recorded (LAN-peer->container would additionally need a LAN route)"

# ============================ Correction 4: worker/frontend/api egress =======
r=$(tcp vapt_worker 1.1.1.1 443);          add NET-G1 ENETUNREACH "$r" "$(eq "$r" ENETUNREACH)" "worker -> internet"
r=$(tcp vapt_worker "${LAN_GW:-192.168.1.1}" 80); add NET-G2 ENETUNREACH "$r" "$(eq "$r" ENETUNREACH)" "worker -> LAN gateway"
r=$(tcp vapt_worker "$PX" 3128);           add NET-G3 ENETUNREACH "$r" "$(eq "$r" ENETUNREACH)" "worker -> egress proxy (must be unreachable)"
r=$(tcp vapt_worker "$API_EDGE" 8000);     add NET-G4 ENETUNREACH "$r" "$(eq "$r" ENETUNREACH)" "worker -> api edge address (no route)"
r=$(tcp vapt_worker "$API_CORE" 8000);     add NET-G5 ECONNREFUSED "$r" "$(eq "$r" ECONNREFUSED)" "worker -> api core address: api binds the EDGE interface only, so no listener here"
r=$(tcp vapt_worker "$PG" 5432);           add NET-G6a REACHABLE "$r" "$(eq "$r" REACHABLE)" "worker -> postgres"
r=$(tcp vapt_worker "$RD" 6379);           add NET-G6b REACHABLE "$r" "$(eq "$r" REACHABLE)" "worker -> redis"
r=$(tcp vapt_worker "$STANDIN" 8443);      add NET-G7 ENETUNREACH "$r" "$(eq "$r" ENETUNREACH)" "worker -> llm stand-in (no WAN route)"
r=$(tcp vapt_api 1.1.1.1 443);             add NET-H1 ENETUNREACH "$r" "$(eq "$r" ENETUNREACH)" "api -> internet DIRECT (must be blocked; egress only via the proxy)"
r=$(tcp vapt_api "$PX" 3128);              add NET-H2 REACHABLE "$r" "$(eq "$r" REACHABLE)" "api -> egress proxy"
r=$(tcp vapt_api "$PG" 5432);              add NET-H3a REACHABLE "$r" "$(eq "$r" REACHABLE)" "api -> postgres"
r=$(tcp vapt_api "$RD" 6379);              add NET-H3b REACHABLE "$r" "$(eq "$r" REACHABLE)" "api -> redis"
r=$(tcp vapt_api "$STANDIN" 8443);         add NET-H4 ENETUNREACH "$r" "$(eq "$r" ENETUNREACH)" "api -> stand-in directly (must go through the proxy)"
r=$(tcp vapt_frontend "$API_EDGE" 8000);   add NET-I1 REACHABLE "$r" "$(eq "$r" REACHABLE)" "frontend -> api (edge)"
r=$(tcp vapt_frontend "$PG" 5432);         add NET-I2a ENETUNREACH "$r" "$(eq "$r" ENETUNREACH)" "frontend -> postgres"
r=$(tcp vapt_frontend "$RD" 6379);         add NET-I2b ENETUNREACH "$r" "$(eq "$r" ENETUNREACH)" "frontend -> redis"
r=$(tcp vapt_frontend "$PX" 3128);         add NET-I3 ENETUNREACH "$r" "$(eq "$r" ENETUNREACH)" "frontend -> egress proxy (must be unreachable)"
r=$(tcp vapt_frontend 1.1.1.1 443);        add NET-I4 ENETUNREACH "$r" "$(eq "$r" ENETUNREACH)" "frontend -> internet"
# proxy must not reach application or scanner components
r=$(tcp vapt_egress_proxy "$PG" 5432);     add NET-J7a "BLOCKED(ENETUNREACH|TIMEOUT)" "$r" "$(blocked "$r")" "proxy -> postgres — the proxy HAS a default route, so unreachability here rests on Docker inter-network isolation (silent DROP), not on absence of a route"
r=$(tcp vapt_egress_proxy "$RD" 6379);     add NET-J7b "BLOCKED(ENETUNREACH|TIMEOUT)" "$r" "$(blocked "$r")" "proxy -> redis — the proxy HAS a default route, so unreachability here rests on Docker inter-network isolation (silent DROP), not on absence of a route"
r=$(tcp vapt_egress_proxy "$WK" 9000);     add NET-J7c "BLOCKED(ENETUNREACH|TIMEOUT)" "$r" "$(blocked "$r")" "proxy -> worker — the proxy HAS a default route, so unreachability here rests on Docker inter-network isolation (silent DROP), not on absence of a route"
r=$(tcp vapt_egress_proxy "$API_EGRESS" 8000); add NET-J8 ECONNREFUSED "$r" "$(eq "$r" ECONNREFUSED)" "proxy -> api egress address: no listener (api binds edge only)"
r=$(tcp vapt_egress_proxy 172.30.10.10 8080);  add NET-J9a "BLOCKED(ENETUNREACH|TIMEOUT)" "$r" "$(blocked "$r")" "proxy -> zap (scanner plane) — the proxy HAS a default route, so unreachability here rests on Docker inter-network isolation (silent DROP), not on absence of a route"
r=$(tcp vapt_egress_proxy 172.30.10.20 3000);  add NET-J9b "BLOCKED(ENETUNREACH|TIMEOUT)" "$r" "$(blocked "$r")" "proxy -> juiceshop (scanner plane) — the proxy HAS a default route, so unreachability here rests on Docker inter-network isolation (silent DROP), not on absence of a route"

# ============================ Correction 3: proxy ACL ========================
r=$(via_proxy "CONNECT llm-standin:8443 HTTP/1.1"); add NET-J1 "HTTP/1.1 200*" "$r" "$(case "$r" in *200*) echo true;; *) echo false;; esac)" "permitted CONNECT to the allowlisted stand-in"
tunnel=$(docker exec vapt_api python3 -c "
import socket
s=socket.socket(); s.settimeout(8)
s.connect(('$PX',3128))
s.sendall(b'CONNECT llm-standin:8443 HTTP/1.1\r\nHost: llm-standin\r\n\r\n')
if b'200' not in s.recv(128): print('NO_TUNNEL'); raise SystemExit
s.sendall(b'PING\n'); print(s.recv(64).decode().strip() or 'EMPTY')
s.close()" 2>/dev/null || echo PROBE_ERROR)
add NET-J1b PONG "$tunnel" "$(eq "$tunnel" PONG)" "bytes flow end-to-end through the tunnel"
r=$(via_proxy "CONNECT llm-standin:443 HTTP/1.1");  add NET-J2 "403*" "$r" "$(case "$r" in *403*) echo true;; *) echo false;; esac)" "denied: allowlisted host, non-allowlisted PORT"
r=$(via_proxy "CONNECT example.com:443 HTTP/1.1");  add NET-J3 "403*" "$r" "$(case "$r" in *403*) echo true;; *) echo false;; esac)" "denied: non-allowlisted HOST (real provider class)"
r=$(via_proxy "GET http://llm-standin:8443/ HTTP/1.1"); add NET-J4a "403*" "$r" "$(case "$r" in *403*) echo true;; *) echo false;; esac)" "denied: plain-HTTP absolute-URI GET (not CONNECT)"
r=$(via_proxy "POST http://llm-standin:8443/v1 HTTP/1.1"); add NET-J4b "403*" "$r" "$(case "$r" in *403*) echo true;; *) echo false;; esac)" "denied: POST"
r=$(via_proxy "CONNECT 172.30.21.40:5432 HTTP/1.1"); add NET-J5 "403*" "$r" "$(case "$r" in *403*) echo true;; *) echo false;; esac)" "denied: CONNECT to an internal component (postgres)"
r=$(via_proxy "CONNECT 172.30.10.10:8080 HTTP/1.1"); add NET-J6 "403*" "$r" "$(case "$r" in *403*) echo true;; *) echo false;; esac)" "denied: CONNECT to the scanner plane (zap)"
denies=$(docker logs vapt_egress_proxy 2>&1 | grep -c '"verdict": "deny"' || true)
add NET-J10 ">0" "$denies" "$([ "${denies:-0}" -gt 0 ] && echo true || echo false)" "proxy logged its denials"
allow_logged=$(docker logs vapt_egress_proxy 2>&1 | grep -c '"verdict": "allow"' || true)
add NET-J10b ">0" "$allow_logged" "$([ "${allow_logged:-0}" -gt 0 ] && echo true || echo false)" "proxy logged the permitted tunnel"
# the proxy listens on its egress interface only
r=$(tcp vapt_llm_standin "$PX_WAN" 3128); add NET-J11 ECONNREFUSED "$r" "$(eq "$r" ECONNREFUSED)" "WAN side cannot use the proxy (binds the egress interface only)"
# no real provider in the test allowlist, and nothing public is reachable through it
al=$(docker inspect vapt_egress_proxy --format '{{range .Config.Env}}{{println .}}{{end}}' | sed -n 's/^EGRESS_ALLOWLIST=//p')
bad=$(printf '%s' "$al" | tr ',' '\n' | grep -vc '^llm-standin:8443$' || true)
add NET-K2 0 "$bad" "$(eq "$bad" 0)" "test allowlist contains ONLY the local stand-in (observed: ${al:-<empty>}) — the real provider is never contacted"
# Non-contact is proven from the proxy's own decision log, not from DNS:
# resolution is not contact, and the proxy legitimately has a resolver. Every
# ALLOW must name the stand-in; an allow for anything else would be a contact.
foreign=$(docker logs vapt_egress_proxy 2>&1 | python3 -c "
import json,sys
bad=0
for ln in sys.stdin:
    ln=ln.strip()
    if not ln.startswith('{'): continue
    try: e=json.loads(ln)
    except ValueError: continue
    if e.get('verdict') in ('allow','closed') and e.get('destination','').lower()!='llm-standin:8443': bad+=1
print(bad)" 2>/dev/null || echo PROBE_ERROR)
add NET-K3 0 "$foreign" "$(eq "$foreign" 0)" "proxy log shows no permitted tunnel to any destination other than the local stand-in — the real provider was never contacted"
resolved_to=$(docker logs vapt_egress_proxy 2>&1 | python3 -c "
import json,sys
ips=set()
for ln in sys.stdin:
    ln=ln.strip()
    if not ln.startswith('{'): continue
    try: e=json.loads(ln)
    except ValueError: continue
    if e.get('verdict')=='allow': ips.update(e.get('resolved',[]))
print(','.join(sorted(ips)) or 'NONE')" 2>/dev/null || echo PROBE_ERROR)
add NET-K4 "172.30.23.70" "$resolved_to" "$(eq "$resolved_to" "172.30.23.70")" "every permitted tunnel resolved to the local stand-in address only"

# ============================ verdict ========================================
net_passed=true
for r in "${RESULTS[@]}"; do IFS='|' read -r id req obs ok det <<< "$r"; [ "$ok" = true ] || net_passed=false; done
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
{
  echo "{"
  echo "  \"checked_at\": \"$now\","
  echo "  \"ip_forward\": \"$IP_FORWARD\","
  echo "  \"host_lan_ip\": \"${LAN_IP:-unknown}\","
  echo "  \"networks\": {\"edge\": \"172.30.20.0/24\", \"core\": \"172.30.21.0/24\", \"egress\": \"172.30.22.0/24\", \"wan\": \"172.30.23.0/24\"},"
  echo "  \"llm_test_configuration\": {\"provider_host\": \"llm-standin\", \"provider_port\": 8443, \"real_provider_contacted\": false},"
  echo "  \"host_isolation_note\": \"internal:true is container->internet and container->LAN isolation only. Containers reach host services bound on 0.0.0.0 via their network gateway, and the host reaches containers. This is NOT complete host isolation.\","
  echo "  \"net_passed\": $net_passed,"
  echo "  \"probe_results\": ["
  n=${#RESULTS[@]}; i=0
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r id req obs ok det <<< "$r"; i=$((i+1)); c=,; [ $i -eq $n ] && c=
    printf '    {"id": "%s", "required": "%s", "observed": "%s", "pass": %s, "detail": "%s"}%s\n' "$id" "$req" "$obs" "$ok" "$det" "$c"
  done
  echo "  ]"
  echo "}"
} | tee "$OUT_DIR/net-verify.json"
[ "$net_passed" = true ]
