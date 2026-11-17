#!/usr/bin/env bash
# Refuse to bring up the app-plane networks if any VAPT subnet overlaps an
# existing Docker network or a host route (excluding our own bridges).
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] && { set -a; . ./.env; set +a; }
python3 - <<'PY'
import ipaddress, os, subprocess, sys
want = {
  "vapt_edge":   os.environ.get("EDGE_SUBNET",   "172.30.20.0/24"),
  "vapt_core":   os.environ.get("CORE_SUBNET",   "172.30.21.0/24"),
  "vapt_egress": os.environ.get("EGRESS_SUBNET", "172.30.22.0/24"),
  "vapt_wan":    os.environ.get("WAN_SUBNET",    "172.30.23.0/24"),
  "vapt_lab":    os.environ.get("LAB_SUBNET",    "172.30.10.0/24"),
}
nets = {n: ipaddress.ip_network(s) for n, s in want.items()}
own_bridges, conflicts = set(), []
for name in nets:
    nid = subprocess.run(["docker","network","inspect",name,"--format","{{.Id}}"],
                         capture_output=True,text=True).stdout.strip()
    if nid: own_bridges.add("br-"+nid[:12])
names = list(nets)
for i, a in enumerate(names):
    for b in names[i+1:]:
        if nets[a].overlaps(nets[b]): conflicts.append(f"{a} {nets[a]} overlaps {b} {nets[b]}")
for nid in subprocess.run(["docker","network","ls","-q"],capture_output=True,text=True).stdout.split():
    out = subprocess.run(["docker","network","inspect",nid,"--format",
                          '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}'],
                         capture_output=True,text=True).stdout.split()
    if len(out) < 2: continue
    name, subnets = out[0], out[1:]
    if name in nets: continue
    for s in subnets:
        try: net = ipaddress.ip_network(s)
        except ValueError: continue
        for n, w in nets.items():
            if net.overlaps(w): conflicts.append(f"docker network '{name}' {s} overlaps {n} {w}")
for ln in subprocess.run(["ip","-o","-4","route","show"],capture_output=True,text=True).stdout.splitlines():
    p = ln.split(); dev = p[p.index("dev")+1] if "dev" in p else "?"
    if dev in own_bridges: continue
    try: net = ipaddress.ip_network(p[0])
    except ValueError: continue
    for n, w in nets.items():
        if net.overlaps(w) and net.prefixlen > 0:
            conflicts.append(f"host route {p[0]} on {dev} overlaps {n} {w}")
if conflicts:
    print("SUBNET CONFLICT:")
    for c in sorted(set(conflicts)): print("  -", c)
    sys.exit(1)
print("vapt subnets free:", ", ".join(f"{n}={s}" for n, s in want.items()))
PY
