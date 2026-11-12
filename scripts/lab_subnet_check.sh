#!/usr/bin/env bash
# Refuse to bring up the lab if LAB_SUBNET overlaps an existing Docker network
# or a host route. Prevents the lab from hijacking traffic for something else.
set -euo pipefail
SUBNET="${LAB_SUBNET:-172.30.10.0/24}"
LAB_NET_NAME="${LAB_NETWORK_NAME:-vapt_lab}"

existing=$(docker network ls -q | while read -r id; do
  docker network inspect "$id" --format '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null
done)
routes=$(ip -o -4 route show 2>/dev/null | awk '{print $1}' | grep -E '^[0-9]+\.' || true)

python3 - "$SUBNET" "$LAB_NET_NAME" <<'PY'
import ipaddress, subprocess, sys
want = ipaddress.ip_network(sys.argv[1]); mine = sys.argv[2]
conflicts = []
out = subprocess.run(["docker","network","ls","-q"],capture_output=True,text=True).stdout.split()
for nid in out:
    fmt='{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}'
    line = subprocess.run(["docker","network","inspect",nid,"--format",fmt],
                          capture_output=True,text=True).stdout.split()
    if not line: continue
    name, subnets = line[0], line[1:]
    for s in subnets:
        try: net = ipaddress.ip_network(s)
        except ValueError: continue
        if net.overlaps(want) and name != mine:
            conflicts.append(f"docker network '{name}' uses {s}")
# The lab's OWN bridge adds a host route for its subnet once it is up. That is
# not a conflict with anything: identify our bridge (br-<network id prefix>) and
# ignore routes on it. Routes on any OTHER device remain conflicts.
own_bridges = set()
nid = subprocess.run(["docker","network","inspect",mine,"--format","{{.Id}}"],
                     capture_output=True,text=True).stdout.strip()
if nid:
    own_bridges.add("br-" + nid[:12])
r = subprocess.run(["ip","-o","-4","route","show"],capture_output=True,text=True).stdout
for ln in r.splitlines():
    parts = ln.split()
    tok = parts[0]
    dev = parts[parts.index("dev")+1] if "dev" in parts else "?"
    try: net = ipaddress.ip_network(tok)
    except ValueError: continue
    if net.overlaps(want) and net.prefixlen > 0 and dev not in own_bridges:
        conflicts.append(f"host route {tok} on {dev}")
if conflicts:
    print(f"SUBNET CONFLICT for {want}:")
    for c in sorted(set(conflicts)): print(f"  - {c}")
    print("Refusing to start the lab. Set LAB_SUBNET to a free range.")
    sys.exit(1)
print(f"subnet {want}: free (no docker network or host route overlap)")
PY
