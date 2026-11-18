#!/usr/bin/env bash
# Run the lab isolation check and report the measured result to the API, which
# stores it as a lab_isolation_checks row. Preflight gate 2 consumes the latest.
# The platform never reads the host filesystem; the operator reports.
set -euo pipefail
cd "$(dirname "$0")/.."
TOKEN=$(python3 -c "import json;print(json.load(open('.lab-state/tokens.json'))['admin'])")
OUT=$(./scripts/lab_isolation_check.sh --require containment || true)
python3 - "$TOKEN" <<'PY'
import json, subprocess, sys, urllib.request
token = sys.argv[1]
raw = subprocess.run(["./scripts/lab_isolation_check.sh", "--require", "containment"],
                     capture_output=True, text=True)
doc = json.loads(raw.stdout[raw.stdout.index("{"):])
payload = {k: doc[k] for k in ("checked_at", "valid_until", "network_name", "subnet",
                               "egress_blocked", "dns_contained", "isolation_passed",
                               "host_hygiene_passed", "host_wildcard_listeners")}
payload["probe_results"] = doc["probe_results"]
req = urllib.request.Request("http://127.0.0.1:8000/api/v1/system/isolation/report",
                             data=json.dumps(payload).encode(),
                             headers={"Content-Type": "application/json",
                                      "Authorization": f"Bearer {token}"}, method="POST")
with urllib.request.urlopen(req, timeout=20) as r:
    print(r.status, r.read().decode())
PY
