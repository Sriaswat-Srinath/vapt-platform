#!/usr/bin/env bash
# Measure an authorisation document and report its digest to the API.
#
# The platform never reads the host filesystem: the operator measures, the
# platform compares. Gate 5 denies if the attested digest differs from the one
# the grant was approved against, so an edit to a signed document stops
# scanning rather than silently changing what was authorised.
#
# Usage: scripts/attest_authorisation.sh [path] [note]
set -euo pipefail
cd "$(dirname "$0")/.."
DOC="${1:-lab/authorisation/MOCK-WEB-001.md}"
NOTE="${2:-}"
[ -f "$DOC" ] || { echo "no such document: $DOC" >&2; exit 2; }

DIGEST=$(sha256sum "$DOC" | awk '{print $1}')
SIZE=$(wc -c < "$DOC" | tr -d ' ')
TOKEN=$(python3 -c "import json;print(json.load(open('.lab-state/tokens.json'))['admin'])")

echo "document : $DOC"
echo "sha256   : $DIGEST"
echo "bytes    : $SIZE"

python3 - "$TOKEN" "$DOC" "$DIGEST" "$SIZE" "$NOTE" <<'PY'
import json, sys, urllib.error, urllib.request
token, doc, digest, size, note = sys.argv[1:6]
payload = {"document_ref": doc, "document_sha256": digest, "byte_size": int(size),
           "note": note or None}
req = urllib.request.Request("http://127.0.0.1:8000/api/v1/authorisation-documents/attest",
                             data=json.dumps(payload).encode(),
                             headers={"Content-Type": "application/json",
                                      "Authorization": f"Bearer {token}"}, method="POST")
try:
    with urllib.request.urlopen(req, timeout=20) as r:
        body = json.loads(r.read().decode())
except urllib.error.HTTPError as e:
    print(e.code, e.read().decode()); raise SystemExit(1)
print(json.dumps(body, indent=2))
if body.get("grants_with_a_different_digest"):
    raise SystemExit(1)
PY
