#!/usr/bin/env bash
# Prove that editing the authorisation document stops scanning.
#
# The document claims: "any edit after activation invalidates the grant and
# blocks scanning until it is re-approved". This measures that claim instead of
# trusting it, the same way scripts/prove_net_failure.sh measures containment.
#
# It does NOT sign anything and does NOT activate a grant. It works on a COPY
# of the document in a scratch path, attests the copy, and shows gate 5's
# verdict for a grant recorded against the original digest.
set -uo pipefail
cd "$(dirname "$0")/.."
DOC="lab/authorisation/MOCK-WEB-001.md"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
REF="proof/$(basename "$DOC")"
TOKEN=$(python3 -c "import json;print(json.load(open('.lab-state/tokens.json'))['admin'])")

cp "$DOC" "$TMP/doc.md"
ORIGINAL=$(sha256sum "$TMP/doc.md" | awk '{print $1}')
printf '\n<!-- an unauthorised edit -->\n' >> "$TMP/doc.md"
TAMPERED=$(sha256sum "$TMP/doc.md" | awk '{print $1}')

echo "original : $ORIGINAL"
echo "tampered : $TAMPERED"
[ "$ORIGINAL" != "$TAMPERED" ] || { echo "FAIL: the edit did not change the digest"; exit 1; }

python3 - "$TOKEN" "$REF" "$ORIGINAL" "$TAMPERED" <<'PY'
import datetime as dt, json, pathlib, sys, urllib.request
sys.path.insert(0, str(pathlib.Path("backend").resolve()))
import os
os.environ.setdefault("SECRET_KEY", "proof"); os.environ.setdefault(
    "DATABASE_URL", "postgresql+psycopg://unused:unused@127.0.0.1:1/unused")
from app.safety import scope_policy as sp

token, ref, original, tampered = sys.argv[1:5]

def attest(digest, note):
    req = urllib.request.Request(
        "http://127.0.0.1:8000/api/v1/authorisation-documents/attest",
        data=json.dumps({"document_ref": ref, "document_sha256": digest,
                         "note": note}).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        method="POST")
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode())

now = dt.datetime.now(dt.timezone.utc)

def gate5(attested):
    grant = sp.GrantSnapshot(
        id="proof", state="active", document_state="signed_verified",
        allowed_cidrs=("172.30.10.0/24",), allowed_ports=(3000,),
        allowed_profiles=("zap-passive",), intrusive_allowed=False,
        valid_from=None, valid_until=None, revoked_at=None,
        document_ref=ref, document_sha256=original)
    req = sp.ScopeRequest(now=now, subject_type="scan_job", mode=sp.MODE_LIVE, grant=grant,
                          attested_document_sha256=attested,
                          attested_document_at=now - dt.timedelta(minutes=1))
    return sp.GATES[4][2](req)

baseline = gate5(original)
print(f"\nBASELINE  gate 5 with the approved digest  -> "
      f"{'PASS' if baseline.passed else 'DENY'}")
if not baseline.passed:
    print(f"  unexpected: {baseline.reason}")
    raise SystemExit(1)

body = attest(tampered, "prove_authorisation_tamper.sh — scratch copy, not the real document")
after = gate5(tampered)
print(f"TAMPERED  gate 5 after the edit            -> "
      f"{'PASS' if after.passed else 'DENY'}")
print(f"  reason: {after.reason}")
if after.passed:
    print("\nFAIL: an edited authorisation document did NOT stop the gate chain")
    raise SystemExit(1)

reverted = gate5(original)
print(f"REVERTED  gate 5 with the original digest  -> "
      f"{'PASS' if reverted.passed else 'DENY'}")
if not reverted.passed:
    print("\nFAIL: the check did not revert cleanly")
    raise SystemExit(1)
print(f"\nattestation recorded: {body['id']}")
print("PROVED: the gate chain denies while the attested document differs from "
      "the one the grant was approved against, and recovers when it matches.")
PY
