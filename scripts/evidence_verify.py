#!/usr/bin/env python3
"""Verify every stored evidence blob is readable and intact.

Run this after enabling encryption, after a key change, or before trusting a
backup. It reads each blob through the same path the platform uses, so a blob
that this script can read is a blob the platform can read.

Reports four states and exits non-zero if any blob is unreadable:
  ok          decrypted (or read) and the digest matches
  plaintext   readable, stored unencrypted
  MISSING     the row says present and the file is not there
  UNREADABLE  wrong key, altered file, or a failed integrity check
"""
from __future__ import annotations
import json
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]

SCRIPT = '''
import json
from sqlalchemy import select
from app import models
from app.db import session_factory
from app.evidence import store, crypto

session = session_factory()()
rows = session.execute(select(models.EvidenceBlob).where(
    models.EvidenceBlob.state == "present")).scalars().all()
out = {"total": len(rows), "ok": 0, "plaintext": 0, "missing": 0, "unreadable": [],
       "encryption_enabled": crypto.enabled(), "key_available": crypto.available()}
for blob in rows:
    try:
        data = store.read(blob)
    except FileNotFoundError:
        out["missing"] += 1
        continue
    except Exception as exc:
        out["unreadable"].append({"sha256": blob.content_sha256[:16],
                                  "error": f"{type(exc).__name__}: {exc}"[:160]})
        continue
    if blob.encryption == "none":
        out["plaintext"] += 1
    else:
        out["ok"] += 1
    del data
print(json.dumps(out, indent=2))
'''


def main() -> int:
    env = dict(line.split("=", 1) for line in (REPO / ".env").read_text().splitlines()
               if "=" in line and not line.strip().startswith("#"))
    cmd = [
        "docker", "run", "--rm", "--network", "vapt_core",
        "-v", "vapt_evidence:/var/lib/vapt/evidence", "--user", "65532:65532",
        "-e", (f"DATABASE_URL=postgresql+psycopg://{env['POSTGRES_USER']}:"
               f"{env['POSTGRES_PASSWORD']}@172.30.21.40:5432/{env['POSTGRES_DB']}"),
        "-e", f"SECRET_KEY={env['SECRET_KEY']}",
        "-e", f"REDACTION_HMAC_KEY={env['REDACTION_HMAC_KEY']}",
        "-e", f"EVIDENCE_ENCRYPTION_KEY={env.get('EVIDENCE_ENCRYPTION_KEY', '')}",
        "-e", f"EVIDENCE_ENCRYPTION_ENABLED={env.get('EVIDENCE_ENCRYPTION_ENABLED', 'false')}",
        "-e", "EVIDENCE_BLOB_ROOT=/var/lib/vapt/evidence",
        "vapt-api:dev", "python", "-c", SCRIPT,
    ]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if out.returncode != 0:
        print(out.stderr[-1500:], file=sys.stderr)
        return 2
    print(out.stdout)
    try:
        report = json.loads(out.stdout[out.stdout.index("{"):])
    except ValueError:
        return 2
    return 1 if (report["unreadable"] or report["missing"]) else 0


if __name__ == "__main__":
    sys.exit(main())
