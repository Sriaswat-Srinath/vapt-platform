#!/usr/bin/env python3
"""Create and remove SYNTHETIC evidence blobs for retention testing.

Runs inside the api container (it needs the app's session and the evidence
volume). Everything it creates is marked with a fixed prefix so cleanup can
never touch a real blob, and it refuses to operate on anything it did not
create.

Scenarios:
  orphan      a blob with no reference of any kind -> a purge candidate
  dangling    a blob row marked present whose FILE is missing -> must halt
  orphan-ref  an evidence row pointing at a blob id that does not exist -> halt
  cleanup     remove everything this script created
"""
from __future__ import annotations
import sys
import uuid

from sqlalchemy import select

from app import models
from app.db import session_factory
from app.evidence import store

MARK = b"SYNTHETIC-RETENTION-FIXTURE-"


def _mine(session):
    rows = session.execute(select(models.EvidenceBlob).where(
        models.EvidenceBlob.media_type == "application/x-vapt-retention-fixture")).scalars().all()
    return rows


def orphan(session, n: int = 2) -> list[str]:
    out = []
    for i in range(n):
        blob = store.put(session, MARK + uuid.uuid4().hex.encode(),
                         media_type="application/x-vapt-retention-fixture")
        out.append(blob.content_sha256)
    session.commit()
    return out


def dangling(session) -> str:
    blob = store.put(session, MARK + b"dangling-" + uuid.uuid4().hex.encode(),
                     media_type="application/x-vapt-retention-fixture")
    session.commit()
    import pathlib
    pathlib.Path(blob.storage_path).unlink()        # the induced inconsistency
    return blob.content_sha256


def orphan_ref(session) -> str:
    """Attempt an evidence row whose blob id has no row.

    The database REFUSES this: a trigger (vapt_blob_reference_guard, phase 5)
    rejects a reference to a blob that is absent or not present. So the
    expected result of this scenario is `refused-by-database`, which is a
    stronger guarantee than the runtime check in app/retention.py — that check
    stays as defence in depth against a future schema change.
    """
    finding = session.execute(select(models.Finding).limit(1)).scalar_one_or_none()
    if finding is None:
        raise SystemExit("no finding exists to attach a synthetic evidence row to")
    ev = models.Evidence(
        finding_id=finding.id, kind="http_response", label="SYNTHETIC-RETENTION-FIXTURE",
        content_redacted="synthetic", blob_id=uuid.uuid4(), redaction_version="1.1.0",
        redaction_report={"counts": {}})
    session.add(ev)
    try:
        session.commit()
    except Exception as exc:                            # noqa: BLE001
        session.rollback()
        return f"refused-by-database: {type(exc).__name__}"
    return str(ev.id)


def cleanup(session) -> dict[str, int]:
    removed_ev = session.execute(models.Evidence.__table__.delete().where(
        models.Evidence.label == "SYNTHETIC-RETENTION-FIXTURE")).rowcount
    blobs = _mine(session)
    import pathlib
    for b in blobs:
        try:
            pathlib.Path(b.storage_path).unlink()
        except FileNotFoundError:
            pass
        session.delete(b)
    session.commit()
    return {"evidence_rows": int(removed_ev or 0), "blobs": len(blobs)}


def main() -> int:
    action = sys.argv[1] if len(sys.argv) > 1 else "status"
    session = session_factory()()
    try:
        if action == "orphan":
            print(len(orphan(session, int(sys.argv[2]) if len(sys.argv) > 2 else 2)))
        elif action == "dangling":
            print(dangling(session))
        elif action == "orphan-ref":
            print(orphan_ref(session))
        elif action == "cleanup":
            print(cleanup(session))
        else:
            print({"synthetic_blobs": len(_mine(session))})
    finally:
        session.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
