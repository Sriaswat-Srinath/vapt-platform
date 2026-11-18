"""Evidence retention: a scheduled, reference-aware, HALTING purge.

What it deletes: the unredacted ORIGINAL bytes in the content-addressed blob
store, once nothing active references them and they are older than the
retention window. What it never deletes: findings, raw observations, evidence
rows, provenance digests or the audit log. A purged blob leaves its reference
behind marked `blob_purged_at`, so a reader is told the bytes are gone rather
than being shown a gap (ADR-0011).

Invariant I12 — two properties, both enforced here rather than hoped for:

  idempotent   running again over the same data purges nothing more. The
               candidate query only selects blobs that are `present`, unexpired
               and unreferenced, so a completed run leaves no work behind, and
               a half-finished run resumes from facts rather than from a cursor.

  halts        every candidate is verified BEFORE any of them is deleted, so a
               disagreement between the store and the database means the batch
               deletes nothing at all — not "some, then stopped". A surprise
               during deletion (a reference appearing, an unlink failing) halts
               immediately as well. A purge that keeps going through an
               inconsistency is how a reference outlives its bytes, which is
               the one outcome worse than keeping data too long.

Halt reasons are enumerated below. Each is a disagreement between what the
database claims and what the filesystem shows; none of them is recoverable by
guessing, so none of them is guessed at.
"""
from __future__ import annotations
import dataclasses as dc
import datetime as dt
import pathlib
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import models
from .config import settings
from .evidence import store

from .retention_rules import (HALT_BLOB_FILE_MISSING, HALT_BLOB_INTEGRITY,  # noqa: F401
                              HALT_DELETE_FAILED, HALT_ORPHAN_REFERENCE,
                              HALT_REFERENCE_APPEARED, PURGE_ELIGIBILITY, PURGE_SCOPE,
                              RETENTION_VERSION)


class PurgeHalted(RuntimeError):
    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


@dc.dataclass(slots=True)
class PurgeOutcome:
    state: str = "completed"          # completed | halted
    dry_run: bool = True
    scanned: int = 0
    eligible: int = 0
    purged: int = 0
    skipped_referenced: int = 0
    skipped_within_window: int = 0
    bytes_reclaimed: int = 0
    window_days: int = 0
    halt_reason: str | None = None
    halt_detail: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return dc.asdict(self)


def policy() -> dict[str, Any]:
    s = settings()
    return {
        "retention_enabled": s.retention_enabled,
        "evidence_blob_days": s.retention_evidence_blob_days,
        "batch_limit": s.retention_batch_limit,
        "retention_version": RETENTION_VERSION,
        "scope": PURGE_SCOPE,
        "note": PURGE_ELIGIBILITY,
    }


def _cutoff(now: dt.datetime, days: int | None = None) -> dt.datetime:
    window = settings().retention_evidence_blob_days if days is None else days
    return now - dt.timedelta(days=window)


def candidates(session: Session, *, now: dt.datetime, limit: int,
               days: int | None = None) -> list[models.EvidenceBlob]:
    """Blobs whose bytes may go. Pure query: the same inputs select the same rows.

    Selection is by FACTS about current state, never by a cursor or a flag set
    by an earlier run — which is what makes a repeat run a no-op rather than a
    second attempt at the same list.
    """
    cutoff = _cutoff(now, days)
    # Raw observations reference blobs too (see store.active_reference_count):
    # a blob any observation points at is never a candidate, whatever its age.
    # Every OTHER thing that points at a blob. A blob any of these reference is
    # never a candidate, whatever its age: report artifacts live in the same
    # store, and a report an analyst can still open is a live reference.
    observed = select(models.RawObservation.request_blob_id).where(
        models.RawObservation.request_blob_id.is_not(None)).union(
        select(models.RawObservation.response_blob_id).where(
            models.RawObservation.response_blob_id.is_not(None)),
        select(models.ReportArtifact.artifact_blob_id).where(
            models.ReportArtifact.artifact_blob_id.is_not(None))).subquery()
    newest_ref = (
        select(models.Evidence.blob_id,
               func.max(models.Evidence.collected_at).label("newest"),
               func.count().filter(models.Evidence.blob_purged_at.is_(None)).label("active"))
        .where(models.Evidence.blob_id.is_not(None))
        .group_by(models.Evidence.blob_id)
        .subquery())
    stmt = (select(models.EvidenceBlob)
            .outerjoin(newest_ref, newest_ref.c.blob_id == models.EvidenceBlob.id)
            .where(models.EvidenceBlob.state == "present",
                   models.EvidenceBlob.created_at < cutoff,
                   # Either nothing references it, or everything that does is
                   # itself older than the window.
                   ((newest_ref.c.newest.is_(None)) | (newest_ref.c.newest < cutoff)),
                   models.EvidenceBlob.id.not_in(select(observed.c[0])))
            .order_by(models.EvidenceBlob.created_at)
            .limit(limit))
    return list(session.execute(stmt).scalars().all())


def _verify_consistent(session: Session, blob: models.EvidenceBlob) -> None:
    """Every way the database and the store can disagree, checked before delete."""
    path = pathlib.Path(blob.storage_path or "")
    if not path.exists():
        raise PurgeHalted(
            HALT_BLOB_FILE_MISSING,
            f"blob {blob.content_sha256[:12]} is marked present but {path} does not exist. "
            "The database and the store disagree; purging further would compound it.")
    try:
        store.read(blob)
    except ValueError as exc:
        raise PurgeHalted(HALT_BLOB_INTEGRITY, str(exc)) from exc
    except FileNotFoundError as exc:
        raise PurgeHalted(HALT_BLOB_FILE_MISSING, str(exc)) from exc


def _orphan_reference(session: Session) -> tuple[str, str] | None:
    """An evidence row pointing at a blob id that no longer exists.

    The database already refuses to create one (trigger
    vapt_blob_reference_guard, phase 5). This is defence in depth for a future
    schema change, and it costs one indexed query per run.
    """
    row = session.execute(
        select(models.Evidence.id, models.Evidence.blob_id)
        .outerjoin(models.EvidenceBlob, models.EvidenceBlob.id == models.Evidence.blob_id)
        .where(models.Evidence.blob_id.is_not(None),
               models.Evidence.blob_purged_at.is_(None),
               models.EvidenceBlob.id.is_(None))
        .limit(1)).first()
    if row is None:
        return None
    return str(row[0]), str(row[1])


def run(session: Session, *, dry_run: bool = True, limit: int | None = None,
        now: dt.datetime | None = None, days: int | None = None) -> PurgeOutcome:
    """Execute one purge pass. Never raises: a halt is a recorded outcome."""
    s = settings()
    now = now or dt.datetime.now(dt.timezone.utc)
    limit = limit or s.retention_batch_limit
    out = PurgeOutcome(dry_run=dry_run)

    orphan = _orphan_reference(session)
    if orphan is not None:
        out.state = "halted"
        out.halt_reason = HALT_ORPHAN_REFERENCE
        out.halt_detail = (f"evidence {orphan[0]} references blob {orphan[1]}, which has no row. "
                           "Nothing was purged.")
        return out

    out.window_days = settings().retention_evidence_blob_days if days is None else days
    rows = candidates(session, now=now, limit=limit, days=days)
    out.scanned = len(rows)

    # PHASE 1 — verify every candidate before deleting ANY of them.
    # Checking as we go would leave a run that deleted some blobs and then
    # halted, which is harder to reason about and harder to resume. If the
    # store and the database disagree anywhere in this batch, nothing goes.
    eligible: list[models.EvidenceBlob] = []
    for blob in rows:
        if store.active_reference_count(session, blob.id) > 0:
            out.skipped_referenced += 1
            continue
        try:
            _verify_consistent(session, blob)
        except PurgeHalted as halt:
            out.state = "halted"
            out.halt_reason = halt.reason
            out.halt_detail = halt.detail
            out.eligible = len(eligible)
            return out
        eligible.append(blob)
    out.eligible = len(eligible)

    if dry_run:
        return out

    # PHASE 2 — delete. Any surprise here still halts immediately.
    for blob in eligible:
        size = int(blob.byte_size or 0)
        try:
            result = store.delete_if_unreferenced(session, blob.id)
        except store.BlobStillReferenced:
            # A reference appeared between the count and the delete. Not an
            # error in itself, but it means the run's view is stale: stop.
            out.state = "halted"
            out.halt_reason = HALT_REFERENCE_APPEARED
            out.halt_detail = (f"blob {blob.content_sha256[:12]} gained a reference during the "
                               "run; stopping rather than racing it.")
            return out
        except Exception as exc:                        # noqa: BLE001 - halt, never continue
            out.state = "halted"
            out.halt_reason = HALT_DELETE_FAILED
            out.halt_detail = f"{type(exc).__name__}: {exc}"
            return out
        if result == "purged":
            out.purged += 1
            out.bytes_reclaimed += size
    return out


def record(session: Session, outcome: PurgeOutcome, *, triggered_by: str | None,
           started_at: dt.datetime) -> models.PurgeRun:
    row = models.PurgeRun(
        state=outcome.state, dry_run=outcome.dry_run,
        retention_version=RETENTION_VERSION,
        # The EFFECTIVE window for this run, which an operator override changes.
        evidence_blob_days=outcome.window_days or settings().retention_evidence_blob_days,
        scanned=outcome.scanned, eligible=outcome.eligible, purged=outcome.purged,
        skipped_referenced=outcome.skipped_referenced,
        bytes_reclaimed=outcome.bytes_reclaimed,
        halt_reason=outcome.halt_reason, halt_detail=outcome.halt_detail,
        triggered_by=triggered_by, started_at=started_at,
        finished_at=dt.datetime.now(dt.timezone.utc))
    session.add(row)
    session.flush()
    return row
