"""Content-addressed blob store for unredacted evidence originals.

Writes are atomic (temp file + fsync + rename), mode 0600, under
EVIDENCE_BLOB_ROOT. Deletion is reference-aware: a blob is never unlinked while
any active evidence row references it (ADR-0011 R2 §7 / invariant I7).

Blobs may be ENCRYPTED at rest (evidence/crypto.py). Content addressing is
unchanged by that: `content_sha256` is always the digest of the PLAINTEXT, so
deduplication, provenance and every stored reference keep working, and a store
containing both encrypted and plaintext blobs stays readable because each file
says which it is.
"""
from __future__ import annotations
import hashlib
import os
import pathlib
import tempfile
from typing import Any
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from .. import models
from . import crypto


def root() -> pathlib.Path:
    return pathlib.Path(os.environ.get("EVIDENCE_BLOB_ROOT", "/var/lib/vapt/evidence"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def path_for(digest: str) -> pathlib.Path:
    return root() / digest[:2] / digest


def put(session: Session, data: bytes, media_type: str | None = None) -> models.EvidenceBlob:
    """Store (or reuse) a blob. Content addressing deduplicates identical bodies."""
    digest = sha256_bytes(data)                 # ALWAYS the plaintext digest
    existing = session.execute(select(models.EvidenceBlob).where(
        models.EvidenceBlob.content_sha256 == digest)).scalar_one_or_none()
    target = path_for(digest)
    if existing is not None and existing.state == "present" and target.exists():
        return existing

    # Encrypt before anything touches the filesystem. If encryption was asked
    # for and cannot be done, FAIL — never quietly write plaintext that the
    # operator believes is encrypted.
    encryption = crypto.PLAINTEXT
    on_disk = data
    if crypto.enabled():
        on_disk = crypto.encrypt(data)
        encryption = crypto.ALGORITHM

    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=".blob.")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(on_disk)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, target)
        dirfd = os.open(str(target.parent), os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    except BaseException:
        with contextlib_suppress():
            os.unlink(tmp)
        raise
    if existing is not None:
        existing.state = "present"
        existing.storage_path = str(target)
        existing.purged_at = None
        existing.encryption = encryption
        return existing
    # byte_size is the PLAINTEXT size: it is what a reader gets back, and what
    # retention accounting should reason about.
    row = models.EvidenceBlob(content_sha256=digest, byte_size=len(data),
                              media_type=media_type, storage_path=str(target),
                              state="present", encryption=encryption)
    session.add(row)
    session.flush()
    return row


def read(blob: models.EvidenceBlob) -> bytes:
    """Returns the PLAINTEXT, whatever is on disk.

    The integrity check runs on the decrypted bytes, so it still means what it
    always meant: these are the bytes that were stored. AES-GCM would already
    have rejected a tampered ciphertext; this catches the other case, a
    plaintext blob altered in place.
    """
    p = pathlib.Path(blob.storage_path)
    if not p.exists():
        raise FileNotFoundError(f"blob {blob.content_sha256} is missing from {p}")
    raw = p.read_bytes()
    data = crypto.decrypt(raw)
    if sha256_bytes(data) != blob.content_sha256:
        raise ValueError(f"blob {blob.content_sha256} failed its integrity check")
    return data


def active_reference_count(session: Session, blob_id: Any) -> int:
    """Computed by query, never cached (ADR-0011 R2 §7).

    Counts THREE kinds of reference, because all three break if the bytes go:
      * evidence rows that have not already been marked purged,
      * report pins that explicitly pin the blob,
      * raw observations whose request/response bytes these are. Revalidation
        re-reads those bytes, so purging them would silently change a future
        verdict from different inputs. Provenance is a reference, not a hash.
      * report artifacts stored in the same blob store. A generated report that
        an analyst can still open is a live reference to its bytes.
    """
    refs = int(session.execute(select(func.count()).select_from(models.Evidence).where(
        models.Evidence.blob_id == blob_id,
        models.Evidence.blob_purged_at.is_(None))).scalar_one())
    observations = int(session.execute(
        select(func.count()).select_from(models.RawObservation).where(
            (models.RawObservation.request_blob_id == blob_id) |
            (models.RawObservation.response_blob_id == blob_id))).scalar_one())
    pins = int(session.execute(
        select(func.count()).select_from(models.EvidencePin)
        .join(models.Evidence, models.Evidence.id == models.EvidencePin.evidence_id)
        .where(models.Evidence.blob_id == blob_id,
               models.EvidencePin.pins_blob.is_(True),
               models.EvidencePin.released_at.is_(None))).scalar_one())
    artifacts = int(session.execute(
        select(func.count()).select_from(models.ReportArtifact).where(
            models.ReportArtifact.artifact_blob_id == blob_id)).scalar_one())
    return refs + pins + observations + artifacts


class BlobStillReferenced(RuntimeError):
    """Refusal to delete a blob that an active evidence reference needs."""


def delete_if_unreferenced(session: Session, blob_id: Any) -> str:
    """Reference-aware deletion. Returns the outcome.

    Ordering is deliberate (ADR-0011 R3 §12.3): intent is committed, the file is
    unlinked and verified absent, and only then is the row updated — so the only
    reachable inconsistency is "bytes gone, row stale", which is repairable. The
    reverse would leave a secret on disk while the database claimed it was gone.
    """
    blob = session.get(models.EvidenceBlob, blob_id, with_for_update=True)
    if blob is None:
        return "missing_row"
    count = active_reference_count(session, blob_id)
    if count > 0:
        raise BlobStillReferenced(
            f"blob {blob.content_sha256[:12]} still has {count} active reference(s)")
    blob.state = "pending_delete"
    session.commit()                                   # intent committed first
    target = pathlib.Path(blob.storage_path)
    try:
        target.unlink()
    except FileNotFoundError:
        pass                                           # idempotent
    if target.exists():
        raise RuntimeError(f"blob file {target} still present after unlink")
    try:
        dirfd = os.open(str(target.parent), os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    except OSError:
        pass
    if active_reference_count(session, blob_id) != 0:
        raise RuntimeError("a reference appeared during deletion")
    blob.state = "purged"
    blob.purged_at = func.now()
    session.execute(models.Evidence.__table__.update().where(
        models.Evidence.blob_id == blob_id).values(blob_purged_at=func.now()))
    session.commit()
    return "purged"


class contextlib_suppress:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc) -> bool:
        return True
