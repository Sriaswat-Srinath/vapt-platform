"""The GLOBAL scanner daemon lease (ADR-0008 R2/R3).

Why global and not per-asset: `newSession` and the sites/message/alert stores are
daemon-global, so a job on one asset would destroy a concurrent job on another.
The mutex is a session-level Postgres advisory lock held on a dedicated
connection for the job's whole lifecycle; the lease ROW makes ownership
observable and survives a crash for forensics.

Fail-safe recovery: the advisory lock dies with its connection but the row does
not. An acquirer that finds a held-looking row whose lock is free treats the
previous teardown as UNPROVEN and marks the daemon dirty — unknown daemon state
is never trusted.
"""
from __future__ import annotations
import datetime as dt
import os
import socket
from typing import Any
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session, sessionmaker
from .. import audit, models
from ..config import settings

LOCK_KEY_SQL = "select pg_try_advisory_lock(hashtext(:key))"
UNLOCK_SQL = "select pg_advisory_unlock(hashtext(:key))"
LEASE_STALE_SECONDS = int(os.environ.get("ZAP_LEASE_STALE_SECONDS", "60"))


class LeaseUnavailable(RuntimeError):
    """Another holder has the daemon, or the daemon is dirty."""


class DaemonDirty(RuntimeError):
    """The daemon is dirty; only an audited admin reset may clear it."""


def daemon_state(session: Session, adapter: str) -> models.ScannerDaemonState:
    row = session.get(models.ScannerDaemonState, adapter)
    if row is None:
        row = models.ScannerDaemonState(adapter_name=adapter, is_dirty=False)
        session.add(row)
        session.flush()
    return row


def mark_dirty(session: Session, adapter: str, reason: str, job_id: Any | None = None,
               requires_operator_restart: bool = False) -> None:
    st = daemon_state(session, adapter)
    st.is_dirty = True
    st.dirty_reason = reason
    st.dirty_since = dt.datetime.now(dt.timezone.utc)
    st.dirty_job_id = job_id
    st.requires_operator_restart = st.requires_operator_restart or requires_operator_restart
    audit.record(session, action="scanner_daemon_marked_dirty", actor_kind="system",
                 actor_id="worker", outcome="error", subject_type="scanner_daemon",
                 subject_id=adapter, detail={"reason": reason, "job_id": str(job_id) if job_id else None})


class ExclusiveDaemonLease:
    """Context manager. Holds its own engine/connection so the advisory lock
    lives exactly as long as the lease."""

    def __init__(self, adapter: str, job_id: Any) -> None:
        self.adapter, self.job_id = adapter, job_id
        self.key = f"vapt:{adapter}:daemon"
        self._engine = create_engine(settings().database_url, poolclass=None, future=True)
        self._conn = None
        self._session: Session | None = None
        self.lease_id: Any | None = None
        self.dirty_on_entry = False

    def __enter__(self) -> "ExclusiveDaemonLease":
        conn = self._engine.connect()
        self._conn = conn
        got = bool(conn.execute(text(LOCK_KEY_SQL), {"key": self.key}).scalar())
        self._session = sessionmaker(bind=self._engine, expire_on_commit=False, future=True)()
        if not got:
            self._cleanup()
            raise LeaseUnavailable(f"the exclusive {self.adapter} daemon lease is held by another job")
        s = self._session
        st = daemon_state(s, self.adapter)
        if st.is_dirty:
            s.commit()
            self._cleanup()
            raise DaemonDirty(f"{self.adapter} daemon is dirty: {st.dirty_reason}")
        # A row that still looks held, while we just took the lock, means the
        # previous holder died without proving teardown.
        stale = s.execute(select(models.ScannerDaemonLease).where(
            models.ScannerDaemonLease.adapter_name == self.adapter,
            models.ScannerDaemonLease.lease_state == "held")).scalars().all()
        for row in stale:
            row.lease_state = "abandoned"
            row.released_at = dt.datetime.now(dt.timezone.utc)
            row.abandoned_reason = "lock was free while the lease looked held: teardown unproven"
            row.daemon_dirty_on_release = True
            mark_dirty(s, self.adapter,
                       "a previous lease was abandoned without a proven teardown", row.job_id)
            self.dirty_on_entry = True
        if self.dirty_on_entry:
            s.commit()
            self._cleanup()
            raise DaemonDirty("a previous lease was abandoned without a proven teardown; "
                              "an audited admin reset is required")
        now = dt.datetime.now(dt.timezone.utc)
        lease = models.ScannerDaemonLease(
            adapter_name=self.adapter, lease_state="held", job_id=self.job_id,
            holder_worker_id=f"{socket.gethostname()}:{os.getpid()}", acquired_at=now,
            heartbeat_at=now, expires_at=now + dt.timedelta(seconds=LEASE_STALE_SECONDS))
        s.add(lease)
        s.flush()
        self.lease_id = lease.id
        audit.record(s, action="scanner_lease_acquired", actor_kind="system", actor_id="worker",
                     outcome="ok", subject_type="scanner_daemon", subject_id=self.adapter,
                     detail={"job_id": str(self.job_id), "lease_id": str(lease.id)})
        s.commit()
        return self

    def heartbeat(self) -> None:
        if self._session is None or self.lease_id is None:
            return
        row = self._session.get(models.ScannerDaemonLease, self.lease_id)
        if row is not None:
            now = dt.datetime.now(dt.timezone.utc)
            row.heartbeat_at = now
            row.expires_at = now + dt.timedelta(seconds=LEASE_STALE_SECONDS)
            self._session.commit()

    def release(self, *, dirty: bool = False, reason: str | None = None) -> None:
        if self._session is not None and self.lease_id is not None:
            row = self._session.get(models.ScannerDaemonLease, self.lease_id)
            if row is not None:
                row.lease_state = "released"
                row.released_at = dt.datetime.now(dt.timezone.utc)
                row.daemon_dirty_on_release = dirty
            if dirty:
                mark_dirty(self._session, self.adapter, reason or "unconfirmed teardown", self.job_id)
            audit.record(self._session, action="scanner_lease_released", actor_kind="system",
                         actor_id="worker", outcome="error" if dirty else "ok",
                         subject_type="scanner_daemon", subject_id=self.adapter,
                         detail={"job_id": str(self.job_id), "dirty": dirty, "reason": reason})
            self._session.commit()

    def _cleanup(self) -> None:
        if self._session is not None:
            self._session.close()
            self._session = None
        if self._conn is not None:
            try:
                self._conn.execute(text(UNLOCK_SQL), {"key": self.key})
                self._conn.commit()
            except Exception:                              # noqa: BLE001
                pass
            self._conn.close()
            self._conn = None
        self._engine.dispose()

    def __exit__(self, exc_type, exc, tb) -> None:
        self._cleanup()
