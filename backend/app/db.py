"""Engine and session management."""
from __future__ import annotations
from collections.abc import Iterator
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from .config import settings

_engine = None
_factory = None


def engine():
    global _engine
    if _engine is None:
        _engine = create_engine(settings().database_url, pool_pre_ping=True, future=True)
    return _engine


def session_factory():
    global _factory
    if _factory is None:
        _factory = sessionmaker(bind=engine(), expire_on_commit=False, future=True)
    return _factory


def get_session() -> Iterator[Session]:
    s = session_factory()()
    try:
        yield s
    finally:
        s.close()
