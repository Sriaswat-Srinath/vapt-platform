"""Celery application. The worker is dual-homed vapt_core + vapt_lab and holds
no LLM credentials and no proxy variables (docs/NETWORK_ARCHITECTURE.md §3)."""
from __future__ import annotations
from celery import Celery
from ..config import settings


def _broker_url() -> str:
    s = settings()
    if s.redis_password and "@" not in s.redis_url:
        scheme, rest = s.redis_url.split("://", 1)
        return f"{scheme}://:{s.redis_password}@{rest}"
    return s.redis_url


celery = Celery("vapt", broker=_broker_url(), backend=None)
celery.conf.update(
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,            # one long job at a time
    task_track_started=True,
    task_time_limit=3600,
    task_soft_time_limit=3300,
    broker_connection_retry_on_startup=True,
    task_default_queue="vapt",
    imports=("app.worker.tasks",),
)
