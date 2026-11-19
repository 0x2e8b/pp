"""Counters and liveness as the pages and /stats show them, read from the job database.

Both processes add to the same persistent counters (store.py), so the numbers survive restarts of
either; `since` is when the database was created. Uptimes come from the start times each process
writes into `meta`.
"""

from __future__ import annotations

import time

from sycope_recorder.config import Settings
from sycope_recorder.store import (
    MAIN_SLOT, META_DB_CREATED, META_LAST_SUCCESS, META_LAST_WEBHOOK, META_WEB_STARTED, META_WORKER_STARTED,
    WORKER_BUSY, WORKER_ERROR,
)

OUTCOMES = ("webhook", "queued", "rejected_429", "no_bpf", "disk_low", "db_busy", "success", "miss",
            "failed", "timeout", "window_warning", "cancelled", "interrupted")


def snapshot(store, now: float | None = None) -> dict:
    """Counters, ages of the last webhook/success, and both processes' uptimes."""
    now = time.time() if now is None else now
    outcomes = {k: 0 for k in OUTCOMES}
    outcomes.update(store.counters())
    meta = store.meta()

    def age(key: str) -> int | None:
        """Seconds since the meta timestamp `key`, None when the process never wrote it."""
        return int(now - float(meta[key])) if key in meta else None

    return {
        "since": float(meta[META_DB_CREATED]) if META_DB_CREATED in meta else None,
        "outcomes": outcomes,
        "seconds_since_last_webhook": age(META_LAST_WEBHOOK),
        "seconds_since_last_success": age(META_LAST_SUCCESS),
        "uptime": {"web": age(META_WEB_STARTED), "worker": age(META_WORKER_STARTED)},
        "uptime_seconds": age(META_WEB_STARTED),
    }


def worker_summary(store, settings: Settings, now: float | None = None) -> dict:
    """Is the worker alive and what is it doing (queue banner, /stats, System page)."""
    now = time.time() if now is None else now
    rows = store.workers()
    main = next((r for r in rows if r["slot"] == MAIN_SLOT), None)
    age = None if main is None or main.get("heartbeat") is None else int(now - main["heartbeat"])
    slots = [r for r in rows if r["slot"] != MAIN_SLOT]
    return {
        "state": main["state"] if main else "never started",
        "paused": store.paused(),
        "heartbeat_age": age,
        "alive": age is not None and age <= settings.worker_stale_seconds and (main or {}).get("state") != WORKER_ERROR,
        "slots_busy": sum(1 for r in slots if r["state"] == WORKER_BUSY),
        "slots": len(slots),
    }
