"""Background sweep that deletes old/excess extracted PCAPs from output_dir.

The legacy system had no retention policy at all — extracted PCAPs would accumulate on disk indefinitely. This module
fills that gap with a periodic sweep, called by the worker's housekeeping thread, that
enforces an age limit and a total-size cap independently. It has no
legacy-compatibility contract to honor since there was nothing before it.
"""

from __future__ import annotations

import logging
import os
import re
import time

from sycope_recorder.config import Settings

log = logging.getLogger("sycope_recorder")

PART = re.compile(r"\.part\d+-\d+\.pcap$")  # npcapextract output still being written (extraction.py)


def _entries(output_dir: str) -> list[tuple[str, float, int]]:
    """List (path, mtime, size) for every .pcap file in output_dir, or empty if it's missing/unreadable."""
    result: list[tuple[str, float, int]] = []
    try:
        names = os.listdir(output_dir)
    except OSError:
        return result
    for name in names:
        if not name.endswith(".pcap") or PART.search(name):
            continue
        path = os.path.join(output_dir, name)
        try:
            st = os.stat(path)
        except OSError:
            continue
        if os.path.isfile(path):
            result.append((path, st.st_mtime, st.st_size))
    return result


def _delete(path: str) -> int:
    """Delete path and return bytes freed; swallow OSError (e.g. already gone via a race) and return 0 instead of raising."""
    try:
        size = os.path.getsize(path)
        os.remove(path)
        return size
    except OSError as exc:
        log.warning("retention: could not delete %s: %s", path, exc)
        return 0


def total_after(entries: list[tuple[str, float, int]], protected: set[str] | frozenset[str]) -> int:
    """Bytes the sweep leaves behind that it may not delete (only meaningful after the passes)."""
    return sum(size for path, _m, size in entries if os.path.basename(path) in protected)


def sweep_once(
    output_dir: str, max_age_seconds: int, max_total_bytes: int, now: float,
    protected: frozenset[str] | set[str] = frozenset(),
) -> dict:
    """Apply the age limit and the total-size cap as two independent passes, in that order.

    First, delete anything older than max_age_seconds (skipped entirely if
    max_age_seconds is 0). Then, among whatever survives that pass, delete
    oldest-first until the remaining total size is under max_total_bytes
    (skipped if max_total_bytes is 0). Running size-based cleanup only
    against the age pass's survivors means a file can be removed for being
    old, for being part of an oversized backlog, or both — never double
    counted. Either limit can be disabled independently by passing 0.

    `protected` holds file names (not paths) of PCAPs that belong to persistent jobs: neither pass
    deletes them. They still count toward the total, since they occupy the disk, so a cap below
    their size cannot be reached; that is logged and left as it is.
    """
    deleted = 0
    reclaimed = 0

    entries = _entries(output_dir)

    if max_age_seconds > 0:
        survivors = []
        for path, mtime, size in entries:
            if now - mtime > max_age_seconds and os.path.basename(path) not in protected:
                freed = _delete(path)
                if freed or not os.path.exists(path):
                    deleted += 1
                    reclaimed += freed
            else:
                survivors.append((path, mtime, size))
        entries = survivors

    if max_total_bytes > 0:
        total = sum(size for _, _, size in entries)
        for path, _mtime, size in sorted(entries, key=lambda e: e[1]):  # oldest first
            if total <= max_total_bytes:
                break
            if os.path.basename(path) in protected:
                continue
            freed = _delete(path)
            if freed or not os.path.exists(path):
                deleted += 1
                reclaimed += freed
                total -= size

    if max_total_bytes > 0 and total_after(entries, protected) > max_total_bytes:
        log.warning("retention: the persistent PCAPs alone exceed the size cap (%d bytes); they are kept",
                    max_total_bytes)
    if deleted:
        log.info("retention: deleted %d file(s), reclaimed %d bytes", deleted, reclaimed)
    return {"deleted": deleted, "bytes": reclaimed}


def sweep(settings: Settings, protected: frozenset[str] | set[str], now: float | None = None) -> dict:
    """One retention pass with the configured limits (both 0 = nothing is ever deleted).

    `protected` is required on purpose: a caller that cannot say which files are persistent must not
    sweep at all.
    """
    return sweep_once(settings.output_dir, settings.retention_max_age_days * 86400,
                      settings.retention_max_total_bytes, time.time() if now is None else now, protected)
