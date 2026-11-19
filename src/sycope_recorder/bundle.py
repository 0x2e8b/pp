"""Debug bundle: one zip with what the api container itself can see, for support.

Scope is deliberate: the recent logs of both processes (the worker's includes every npcapextract
failure with its stdout/stderr), the job table with each job's history, the self-checks, the settings and
SR_* environment with secrets redacted, free disk, and the newest/oldest rolling files by name.
Nothing from the host (n2disk journal) and no PCAP content.
"""

from __future__ import annotations

import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import zipfile

from sycope_recorder import checks as checks_mod
from sycope_recorder import stats as stats_mod
from sycope_recorder.config import Settings
from sycope_recorder.jobs import JobStore
from sycope_recorder.logging_config import log_tail
from sycope_recorder.store import META_NPCAPEXTRACT_INFO

_SECRET_KEY = re.compile(r"pass|secret|token|key|auth|cred", re.I)
_URL_CRED = re.compile(r"(://)[^/\s:@]+:[^/\s@]+@")
_AUTH_HDR = re.compile(r"(authorization\s*[:=]\s*)(basic|bearer)?\s*\S+", re.I)
_ASSIGN = re.compile(r"((?:pass(?:word)?|secret|token|api[_-]?key)\s*[=:]\s*)\S+", re.I)
MAX_JOBS = 1000


def redact(text: str) -> str:
    """Remove credentials from free text (log lines, details)."""
    text = _URL_CRED.sub(r"\1***:***@", text)
    text = _AUTH_HDR.sub(r"\1***", text)
    return _ASSIGN.sub(r"\1***", text)


def redact_map(values: dict) -> dict:
    return {k: ("***" if _SECRET_KEY.search(str(k)) else v) for k, v in values.items()}


def _disk(path: str) -> dict:
    try:
        u = shutil.disk_usage(path)
        return {"path": path, "total": u.total, "used": u.used, "free": u.free}
    except OSError as exc:
        return {"path": path, "error": str(exc)}


def _rolling(store: JobStore) -> dict:
    """File count and how far back the rolling capture reaches, as the worker reported it (the web
    cannot list n2disk's directories; see system.rolling_info)."""
    from sycope_recorder.system import rolling_info

    info = rolling_info(store)
    return {"reported_by_worker": info["reported"], "stale": info["stale"],
            "reported_seconds_ago": info["reported_age_seconds"],
            "files": info["files"], "retention_minutes": info["retention_minutes"],
            "newest_file_started_seconds_ago": info["newest_age_seconds"]}


def npcapextract_info(settings: Settings) -> str:
    """`npcapextract -h` output for support; recorded by the worker at start because the web does not run npcapextract."""
    path = shutil.which(settings.npcapextract_path)
    if not path:
        return f"{settings.npcapextract_path}: not found on PATH"
    try:
        p = subprocess.run([path, "-h"], capture_output=True, text=True, timeout=10)
        return f"{path}\n{(p.stdout or '') + (p.stderr or '')}"
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"{path}: {exc}"


def build(settings: Settings, store: JobStore) -> bytes:
    """The zip as bytes (kept small: the log tails and at most MAX_JOBS jobs)."""
    now = time.time()
    snap = stats_mod.snapshot(store, now)
    files: dict[str, str] = {}

    from sycope_recorder import __version__

    info = {"version": __version__, "generated_utc": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(now)),
            "python": sys.version, "platform": platform.platform(),
            "tz": os.environ.get("TZ", ""), "uptime_seconds": snap["uptime"]}
    files["info.json"] = json.dumps(info, indent=1)
    files["settings.json"] = json.dumps(redact_map(dict(settings)), indent=1, default=str)
    files["environment.json"] = json.dumps(
        redact_map({k: v for k, v in os.environ.items() if k.startswith("SR_")}), indent=1)
    files["stats.json"] = json.dumps(snap, indent=1, default=str)
    files["disk.json"] = json.dumps([_disk(settings.output_dir), _disk(settings.timeline_dir),
                                     _disk(settings.state_dir)], indent=1)
    files["rolling.json"] = json.dumps(_rolling(store), indent=1)
    files["npcapextract.txt"] = redact(store.get_meta(META_NPCAPEXTRACT_INFO) or "not reported by the worker yet")
    checks = checks_mod.stored_checks(store, settings, now)
    files["checks.json"] = json.dumps(
        [{"name": c.name, "status": c.status, "detail": redact(c.detail)} for c in checks], indent=1)
    files["web.log"] = redact(log_tail(settings, "web")) + "\n"
    files["worker.log"] = redact(log_tail(settings, "worker")) + "\n"
    files["workers.json"] = json.dumps(store.workers(), indent=1, default=str)
    files["control.json"] = json.dumps(store.control(), indent=1, default=str)
    files["counters.json"] = json.dumps(store.counters(), indent=1)

    jobs = store.list_jobs(limit=MAX_JOBS, offset=0, state=None)
    events = store.events_many([j["id"] for j in jobs])
    files["queue_counts.json"] = json.dumps(store.counts(), indent=1)
    files["jobs.json"] = redact(json.dumps(
        [{**j, "events": events.get(j["id"], [])} for j in jobs], indent=1, default=str))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, text in files.items():
            zf.writestr(name, text)
    return buf.getvalue()
