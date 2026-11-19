"""What the System page shows: the state of the recorder as the api container sees it.

Gathered in one place so the HTML page and the JSON variant (`/system`, `Accept: application/json`)
say the same. Host-only facts (n2disk process, journal) are not visible from the container; the
rolling capture stands in for them. The web user cannot list n2disk's directories, so the rolling
figures are the summary the worker stored (`rolling_info`), shown with its age.
"""

from __future__ import annotations

import json
import os
import shutil
import time

from sycope_recorder import checks as checks_mod
from sycope_recorder import config_store
from sycope_recorder import stats as stats_mod
from sycope_recorder.bundle import redact_map
from sycope_recorder.config import Settings
from sycope_recorder.jobs import JobStore
from sycope_recorder.alert import parse_alert
from sycope_recorder.profiles import ProfileBook, profile_bpf, range_seconds

ROLLING_META = "rolling_info"  # written by the worker (housekeeping), read here
ROLLING_MIN_INTERVAL = 300

# check name -> module column, like Sycope's Functions table
MODULE = {"rolling_fresh": "Capture", "timezone": "Capture", "npcapextract": "Extraction",
          "output_dir": "Storage", "alerts_visible_to_caddy": "Storage", "state_dir": "Storage",
          "profiles": "Profiles", "worker": "Extraction", "state_dir_local": "Storage", "checks": "Other"}


def profile_store_active(settings: Settings) -> str:
    from sycope_recorder.profile_store import active_path

    return active_path(settings)[0]


def version() -> str:
    """The release label (the release label), as the pages and /stats show it."""
    from sycope_recorder import __version__

    return __version__


def rolling_interval(settings: Settings) -> float:
    """Seconds between the worker's rolling summaries: a new file appears once per chunk, and a scan of
    a large buffer is expensive, so never more often than every five minutes."""
    return float(max(settings.chunk_seconds, ROLLING_MIN_INTERVAL))


def rolling_info(store: JobStore, now: float | None = None) -> dict:
    """The rolling capture as the worker last reported it (meta `rolling_info`), aged to `now`.

    The web never lists the rolling tree (n2disk's directories are not readable for its user). Before
    the first report `reported` is False and every figure is None: callers say "not reported yet", not
    "no files". `bytes` is None: sizing needs a stat() per file.
    """
    now = time.time() if now is None else now
    out: dict[str, bool | int | None] = {"reported": False, "stale": False, "reported_age_seconds": None, "files": None, "bytes": None,
           "retention_minutes": None, "newest_age_seconds": None}
    try:
        raw = json.loads(store.get_meta(ROLLING_META) or "")
        ts = float(raw["ts"])
    except (ValueError, KeyError, TypeError):
        return out
    age = max(0, int(now - ts))
    interval = raw.get("interval")
    interval = float(interval) if isinstance(interval, (int, float)) and interval > 0 else ROLLING_MIN_INTERVAL
    # like stored_checks: a report that is three intervals old is not the current state of the buffer
    out.update(reported=True, reported_age_seconds=age, stale=age > 3 * interval, files=raw.get("files"))
    if isinstance(raw.get("newest_start"), (int, float)):
        out["newest_age_seconds"] = max(0, int(now - raw["newest_start"]))
    if isinstance(raw.get("oldest_start"), (int, float)):
        out["retention_minutes"] = max(0, int((now - raw["oldest_start"]) / 60))
    return out


def alerts_info(path: str) -> dict:
    n = size = 0
    try:
        with os.scandir(path) as it:
            for e in it:
                if e.is_file() and e.name.endswith(".pcap"):
                    n += 1
                    size += e.stat().st_size
    except OSError:
        pass
    return {"files": n, "bytes": size}


def disks(settings: Settings) -> list[dict]:
    """Usage of the filesystems the recorder depends on, one row per filesystem (volumes on the same
    device are listed together). statvfs works on n2disk's rolling mount without listing it."""
    out: list[dict] = []
    seen: dict[int, dict] = {}
    for label, path in (("Rolling buffer (n2disk)", settings.timeline_dir), ("Alert PCAPs", settings.output_dir),
                        ("Recorder state", settings.state_dir)):
        try:
            dev = os.stat(path).st_dev
            du = shutil.disk_usage(path)
        except OSError:
            out.append({"names": [label], "paths": [path], "total": None, "used": None, "free": None, "pct": None})
            continue
        if dev in seen:
            seen[dev]["names"].append(label)
            seen[dev]["paths"].append(path)
            continue
        row = {"names": [label], "paths": [path], "total": du.total, "used": du.used, "free": du.free,
               "pct": round(du.used * 100 / du.total) if du.total else None}
        seen[dev] = row
        out.append(row)
    return out


def host_info() -> dict:
    """CPU, memory and load as the container sees them (the host's /proc), for the System page."""
    info: dict = {"cpus": os.cpu_count(), "cpu_model": None, "mem_total": None, "mem_used": None, "load1": None}
    try:
        with open("/proc/cpuinfo", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("model name"):
                    info["cpu_model"] = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    try:
        mem = {}
        with open("/proc/meminfo", encoding="utf-8", errors="replace") as f:
            for line in f:
                k, _, v = line.partition(":")
                if k in ("MemTotal", "MemAvailable"):
                    mem[k] = int(v.split()[0]) * 1024
        if "MemTotal" in mem:
            info["mem_total"] = mem["MemTotal"]
            if "MemAvailable" in mem:
                info["mem_used"] = mem["MemTotal"] - mem["MemAvailable"]
    except (OSError, ValueError):
        pass
    try:
        info["load1"] = os.getloadavg()[0]
    except OSError:
        pass
    return info


# A synthetic alert for the example filter: values that cannot be confused with a static port or a real host,
# replaced by placeholders afterwards.
_EXAMPLE = {"id": "example", "clientIp": "192.0.2.1", "serverIp": "192.0.2.2", "serverPort": 65001,
            "protocol": "tcp", "unixTimestamp": 1782050580}


def example_filter(p: dict) -> str | None:
    """The BPF filter this profile builds for an alert, with <client>/<server>/<port>/<protocol> in place of the
    alert's values; None when it builds none (NO BPF FILTER)."""
    try:
        bpf = profile_bpf(p, parse_alert(dict(_EXAMPLE)))
    except Exception:  # an invalid profile cannot be loaded anyway; show it as no filter
        return None
    if not bpf:
        return None
    if "protocol" in {d.get("field") for d in p.get("packet_dims", [])} and bpf.startswith("tcp and "):
        bpf = "<protocol> and " + bpf[len("tcp and "):]
    return (bpf.replace("host 192.0.2.1", "host <client>").replace("host 192.0.2.2", "host <server>")
            .replace("port 65001", "port <port>"))


def profile_rows(book: ProfileBook, settings: Settings | None = None) -> list[dict]:
    """One row per profile for the Profiles page; with `settings`, also the extraction window it gives
    (seconds before and after the alert time)."""
    lag = settings.exporter_lag_seconds if settings else 0
    margin = settings.window_margin_seconds if settings else 0
    rows = []
    for p in sorted(book.profiles, key=lambda p: str(p.get("name", "")).lower()):
        rows.append({
            "name": p.get("name"), "def_id": p.get("def_id"), "active": p.get("active", True),
            "shape": p.get("shape"), "range_s": p.get("time_range_s"), "interval_s": p.get("interval_s"),
            "keys": [d.get("alias") for d in p.get("packet_dims", [])],
            "static": p.get("static", {}), "alert_key": p.get("alert_key", []),
            "macros": p.get("macros", []), "unfilterable": p.get("unfilterable", []),
            "notes": p.get("notes", []), "throttling_min": p.get("throttling_min"), "filter": example_filter(p),
            "before_s": (rng + lag) if (rng := range_seconds(p)) is not None else None,
            "after_s": margin})
    return rows


def gather(settings: Settings, store: JobStore, book: ProfileBook) -> dict:
    """Everything the System page and its JSON show, read from the database and the filesystem.

    The web does not run the checks or count anything itself: results, counters and the worker's
    state are what the worker and the webhook stored, so this view survives a web reload and shows
    a dead worker as such.
    """
    results = checks_mod.stored_checks(store, settings)
    snap = stats_mod.snapshot(store)
    worker = stats_mod.worker_summary(store, settings)
    rolling = rolling_info(store)
    alerts = alerts_info(settings.output_dir)
    free = shutil.disk_usage(settings.output_dir).free if os.path.isdir(settings.output_dir) else None
    ranges = [range_seconds(p) or 0 for p in book.profiles if p.get("active", True)]
    need_min = None
    if ranges:
        need_min = int((max(ranges) + settings.exporter_lag_seconds + settings.window_margin_seconds
                        + settings.chunk_seconds) / 60) + 1
    mtime = None
    try:
        mtime = int(os.stat(profile_store_active(settings)).st_mtime)
    except OSError:
        pass
    warnings: list[str] = []
    if need_min and not rolling["stale"] and rolling["retention_minutes"] is not None \
            and rolling["retention_minutes"] < need_min:
        warnings.append(f"Rolling buffer holds {rolling['retention_minutes']} min but the longest profile "
                        f"needs about {need_min} min: its alerts can miss. Raise n2disk --disk-limit.")
    if rolling["reported"] and not rolling["stale"] and rolling["newest_age_seconds"] is None:  # the worker looked: nothing there
        warnings.append("No rolling capture files found: is n2disk writing to the timeline directory?")
    if free is not None and free < settings.min_free_bytes * 2:
        warnings.append("Free space is close to SR_MIN_FREE_BYTES: extractions will be refused below it.")
    if store.paused():
        warnings.append("The worker is paused by an operator: queued jobs do not start (System page: Resume).")
    if not worker["alive"]:
        warnings.append(f"The worker is not running (state {worker['state']}): jobs are queued but not extracted.")
    if len(book) == 0:
        warnings.append("No profiles loaded: every alert uses the default window and filter.")
    cfg = redact_map(dict(settings))
    return {
        "version": version(), "generated": int(time.time()), "uptime_seconds": snap["uptime"]["web"],
        "uptime": snap["uptime"], "since": snap["since"],
        "tz": os.environ.get("TZ", "") or "/".join(time.tzname),
        "checks": [{"name": c.name, "module": MODULE.get(c.name, "Other"),
                                           "status": c.status, "detail": c.detail} for c in results],
        "overall": checks_mod.overall(results),
        "rolling": rolling, "alerts": alerts, "free_bytes": free, "need_minutes": need_min,
        "queue": store.counts(), "outcomes": snap["outcomes"],
        "seconds_since_last_webhook": snap["seconds_since_last_webhook"],
        "seconds_since_last_success": snap["seconds_since_last_success"],
        "workers": store.workers(), "paused": store.paused(), "worker": worker,
        "profiles": {"count": len(book), "file": profile_store_active(settings), "mtime": mtime,
                     "rows": profile_rows(book, settings)},
        "warnings": warnings, "config": cfg, "config_rows": config_store.rows(settings),
        "config_enabled": bool(settings.config_password),
        "db_bytes": (os.path.getsize(store.path) if os.path.exists(store.path) else None),
        "disks": disks(settings), "host": host_info(), "min_free_bytes": settings.min_free_bytes}
