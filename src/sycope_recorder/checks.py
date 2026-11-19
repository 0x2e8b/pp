"""Self-checks: is this deployment actually able to produce a PCAP?

Every outage seen at the first customer was at a seam between components
(n2disk silently not writing, alerts volume not shared with Caddy, wrong
timezone, unwritable output dir, disk full), not in the Python logic. These
checks probe those seams directly. They back three things:

- `python -m sycope_recorder doctor` (run by an operator, exit code 1 on FAIL)
- `GET /healthz/deep` (behind Caddy's auth; 503 on FAIL)
- the worker's housekeeping thread (worker.py), which stores results for the web and logs only on
  state changes

Checks never modify anything beyond a short-lived probe file in output_dir.
"""

from __future__ import annotations

import http.client
import logging
import os
import re
import subprocess
import shutil
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime

from sycope_recorder import config
from sycope_recorder.config import Settings
from sycope_recorder.store import MAIN_SLOT, WORKER_BUSY, WORKER_ERROR

log = logging.getLogger("sycope_recorder")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """The root worker's probe never follows a redirect (S-8): a 3xx is a failed probe."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# No proxy from the environment either: the probe is for the caddy service next to the api.
_PROBE_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

OK, WARN, FAIL = "ok", "warn", "fail"

_DATED = re.compile(r"^(\d{4})/(\d{2})/(\d{2})/(\d{2})(?:/|$)")


@dataclass(frozen=True)
class Check:
    name: str
    status: str  # OK | WARN | FAIL
    detail: str


def overall(checks: list[Check]) -> str:
    if any(c.status == FAIL for c in checks):
        return FAIL
    if any(c.status == WARN for c in checks):
        return WARN
    return OK


def _edge_file(root: str, newest: bool, max_depth: int = 8) -> tuple[str, float] | None:
    """The newest or the oldest file under root as (path, mtime), without walking the whole tree.

    The rolling directory can hold ~100k directories (n2disk epoch layout), so a full walk is too
    slow for a health probe or a status page. Directory names in both n2disk layouts (YYYY/MM/DD/HH and
    epoch) sort chronologically, so descend into the highest (newest) or lowest (oldest) sorting
    subdirectory that yields a file, and stop there.
    """

    def better(a: float, b: float) -> bool:
        return a > b if newest else a < b

    def _walk(path: str, depth: int) -> tuple[str, float] | None:
        try:
            with os.scandir(path) as it:
                entries = list(it)
        except OSError:
            return None
        best: tuple[str, float] | None = None
        for e in entries:
            try:
                # Follow symlinks: with --timeline-dir n2disk's dated tree (YYYY/MM/DD/HH/MM)
                # holds only symlinks to the real files, and the timezone check needs that path.
                if e.is_file():
                    m = e.stat().st_mtime
                    if best is None or better(m, best[1]):
                        best = (e.path, m)
            except OSError:  # broken link or a file vanishing under us
                continue
        if depth > 0:
            dirs = sorted(
                (e for e in entries if e.is_dir(follow_symlinks=False)),
                key=lambda e: e.name,
                reverse=newest,
            )
            for d in dirs:
                found = _walk(d.path, depth - 1)
                if found is not None:
                    if best is None or better(found[1], best[1]):
                        best = found
                    break
        return best

    return _walk(root, max_depth)


def newest_file(root: str, max_depth: int = 8) -> tuple[str, float] | None:
    """Newest file under root as (path, mtime): see _edge_file."""
    return _edge_file(root, True, max_depth)


def oldest_file(root: str, max_depth: int = 8) -> tuple[str, float] | None:
    """Oldest file under root as (path, mtime): see _edge_file."""
    return _edge_file(root, False, max_depth)


def check_timeline(settings: Settings, now: float) -> tuple[Check, tuple[str, float] | None]:
    """Is n2disk writing fresh files? (The mtime of the newest one is what matters;
    `systemctl is-active` is true even while n2disk crash-loops on a bad licence.)"""
    root = settings.timeline_dir
    if not settings.rolling_check:
        return Check("rolling_fresh", OK, "skipped (SR_ROLLING_CHECK=false, demo/no capture)"), None
    if not os.path.isdir(root):
        return Check("rolling_fresh", FAIL, f"{root} is not a directory (mount missing?)"), None
    newest = newest_file(root)
    if newest is None:
        return Check("rolling_fresh", FAIL, f"no files under {root}: n2disk not writing "
                     "(check licence, capture interface carrier, journalctl -u n2disk)"), None
    age = now - newest[1]
    if age > settings.rolling_stale_seconds:
        return Check("rolling_fresh", FAIL,
                     f"newest file is {int(age)}s old (limit {settings.rolling_stale_seconds}s): "
                     f"n2disk stopped writing ({newest[0]})"), newest
    return Check("rolling_fresh", OK, f"newest file {int(age)}s old"), newest


def check_clock(settings: Settings, newest: tuple[str, float] | None) -> Check:
    """Does this container's timezone agree with how the host named the newest directory?

    n2disk's dated layout (YYYY/MM/DD/HH) is in the host's local time. The
    file's mtime is an absolute epoch; rendered in *our* timezone it should
    land inside that hour (plus up to one chunk of spill-over). A mismatch
    means extraction windows would be shifted by the difference.
    """
    if newest is None:
        return Check("timezone", OK, "skipped (no rolling file)")
    rel = os.path.relpath(newest[0], settings.timeline_dir).replace(os.sep, "/")
    m = _DATED.match(rel)
    if not m:
        return Check("timezone", OK, "skipped (rolling layout is not YYYY/MM/DD/HH)")
    y, mo, d, h = (int(x) for x in m.groups())
    hour_start = datetime(y, mo, d, h)
    delta = (datetime.fromtimestamp(newest[1]) - hour_start).total_seconds()
    low, high = -120, 3600 + settings.chunk_seconds + 120
    if low <= delta <= high:
        return Check("timezone", OK, f"container TZ matches rolling directory names ({rel})")
    hours = round((delta - 1800) / 3600)
    return Check(
        "timezone", WARN,
        f"container clock is ~{hours:+d}h vs the host's directory naming ({rel}); "
        "extraction windows will be shifted. Set TZ on the api service to the n2disk host's zone",
    )


def check_npcapextract(settings: Settings) -> Check:
    path = settings.npcapextract_path
    resolved = shutil.which(path)
    if resolved is None:
        return Check("npcapextract", FAIL, f"{path!r} not found on PATH")
    try:
        proc = subprocess.run([resolved, "-h"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return Check("npcapextract", FAIL, f"{resolved} does not run: {exc}")
    if not (proc.stdout or proc.stderr).strip():
        return Check("npcapextract", FAIL, f"{resolved} ran but printed nothing (broken binary/libs?)")
    return Check("npcapextract", OK, resolved)


def check_output_dir(settings: Settings) -> Check:
    out = settings.output_dir
    try:
        os.makedirs(out, exist_ok=True)
        probe = os.path.join(out, f".doctor-{uuid.uuid4().hex}")
        with open(probe, "w") as fh:
            fh.write("ok")
        os.remove(probe)
    except OSError as exc:
        return Check("output_dir", FAIL, f"{out} is not writable: {exc}")
    st = shutil.disk_usage(out)
    gib = st.free / 1024**3
    if st.free < settings.min_free_bytes:
        return Check("output_dir", FAIL,
                     f"only {gib:.1f} GiB free on {out}; extractions are refused below "
                     f"{settings.min_free_bytes / 1024**3:.1f} GiB")
    if st.free < 2 * settings.min_free_bytes:
        return Check("output_dir", WARN, f"{gib:.1f} GiB free, close to the refuse threshold")
    return Check("output_dir", OK, f"writable, {gib:.1f} GiB free")


def check_alerts_visible(settings: Settings) -> Check:
    """Prove Caddy serves the same storage the api writes to.

    Mounting the host path into only one of the two services leaves Caddy
    serving an empty volume: PCAPs exist but every download link is a 404.
    """
    if not settings.probe_url:
        return Check("alerts_visible_to_caddy", OK, "skipped (SR_PROBE_URL not set)")
    name = f".probe-{uuid.uuid4().hex}"
    path = os.path.join(settings.output_dir, name)
    url = f"{settings.probe_url.rstrip('/')}/{name}"
    try:
        with open(path, "w") as fh:
            fh.write("probe")
        try:
            with _PROBE_OPENER.open(url, timeout=3) as resp:  # noqa: S310 (compose-set URL, locked)
                body = resp.read(16)
        except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
            return Check("alerts_visible_to_caddy", FAIL,
                         f"caddy cannot read the file the api just wrote ({exc}): "
                         "api and caddy do not share the alerts volume; downloads would be 404")
        if body != b"probe":
            return Check("alerts_visible_to_caddy", FAIL, "caddy returned unexpected content")
        return Check("alerts_visible_to_caddy", OK, "caddy serves the api's alerts volume")
    except OSError as exc:
        return Check("alerts_visible_to_caddy", FAIL, f"cannot write probe file: {exc}")
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def check_state_dir(settings: Settings) -> Check:
    try:
        os.makedirs(settings.state_dir, exist_ok=True)
        probe = os.path.join(settings.state_dir, f".doctor-{uuid.uuid4().hex}")
        with open(probe, "w") as fh:
            fh.write("ok")
        os.remove(probe)
    except OSError as exc:
        return Check("state_dir", FAIL, f"{settings.state_dir} is not writable: {exc}")
    return Check("state_dir", OK, settings.state_dir)


def check_settings(notes: list[str] | None = None) -> Check:
    """WARN when this process started with a setting replaced or ignored (config.get_settings): a value
    outside its range in .env (or in an older uploaded configuration) is used as the nearest valid one,
    and a key that can only be set in the environment is ignored in config.override.json."""
    notes = config.NOTES if notes is None else notes
    if notes:
        return Check("settings", WARN, "; ".join(notes))
    return Check("settings", OK, "every value within its range")


HUNG_MARGIN = 60  # seconds over SR_EXTRACT_TIMEOUT_SECONDS before a slot counts as hung
_NET_FS = {"nfs", "nfs4", "cifs", "smb3", "smbfs", "fuse.sshfs", "glusterfs", "ceph", "9p"}


def check_state_dir_local(settings: Settings, mounts_file: str = "/proc/mounts") -> Check:
    """SQLite WAL (shared memory between the two processes) does not work on network filesystems."""
    try:
        with open(mounts_file) as fh:
            lines = fh.read().splitlines()
    except OSError:
        return Check("state_dir_local", OK, "skipped (no /proc/mounts)")
    path = os.path.realpath(settings.state_dir)
    best_mnt, best_fs = "", ""
    for line in lines:
        parts = line.split()
        if len(parts) < 3:
            continue
        mnt = parts[1].replace("\\040", " ")
        inside = path == mnt or path.startswith(mnt.rstrip("/") + "/")
        if inside and len(mnt) >= len(best_mnt):
            best_mnt, best_fs = mnt, parts[2]
    if best_fs in _NET_FS:
        return Check("state_dir_local", FAIL, f"{settings.state_dir} is on {best_fs} ({best_mnt}): "
                     "the job database needs a local filesystem")
    return Check("state_dir_local", OK, f"{best_fs or 'unknown'} ({best_mnt or '?'})")


def check_worker(rows: list[dict], paused: bool, settings: Settings, now: float) -> Check:
    """Alive (fresh heartbeat), not stuck in a step, not paused."""
    main = next((r for r in rows if r["slot"] == MAIN_SLOT), None)
    if main is None or main.get("heartbeat") is None:
        return Check("worker", FAIL, "the worker has never started (no heartbeat in the job database)")
    age = now - main["heartbeat"]
    if age > settings.worker_stale_seconds:
        return Check("worker", FAIL, f"no worker heartbeat for {int(age)} s: queued jobs are not being run")
    if main.get("state") == WORKER_ERROR:
        return Check("worker", FAIL, f"the worker cannot start: {main.get('detail') or 'see the worker log'}")
    limit = settings.extract_timeout_seconds + HUNG_MARGIN
    for r in rows:
        if r["slot"] != MAIN_SLOT and r.get("state") == WORKER_BUSY and r.get("step_started") \
                and now - r["step_started"] > limit:
            return Check("worker", FAIL, f"{r['slot']} has been in step {r.get('step')} of {r.get('job_id')} "
                         f"for {int(now - r['step_started'])} s (hung)")
    if paused:
        return Check("worker", WARN, "paused by an operator: no new job starts")
    slots = [r for r in rows if r["slot"] != MAIN_SLOT]
    busy = sum(1 for r in slots if r.get("state") == WORKER_BUSY)
    return Check("worker", OK, f"alive, {busy}/{len(slots)} slots busy")


def stored_checks(store, settings: Settings, now: float | None = None) -> list[Check]:
    """The worker's last check results (a stale one becomes at least WARN) plus the live worker check."""
    now = time.time() if now is None else now
    stale_after = 3 * settings.watchdog_interval_seconds
    order = {OK: 0, WARN: 1, FAIL: 2}
    out = []
    rows = store.checks()
    for r in rows:
        if now - r["ts"] > stale_after:
            status = r["status"] if order.get(r["status"], 1) >= 1 else WARN
            out.append(Check(r["name"], status, f"result is {int(now - r['ts'])} s old (checks stale): {r['detail']}"))
        else:
            out.append(Check(r["name"], r["status"], r["detail"]))
    if not rows:
        out.append(Check("checks", WARN, "no self-check results yet (the worker writes them)"))
    out.append(check_worker(store.workers(), store.paused(), settings, now))
    return out


def check_profiles(settings: Settings) -> Check:
    """Are the per-definition extraction profiles loadable (when configured)?"""
    from sycope_recorder.profile_store import override_path

    if not settings.profiles_file and not os.path.exists(override_path(settings)):
        return Check("profiles", OK, "not configured (default window/filter for every alert)")
    from sycope_recorder.profile_store import active_path
    from sycope_recorder.profiles import ProfileBook

    path, source = active_path(settings)
    book = ProfileBook.load(path)
    if len(book) == 0:
        return Check("profiles", WARN, f"{path} is missing, unreadable or empty: "
                     "alerts use the default window/filter")
    return Check("profiles", OK, f"{len(book)} profiles from {path}" + (" (uploaded)" if source == "uploaded" else ""))


def run_checks(settings: Settings, now: float | None = None) -> list[Check]:
    now = time.time() if now is None else now
    timeline, newest = check_timeline(settings, now)
    return [
        timeline,
        check_clock(settings, newest),
        check_npcapextract(settings),
        check_output_dir(settings),
        check_alerts_visible(settings),
        check_state_dir(settings),
        check_state_dir_local(settings),
        check_profiles(settings),
        check_settings(),
    ]
