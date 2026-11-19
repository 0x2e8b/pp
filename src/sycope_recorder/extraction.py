"""Builds the extraction filename/time-window and shells out to npcapextract.

This is the layer where alert data actually turns into a PCAP: it derives
the output filename and the [begin, end] extraction window from the alert
timestamp, invokes npcapextract as a subprocess with the BPF filter built
elsewhere (bpf.py), and classifies the outcome. No packet inspection happens
here or anywhere in this codebase - npcapextract does that; this module is
orchestration around it.

plan_extraction() runs at webhook time in the web process; execute_plan() runs
later in the worker process (jobs.py), once the window is on disk.

Outcomes are a Kind. The caller-facing body text is unchanged from the legacy
contract; MISS and FAILED still share ERR_FAILED text but
carry different `.kind`, exposed to Sycope's logs via the X-Outcome header.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import struct
import subprocess
import threading
import time
from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum

from sycope_recorder.alert import ParsedAlert
from sycope_recorder.bpf import build_bpf_filter
from sycope_recorder.config import Settings
from sycope_recorder.procs import kill_group
from sycope_recorder.profiles import MAX_RANGE_S, profile_bpf, window_seconds

log = logging.getLogger("sycope_recorder")

# The window as npcapextract -b/-e takes it: the host's local wall-clock time, no zone. Each bound
# is the local time of its own epoch (local_bound), never a local time plus seconds, so a clock
# change inside the window cannot shift a bound. What this format cannot say: in the hour a clock
# change repeats (autumn), one string names two instants, and how npcapextract reads such a string
# is up to it; the repository documents no other form of -b/-e, so this one stays.
TS_FMT = "%Y-%m-%d %H:%M:%S"
# npcapextract's summary line: "0 packets (0 bytes) matched the filter in 0.006 sec."
_MATCHED = re.compile(r"(\d+) packets \(\d+ bytes\) matched")
# Intentionally ASCII-only (unlike the legacy implementation, which used
# str.isalnum() and thus accepted Unicode letters/digits). Sycope alert IDs
# are always ASCII/numeric, so behavior is identical for real inputs; the
# stricter ASCII allowlist is also safer when the sanitized value is embedded
# in a filename/URL. Do not "fix" this back to Unicode.
_ID_ALLOWED = re.compile(r"[^A-Za-z0-9_-]")
_ID_PLAIN = re.compile(r"[A-Za-z0-9_-]{1,64}")

NO_BPF = "NO BPF FILTER"
ERR_TIMEOUT = "ERROR: npcapextract timeout"
ERR_FAILED = "ERROR: npcapextract failed"
ERR_DISK = "ERROR: low disk space"


class Kind(str, Enum):
    """What happened to one extraction. Values double as stats keys / X-Outcome."""

    SUCCESS = "success"
    NO_BPF = "no_bpf"
    MISS = "miss"  # npcapextract rc 0 but zero packets matched
    FAILED = "failed"  # npcapextract error (rc != 0, or no output file)
    TIMEOUT = "timeout"
    DISK_LOW = "disk_low"
    CANCELLED = "cancelled"  # an operator cancelled the job while npcapextract ran
    INTERRUPTED = "interrupted"  # the worker stopped (reload, shutdown) while npcapextract ran


class Result(str):
    """The caller-facing body text, plus the precise outcome in `.kind`.

    A str subclass so existing callers/tests that compare against plain
    strings keep working.
    """

    kind: Kind

    def __new__(cls, text: str, kind: Kind) -> "Result":
        obj = super().__new__(cls, text)
        obj.kind = kind
        return obj


def kind_of(text: str) -> Kind:
    """Best-effort Kind for a plain string (used when a Result was not produced)."""
    kind = getattr(text, "kind", None)
    if isinstance(kind, Kind):
        return kind
    if text.startswith("https://"):
        return Kind.SUCCESS
    return {
        NO_BPF: Kind.NO_BPF,
        ERR_TIMEOUT: Kind.TIMEOUT,
        ERR_DISK: Kind.DISK_LOW,
    }.get(text, Kind.FAILED)


@dataclass(frozen=True)
class Plan:
    """Everything needed to run (or later re-run) one extraction."""

    alert_id: object
    filename: str
    output_path: str
    begin: str
    end: str
    bpf: str
    window_end_epoch: float  # alert time + after, as a UTC epoch
    window_begin_epoch: float  # the epoch of `begin` (whole seconds); look-back widening counts from it
    profile: str = ""  # name of the definition profile that built bpf/window, "" = defaults

    @property
    def alert_key(self) -> str:
        """URL-safe form of the alert id: the stable handle of this alert's PCAP (see alert_key)."""
        return alert_key(self.alert_id)

    def url(self, settings: Settings) -> str:
        """The link handed to Sycope: <base>/<alert key>.

        It is always the status page (api.py, GET /{key}) and never returns the file; the PCAP is
        the same path with `?download=1`. `base` is download_url_base (e.g.
        `sycope/npm/api/v1/passthrough/recorder`) or the recorder's own host.
        """
        base = settings.download_url_base or settings.public_host
        return f"https://{base}/{self.alert_key}"

    def legacy_url(self, settings: Settings) -> str:
        """Pre-2026-10-09 link to the file itself (still served by Caddy)."""
        base = settings.download_url_base or settings.public_host
        return f"https://{base}/{settings.download_prefix}/{self.filename}"


def alert_key(raw: object) -> str:
    """The alert's key: its link path and the end of its file name. At most 64 of [A-Za-z0-9_-].

    An id that already is 1 to 64 of those characters is its own key (as it always was). Any other id
    (other characters, longer than 64) is stripped to those characters and cut to 51 ("alert" if
    nothing is left), and gets `-` and 12 hex digits of the SHA-256 of the whole id, so two ids that
    strip alike ("a.b", "a:b") get different keys. Earlier releases only stripped and cut to 64; rows
    and files made then keep that key. An ordinary id can still spell such a key: store.enqueue refuses
    a key that already belongs to another alert.
    """
    text = str(raw)
    if _ID_PLAIN.fullmatch(text):
        return text
    digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:12]
    return f"{_ID_ALLOWED.sub('', text)[:51] or 'alert'}-{digest}"


def local_bound(epoch: float) -> tuple[str, float]:
    """One window bound: (the local wall time of `epoch` in TS_FMT, the epoch of that whole second).

    The string is what npcapextract gets; the epoch is kept for arithmetic, because a local time
    string cannot be moved by seconds across a clock change, nor always be read back (see TS_FMT).
    """
    local = datetime.fromtimestamp(epoch)  # naive local time; fold marks the repeated hour
    return local.strftime(TS_FMT), local.replace(microsecond=0).timestamp()


def local_epoch(ts: str) -> float:
    """The epoch of a stored window start (TS_FMT, local time): only for rows, which keep no begin epoch.

    Exact except in the hour a clock change repeats, where the string names two instants, and for a
    time a spring change skips (rows written before the bounds were computed from epochs). Then the
    earlier reading is taken, so a window computed from it can only grow. ValueError if the text is
    not in TS_FMT.
    """
    naive = datetime.strptime(ts, TS_FMT)
    return min(naive.replace(fold=0).timestamp(), naive.replace(fold=1).timestamp())


def compute_window(alert_epoch: float, before: int, after: int) -> tuple[str, str, float]:
    """(begin, end, begin epoch) of the [alert - before, alert + after] window: each bound the local
    time of its own epoch, so a clock change between the alert and a bound does not shift it."""
    begin, begin_epoch = local_bound(alert_epoch - before)
    end, _ = local_bound(alert_epoch + after)
    return begin, end, begin_epoch


def build_filename(alert_time: datetime, raw_id: object) -> str:
    """Build the output .pcap filename from the alert time and the alert key (alert_key)."""
    return f"{alert_time:%Y%m%d_%H%M%S}_{alert_key(raw_id)}.pcap"


def plan_extraction(
    parsed: ParsedAlert, mode: str, before: int, after: int, settings: Settings,
    profile: dict | None = None,
) -> Plan | None:
    """Build the BPF filter, window, and output path; None if no filter can be built.

    With a definition `profile` (profiles.py) it decides both the filter and the
    window; `mode`, `before` and `after` then only serve alerts without one.
    """
    # Deliberately the host's local wall-clock time, not UTC: npcapextract
    # indexes n2disk's timeline against the recording host's system clock,
    # so the window must be expressed in that same clock. unixTimestamp is a
    # UTC epoch and tz-independent; the conversion is correct whenever the
    # container's timezone matches the n2disk host's (verify with `date` on
    # both - the container defaults to UTC; `doctor` also checks it from the
    # rolling directory names). If they differ, the window silently shifts
    # by the offset; run the recording host in UTC or set TZ on the api
    # service to the host's zone.
    alert_time = datetime.fromtimestamp(parsed.timestamp).astimezone()

    if profile is not None:
        bpf = profile_bpf(profile, parsed)
        window = window_seconds(profile, settings.exporter_lag_seconds, settings.window_margin_seconds)
        if window is None:  # only a mounted file can carry one: an upload is checked
            log.warning("profile %s: time_range_s %r is not an integer from 1 to %d s; alert id=%s uses the "
                        "profile's filter and the default window (%d s before, %d s after)",
                        profile.get("name") or profile.get("def_id"), profile.get("time_range_s"),
                        MAX_RANGE_S, parsed.alert_id, before, after)
        else:
            before, after = window
    else:
        bpf = build_bpf_filter(parsed, mode)
    if not bpf:
        return None

    filename = build_filename(alert_time, parsed.alert_id)
    begin, end, begin_epoch = compute_window(parsed.timestamp, before, after)
    return Plan(
        alert_id=parsed.alert_id,
        filename=filename,
        output_path=os.path.join(settings.output_dir, filename),
        begin=begin,
        end=end,
        bpf=bpf,
        window_end_epoch=parsed.timestamp + after,
        window_begin_epoch=begin_epoch,
        profile=(profile.get("name") or "") if profile is not None else "",
    )


def lag_for_attempt(attempt: int, settings: Settings) -> int:
    """The look-back (seconds before the bucket start) a profile job uses on this attempt (or
    widening step): the lag, x2, x4, ... up to the cap. The one formula for every widening."""
    lag = settings.exporter_lag_seconds
    return max(lag, min(lag * 2 ** (max(attempt, 1) - 1), settings.window_max_lag_seconds))


def widened_plan(plan: Plan, attempt: int, settings: Settings) -> Plan:
    """The stored `plan` as attempt `attempt` of a profile job runs it: looking further back.

    A miss can mean the flows were exported later than the configured lag; the job is retried
    anyway, so the retry costs nothing extra. The stored window is not changed: the widening
    is derived from the attempt number, so a restarted worker cannot compound it. The start moves
    as an epoch and is formatted again (local_bound), so a clock change in between does not shift it.
    """
    extra = lag_for_attempt(attempt, settings) - settings.exporter_lag_seconds
    if not plan.profile or extra <= 0:
        return plan
    begin, begin_epoch = local_bound(plan.window_begin_epoch - extra)
    return replace(plan, begin=begin, window_begin_epoch=begin_epoch)


def wider_than(stored: Plan, attempt: int, settings: Settings) -> Plan | None:
    """The stored plan one look-back step past `attempt` (widened_plan of attempt + 1); None at the cap."""
    if not stored.profile or lag_for_attempt(attempt + 1, settings) <= lag_for_attempt(attempt, settings):
        return None
    return widened_plan(stored, attempt + 1, settings)


# Classic pcap magic number -> (struct byte order, nanosecond timestamps).
_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", False), b"\x4d\x3c\xb2\xa1": ("<", True),
    b"\xa1\xb2\xc3\xd4": (">", False), b"\xa1\xb2\x3c\x4d": (">", True),
}


def first_packet_epoch(path: str) -> float | None:
    """Timestamp of the first packet of a classic pcap file, None if it cannot be read."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(40)
    except OSError:
        return None
    if len(head) < 40:
        return None
    magic = head[:4]
    endian, nano = _PCAP_MAGIC.get(magic, (None, False))
    if endian is None:
        return None
    sec, frac = struct.unpack(endian + "II", head[24:32])
    return sec + frac / (1e9 if nano else 1e6)


def pcap_summary(path: str, max_packets: int = 20_000_000) -> dict | None:
    """Packets and the first/last packet time of a classic pcap file, from its record headers only
    (no payload is read into memory). None for another format or an unreadable file."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(24)
            if len(head) < 24:
                return None
            endian, nano = _PCAP_MAGIC.get(head[:4], (None, False))
            if endian is None:
                return None
            rec = struct.Struct(endian + "IIII")
            div = 1e9 if nano else 1e6
            n, first, last = 0, None, None
            while n < max_packets:
                h = fh.read(16)
                if len(h) < 16:
                    break
                sec, frac, incl, _orig = rec.unpack(h)
                t = sec + frac / div
                first = t if first is None else first
                last = t
                n += 1
                fh.seek(incl, 1)
    except OSError:
        return None
    return {"packets": n, "first": first, "last": last}


def window_warning(plan: Plan, settings: Settings) -> str:
    """A note when the PCAP starts right at the window start: the window may have cut flows.

    Empty when the first packet is comfortably inside the window (or cannot be read).
    """
    first = first_packet_epoch(plan.output_path)
    if first is None:
        return ""
    gap = first - plan.window_begin_epoch
    if gap >= settings.window_warn_seconds:
        return ""
    hint = ("raise SR_EXPORTER_LAG_SECONDS" if plan.profile else "raise the `before` parameter")
    return (f"warning: the first packet is {max(0, int(gap))} s after the window start "
            f"({plan.begin}); flows exported late, or running since before it, may be cut off "
            f"({hint})")


_FILE_START = re.compile(r"^(\d{9,11})(?:\.(\d+))?")


_EPOCH_DIR = re.compile(r"^\d{9,11}(?:\.\d+)?$")


def _start_of(name: str) -> float | None:
    m = _FILE_START.match(name)
    return float(f"{m.group(1)}.{m.group(2) or 0}") if m else None


def rolling_span(timeline_dir: str) -> dict:
    """How much the rolling capture holds, from file names only: {"files", "oldest_start", "newest_start"}.

    n2disk's layout is one directory per run (named by its start epoch) holding files named by their
    own start epoch, so counting and ordering need no stat() and no walk of the dated symlink tree: on a
    multi-terabyte buffer a full walk is hundreds of thousands of calls. Other layouts fall back to the
    directed searches of checks.py (counts unknown).
    """
    from sycope_recorder.checks import newest_file, oldest_file

    out: dict = {"files": 0, "oldest_start": None, "newest_start": None}
    try:
        dirs = [e for e in os.scandir(timeline_dir)
                if e.is_dir(follow_symlinks=False) and _EPOCH_DIR.match(e.name)]
    except OSError:
        return out
    lo = hi = None
    for d in dirs:
        try:
            with os.scandir(d.path) as it:
                for f in it:
                    if f.name.endswith(".pcap") and (s := _start_of(f.name)) is not None:
                        out["files"] += 1
                        lo = s if lo is None else min(lo, s)
                        hi = s if hi is None else max(hi, s)
        except OSError:
            continue
    if lo is None:  # no n2disk epoch directories: directed search in whatever layout there is
        def start_of(found: tuple[str, float] | None) -> float | None:
            if found is None:
                return None
            return _start_of(os.path.basename(found[0])) or found[1]

        hi, lo = start_of(newest_file(timeline_dir)), start_of(oldest_file(timeline_dir))
        out["files"] = None if (lo is not None or hi is not None) else 0
    out["oldest_start"], out["newest_start"] = lo, hi
    return out


def rolling_snapshot(timeline_dir: str, now: float | None = None) -> dict:
    """The worker's report of the rolling capture, for the web to show: names only, with its time.

    n2disk creates its per-run directories unreadable for the web's user, so only the root worker can
    list the tree; the web reads this stored summary and never lists it. The starts are epochs, so the
    web can compute ages at the moment it renders.
    """
    span = rolling_span(timeline_dir)
    return {"ts": time.time() if now is None else now, "files": span["files"],
            "oldest_start": span["oldest_start"], "newest_start": span["newest_start"]}


def newest_file_start(timeline_dir: str) -> float | None:
    """Start time of the newest rolling file, open or closed (n2disk names a file after its first
    packet).

    The epoch-named directories (`<epoch>/<epoch>.pcap`) hold a file from the moment it is opened.
    The dated tree (`YYYY/MM/DD/..`) lists files only once they are closed, one rotation too late
    to tell that the file with the window end is closed, so it is only the fallback for layouts
    without epoch directories.
    """
    from sycope_recorder.checks import newest_file

    best: float | None = None
    try:
        dirs = [e for e in os.scandir(timeline_dir)
                if e.is_dir(follow_symlinks=False) and _EPOCH_DIR.match(e.name)]
        if dirs:
            top = max(dirs, key=lambda e: float(e.name))
            for f in os.scandir(top.path):
                if f.name.endswith(".pcap") and (s := _start_of(f.name)) is not None:
                    best = s if best is None else max(best, s)
    except OSError:
        pass
    if best is None:
        found = newest_file(timeline_dir)
        if found is not None:
            best = _start_of(os.path.basename(found[0]))
    return best


class NewestStart:
    """newest_file_start of one rolling directory, listed at most once per `max_age` seconds.

    The worker's slots share one instance, so many jobs waiting for the same capture cost one listing,
    not one each (E-1). A reused value can only be older, that is smaller: a job may wait one poll
    longer, never run before its window is closed.
    """

    def __init__(self, timeline_dir: str, max_age: float) -> None:
        self.timeline_dir, self.max_age = timeline_dir, max_age
        self._lock = threading.Lock()
        self._at: float | None = None
        self._value: float | None = None

    def get(self) -> float | None:
        """The cached start, listed again when older than max_age (one listing even if many ask)."""
        with self._lock:
            now = time.monotonic()
            if self._at is None or now - self._at >= self.max_age:
                self._value = newest_file_start(self.timeline_dir)
                self._at = now
            return self._value


def window_on_disk(plan: Plan, settings: Settings,
                   newest: NewestStart | None = None) -> tuple[bool, float | None]:
    """(is the file holding the window end closed, start of the newest file).

    True when a file starts after the window end: n2disk opens a new file only after closing the
    previous one. Unknown (no capture, no files, odd names) counts as True: never block on a guess.
    `newest`, when given, supplies the shared start instead of a listing of its own.
    """
    if not settings.rolling_check:
        return True, None
    start = newest.get() if newest is not None else newest_file_start(settings.timeline_dir)
    if start is None:
        return True, None
    return start > plan.window_end_epoch, start


def free_bytes(path: str) -> int | None:
    """Free bytes on the filesystem holding `path` (its nearest existing parent), None if unknown."""
    probe = path
    while probe and not os.path.exists(probe):
        parent = os.path.dirname(probe)
        if parent == probe:
            return None
        probe = parent
    try:
        return shutil.disk_usage(probe).free
    except OSError:
        return None


OUTPUT_TAIL_BYTES = 64 * 1024


class Stopped(Exception):
    """npcapextract was killed on purpose; `reason` is "cancel" (operator) or "stop" (worker stopping)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _run_capped(cmd: list[str], timeout: float, cap: int = OUTPUT_TAIL_BYTES,
                should_stop=None, on_spawn=None) -> subprocess.CompletedProcess:
    """subprocess.run with captured output tails, a process group, and a stop hook.

    Each stream keeps only its last `cap` bytes (a runaway npcapextract cannot fill memory through
    the pipe). The child gets its own process group so a timeout, cancel or stop kills everything it
    started. `on_spawn(pid)` lets the caller record the child (the worker cleans up after a crash);
    `should_stop()` is asked about once a second and a non-empty answer kills the group and raises
    Stopped. A timeout still raises subprocess.TimeoutExpired like subprocess.run.
    """
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    tails: dict[str, bytearray] = {"out": bytearray(), "err": bytearray()}
    cut = {"out": False, "err": False}

    def drain(name: str, pipe) -> None:
        buf = tails[name]
        for chunk in iter(lambda: pipe.read(65536), b""):
            buf += chunk
            if len(buf) > cap:
                del buf[: len(buf) - cap]
                cut[name] = True

    threads: list[threading.Thread] = []
    killed: list[bool] = []

    def stop_all() -> None:
        # Runs once: the timeout and stop paths call it and the catch-all below calls it again for the
        # same exception. The group is killed first and no thread is needed for it: the leader is
        # reaped by kill_group's own polling (an unreaped zombie would keep the group "alive" for the
        # whole grace period), so a thread that cannot be started can never leave npcapextract running.
        if killed:
            return
        killed.append(True)
        try:
            kill_group(proc.pid, reap=proc.poll)
        finally:
            proc.wait()
            for t in threads:
                t.join(5)

    # From here on, whatever goes wrong (a hook raising on a database error, a failed thread start)
    # must not leave a running npcapextract behind: this process is root and nobody else would stop it.
    try:
        for n, p in (("out", proc.stdout), ("err", proc.stderr)):
            t = threading.Thread(target=drain, args=(n, p), daemon=True)
            t.start()
            threads.append(t)
        if on_spawn is not None:
            on_spawn(proc.pid)
        deadline = time.monotonic() + timeout
        while True:
            try:
                proc.wait(timeout=max(0.0, min(1.0, deadline - time.monotonic())))
                break
            except subprocess.TimeoutExpired:
                if time.monotonic() >= deadline:
                    stop_all()
                    raise subprocess.TimeoutExpired(cmd, timeout) from None
                reason = should_stop() if should_stop is not None else None
                if reason:
                    stop_all()
                    raise Stopped(reason) from None
    except BaseException:
        stop_all()
        raise
    for t in threads:
        t.join(5)

    def text(name: str) -> str:
        body = bytes(tails[name]).decode("utf-8", "replace")
        return ("[... earlier output dropped ...]\n" + body) if cut[name] else body

    return subprocess.CompletedProcess(cmd, proc.returncode, text("out"), text("err"))


def execute_plan(plan: Plan, settings: Settings, should_stop=None, on_spawn=None) -> Result:
    """Run npcapextract for a plan and classify the outcome.

    Order of checks: disk guard (refuse before writing anything), then the
    subprocess with a hard timeout, then output validation. rc 0 with a
    zero-byte file is a MISS (no packets matched in the window): the empty
    file is deleted. A MISS shares ERR_FAILED text with a real failure for
    the legacy contract but has Kind.MISS.
    """
    os.makedirs(settings.output_dir, exist_ok=True)

    free = free_bytes(settings.output_dir)
    if free is not None and free < settings.min_free_bytes:
        log.error(
            "LOW DISK: %d bytes free on %s < min_free_bytes=%d; refusing extraction (id=%s)",
            free, settings.output_dir, settings.min_free_bytes, plan.alert_id,
        )
        return Result(ERR_DISK, Kind.DISK_LOW)

    # npcapextract writes to a private temporary name and the finished file is renamed into place, so a
    # reader never sees a half-written PCAP and two runs of the same job cannot write into one file. A
    # worker killed mid-extraction leaves its .part file to the next worker's startup cleanup.
    # (it keeps the .pcap ending, which the real npcapextract may expect, and no *_<alert id>.pcap pattern matches it)
    stem = plan.output_path[:-5] if plan.output_path.endswith(".pcap") else plan.output_path
    part = f"{stem}.part{os.getpid()}-{threading.get_ident()}.pcap"
    cmd = [
        settings.npcapextract_path,
        "-t", settings.timeline_dir,
        "-b", plan.begin,
        "-e", plan.end,
        "-f", plan.bpf,
        "-o", part,
    ]
    if settings.npcapextract_user:
        # Without -u, npcapextract drops to "nobody" and fails with
        # "Permission denied" creating the file in output_dir (seen in the
        # field; the workaround then was chmod 0777 on the directory).
        cmd += ["-u", settings.npcapextract_user]

    try:
        proc = _run_capped(cmd, settings.extract_timeout_seconds,
                           should_stop=should_stop, on_spawn=on_spawn)
    except subprocess.TimeoutExpired:
        log.error("npcapextract timeout after %ss (id=%s)",
                  settings.extract_timeout_seconds, plan.alert_id)
        _remove_quietly(part)
        return Result(ERR_TIMEOUT, Kind.TIMEOUT)
    except Stopped as exc:
        _remove_quietly(part)
        if exc.reason == "cancel":
            log.info("npcapextract cancelled by an operator (id=%s)", plan.alert_id)
            return Result(ERR_FAILED, Kind.CANCELLED)
        log.info("npcapextract stopped: the worker is stopping (id=%s)", plan.alert_id)
        return Result(ERR_FAILED, Kind.INTERRUPTED)

    exists = os.path.exists(part)
    if proc.returncode == 0 and exists and os.path.getsize(part) > 0:
        try:
            # The web runs as sr and serves ?download=1; npcapextract (run with -u root) may create the
            # file stricter than 0644. Only the file this run produced, never anything else in the directory.
            os.chmod(part, 0o644)
        except OSError as exc:
            log.warning("could not make %s readable by the web: %s", part, exc)
        os.replace(part, plan.output_path)
        size = os.path.getsize(plan.output_path)
        url = plan.url(settings)
        log.info("SUCCESS: %s (%d bytes) URL: %s", plan.output_path, size, url)
        return Result(url, Kind.SUCCESS)

    if proc.returncode == 0 and exists:
        log.info("MISS: no packets matched (id=%s); removing %s",
                 plan.alert_id, part)
        _remove_quietly(part)
        return Result(ERR_FAILED, Kind.MISS)

    # The real npcapextract creates no file at all when nothing matches (rc 0, "0 packets
    # ... matched"); an empty file was only ever the stub's idea of a miss.
    matched = _MATCHED.search(proc.stdout or "")
    if proc.returncode == 0 and matched and int(matched.group(1)) == 0:
        log.info("MISS: npcapextract matched 0 packets (id=%s)", plan.alert_id)
        return Result(ERR_FAILED, Kind.MISS)

    log.error("npcapextract failed rc=%s stdout=%r stderr=%r",
              proc.returncode, proc.stdout, proc.stderr)
    _remove_quietly(part)
    return Result(ERR_FAILED, Kind.FAILED)


def _remove_quietly(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass
