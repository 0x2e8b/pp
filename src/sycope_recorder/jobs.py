"""One claimed job, from the readiness check to its final state; run by the worker's slot threads.

Synchronous on purpose: worker.py gives each job its own thread, so blocking calls (the rolling
directory listing, npcapextract, file renames) need no executor. All state lives in the store
(store.py). Why a queue at all: Sycope fires alerts in bursts and npcapextract only sees data n2disk
has closed (a file every --max-file-duration seconds), so an alert for "now" cannot be extracted for
another chunk or so. The webhook answers at once with the alert's link; a job runs once
window_end + chunk + margin has passed.
"""

from __future__ import annotations

from dataclasses import replace
import json
import logging
import os
import re
import sqlite3
import threading
import time

from sycope_recorder.config import Settings
from sycope_recorder.extraction import (
    Kind, NewestStart, Plan, _remove_quietly, execute_plan, lag_for_attempt, local_epoch,
    pcap_summary, wider_than, widened_plan, window_on_disk, window_warning,
)
from sycope_recorder.procs import proc_start
from sycope_recorder.store import (  # noqa: F401  (re-exported: callers import states from here)
    CANCELLED, DONE, FAILED, FINAL, MISS, QUEUED, RETRYABLE, RUNNING, WAITING, JobStore,
)

log = logging.getLogger("sycope_recorder")

_NAME = re.compile(r"^[A-Za-z0-9_-]{1,100}\.pcap$")
# Every BPF the recorder builds (bpf.py, profiles.profile_bpf) uses only these characters.
_BPF = re.compile(r"^[A-Za-z0-9 .:()/]{1,4096}$")  # "/" for the networks of a re-extract (net fe80::/64)
# The extraction window as extraction.TS_FMT writes it; it goes to npcapextract -b/-e as one argument.
_TS = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")


def ready_at_for(plan: Plan, settings: Settings) -> float:
    """Earliest time the whole window is guaranteed to be in closed, indexed files."""
    return plan.window_end_epoch + settings.chunk_seconds + settings.ready_margin_seconds


def plan_from_job(job: dict) -> Plan:
    """Rebuild the extraction plan from a stored row, because the worker only has the database."""
    try:
        meta = json.loads(job.get("alert_meta") or "{}")
        # An operator's re-extract runs exactly the window it asked for: no automatic look-back widening.
        profile = "" if meta.get("reextract") else meta.get("profile", "")
    except (ValueError, AttributeError):
        profile = ""
    return Plan(
        alert_id=job["alert_id"],
        filename=job["id"],
        output_path=job["output_path"],
        begin=job["window_begin"],
        end=job["window_end"],
        bpf=job["bpf"],
        window_end_epoch=job["window_end_epoch"],
        # The row keeps no begin epoch: read it back from the string (exact but in the hour a clock
        # change repeats, where the earlier reading is taken, so the window can only grow).
        window_begin_epoch=local_epoch(job["window_begin"]),
        profile=profile if isinstance(profile, str) else "",
    )


def validate_job_row(job: dict, settings: Settings) -> str:
    """Why this row must not run, or "" when it is safe.

    The root worker executes what the non-root web wrote into the database, so the row is checked
    before every npcapextract run: the file stays inside the alerts directory (symlinks resolved),
    has a name the recorder makes, the filter has no character the recorder never produces, and the
    window is two timestamps in the recorder's format.
    The directory is checked first so a path that escapes is reported as such, not as a bad name.
    """
    name = str(job.get("id", ""))
    output_path = str(job.get("output_path", ""))
    alerts = os.path.realpath(settings.output_dir)
    if os.path.dirname(os.path.realpath(output_path)) != alerts:
        return "output path is outside the alerts directory"
    if not _NAME.match(name) or os.path.basename(output_path) != name:
        return "output file name is not one the recorder makes"
    if not _BPF.match(str(job.get("bpf", ""))):
        return "BPF filter has characters the recorder never produces"
    for column in ("window_begin", "window_end"):
        if not _TS.fullmatch(str(job.get(column, ""))):
            return "extraction window is not in the format the recorder makes"
        try:  # plan_from_job reads the bound back as a time: "2026-13-40 ..." must stop here
            local_epoch(str(job[column]))
        except (ValueError, OverflowError, OSError):
            return "extraction window is not in the format the recorder makes"
    return ""


class JobCtx:
    """What a slot thread lends run_one: progress reports and the stop/cancel signals.

    The default instance reports nothing and never stops, so tests and one-off callers can run a
    job without a worker. `soft_stop` (worker stopping) only prevents further widening;
    `hard_stop` (grace over) and a cancel request kill the running npcapextract.

    The slot's busy flag, step, step start and child are kept here in memory as well as in the
    `workers` row. The row is for the System page; the root watchdog trusts only this copy, because
    the web (sr) can write the row.

    `newest` is the worker's shared start of the newest rolling file; without it the readiness check
    lists the rolling directory itself.
    """

    def __init__(self, store: JobStore | None = None, slot: str = "",
                 soft_stop: threading.Event | None = None,
                 hard_stop: threading.Event | None = None,
                 newest: NewestStart | None = None) -> None:
        """Bind the store and slot for reports; fresh events when the caller has none."""
        self.store, self.slot, self.newest = store, slot, newest
        self.soft_stop = soft_stop or threading.Event()
        self.hard_stop = hard_stop or threading.Event()
        self.job_id = ""
        self._lock = threading.Lock()
        self._mem: dict = self._blank()

    @staticmethod
    def _blank() -> dict:
        """The idle state: no job, no step, no child."""
        return {"busy": False, "job_id": None, "step": None, "step_started": None,
                "child_pid": None, "child_start": None}

    def snapshot(self) -> dict:
        """A consistent copy of the in-memory state, for the watchdog thread."""
        with self._lock:
            return dict(self._mem, slot=self.slot)

    def begin(self, job_id: str) -> None:
        """The slot claimed a job: busy from now, so a hang before the first step is also noticed."""
        with self._lock:
            self._mem = {**self._blank(), "busy": True, "job_id": job_id, "step": "claimed",
                         "step_started": time.time()}

    def end(self) -> None:
        """The slot is idle again."""
        with self._lock:
            self._mem = self._blank()

    def step(self, name: str) -> None:
        """Record which step the slot is in and since when (the watchdog measures each step)."""
        with self._lock:
            self._mem.update(step=name, step_started=time.time(), child_pid=None, child_start=None)
        if self.store is not None and self.slot:
            try:  # the row is for the System page only: a database error must not cost the job (C-6)
                self.store.put_worker(self.slot, step=name, step_started=time.time(),
                                      child_pid=None, child_start=None)
            except sqlite3.Error as exc:
                log.warning("worker: %s could not record step %s: %s", self.slot, name, exc)

    def on_spawn(self, pid: int) -> None:
        """Record the npcapextract process so a later worker can kill it if this one dies.

        A database error is only logged: it must not abort the extraction and leave a root process
        running, and the in-memory record (what the watchdog uses) is already made.
        """
        start = proc_start(pid)
        with self._lock:
            self._mem.update(child_pid=pid, child_start=start)
        if self.store is not None and self.slot:
            try:
                self.store.put_worker(self.slot, child_pid=pid, child_start=start)
            except sqlite3.Error as exc:
                log.warning("worker: %s could not record npcapextract pid %d: %s", self.slot, pid, exc)

    def should_stop(self) -> str | None:
        """"stop" when the worker's grace is over, "cancel" when an operator cancelled this job.

        A database error counts as "no request": the next poll asks again.
        """
        if self.hard_stop.is_set():
            return "stop"
        if self.store is not None and self.job_id:
            try:
                if self.store.cancel_requested(self.job_id):
                    return "cancel"
            except sqlite3.Error as exc:
                log.warning("worker: %s could not poll for a cancel request: %s", self.slot, exc)
        return None


def run_one(store: JobStore, settings: Settings, job: dict, ctx: JobCtx | None = None) -> None:
    """Execute one claimed job and record success, a retry, a cancel, or a final failure."""
    ctx = ctx or JobCtx(store)
    ctx.job_id = job["id"]
    attempts = job["attempts"] + 1
    bad = validate_job_row(job, settings)
    if bad:
        log.error("job %s refused: %s", job["id"], bad)
        store.finish(job["id"], FAILED, f"invalid job row: {bad}", attempts, counters=("failed",))
        return
    stored = plan_from_job(job)
    ctx.step("wait_disk")
    closed, newest = window_on_disk(stored, settings, ctx.newest)
    if not closed:
        waited = time.time() - job["ready_at"]
        if waited < settings.quiet_wait_seconds:
            when = time.strftime("%H:%M:%S", time.localtime(newest))
            _record_or_hand_back("the deferral", job["id"], store.defer, job["id"],
                                 time.time() + settings.quiet_poll_seconds,
                                 f"{WAITING} n2disk has not written past the window end ({stored.end}); the "
                                 f"newest file starts {when}. It closes a file when the next packet arrives, "
                                 f"so a quiet link delays this")
            return
        _note(store, job["id"], attempts,
              f"no file past the window end after waiting {int(waited)} s: extracting anyway")
    plan = widened_plan(stored, attempts, settings)
    if plan.begin != stored.begin:
        _note(store, job["id"], attempts,
              f"looking back further on this attempt: window starts {plan.begin} "
              f"(was {stored.begin})")
    ctx.step("extract")
    try:
        result = execute_plan(plan, settings, should_stop=ctx.should_stop, on_spawn=ctx.on_spawn)
    except Exception as exc:  # never lose the job to an unexpected error
        log.exception("job %s crashed", job["id"])
        _retry_or_fail(store, settings, job["id"], attempts, f"internal error: {exc!r}", FAILED,
                       counters=("failed",))
        return
    if result.kind is Kind.CANCELLED:
        _record_or_hand_back("the cancel", job["id"], store.cancelled, job["id"], attempts,
                             "cancelled by operator while extracting")
        return
    if result.kind is Kind.INTERRUPTED:
        _record_or_hand_back("the interruption", job["id"], store.interrupt, job["id"],
                             "the worker stopped during the extraction; queued again")
        return
    if result.kind is Kind.SUCCESS:
        _finish_success(store, settings, job, stored, plan, attempts, ctx)
        return
    final = MISS if result.kind is Kind.MISS else FAILED
    reason = {
        Kind.MISS: "no packets matched the alert's flow in the time window",
        Kind.TIMEOUT: f"npcapextract timed out after {settings.extract_timeout_seconds}s",
        Kind.DISK_LOW: "not enough free disk space for the output",
    }.get(result.kind, "npcapextract failed (see the worker log for rc and stderr)")
    _retry_or_fail(store, settings, job["id"], attempts, f"{result.kind.value}: {reason}", final,
                   counters=(result.kind.value,))


def _finish_success(store: JobStore, settings: Settings, job: dict, stored: Plan, plan: Plan,
                    attempts: int, ctx: JobCtx) -> None:
    """Done, after widening the window while the first packet sits at its start (keeps the larger file).

    `stored` is the job's own window, `plan` the one this attempt ran (widened_plan of `stored`);
    each wider step is again widened_plan of `stored`, one look-back step further.

    A soft stop ends the widening with the file we have; a cancel or hard stop during a wider
    re-extraction keeps the first file on disk (evidence) and lets the store decide the state.
    """
    try:
        size = os.path.getsize(plan.output_path)
    except OSError:
        size = None
    warning = window_warning(plan, settings)
    step = attempts
    while warning and not ctx.soft_stop.is_set():
        # The first packet sits at the window start: more may lie before it. Extract again with a
        # wider window and keep the larger file; stop at the cap or when nothing grows.
        wider = wider_than(stored, step, settings)
        if wider is None:
            break
        tmp = plan.output_path + ".wide"
        ctx.step("widen")
        res = execute_plan(replace(wider, output_path=tmp), settings,
                           should_stop=ctx.should_stop, on_spawn=ctx.on_spawn)
        try:
            bigger = res.kind is Kind.SUCCESS and os.path.getsize(tmp) > (size or 0)
        except OSError:
            bigger = False
        if not bigger:
            _remove_quietly(tmp)
            break
        os.replace(tmp, plan.output_path)
        size, plan, step = os.path.getsize(plan.output_path), wider, step + 1
        _note(store, job["id"], attempts,
              f"first packet was at the window start: extracted again from {plan.begin} "
              f"(look-back {lag_for_attempt(step, settings)} s), file grew to {size} bytes")
        warning = window_warning(plan, settings)
    ctx.step("finish")
    if warning:
        log.warning("job %s: %s", job["id"], warning)
    counters = ("success", "window_warning") if warning else ("success",)
    info = pcap_summary(plan.output_path)
    _record_or_hand_back("done (the PCAP is in place)", job["id"], store.finish, job["id"], DONE, warning,
                         attempts, size=size, counters=counters, info=info)


def _note(store: JobStore, job_id: str, attempt: int, detail: str) -> None:
    """A progress row in the job's history; a database error is logged and the job goes on (C-6)."""
    try:
        store.note(job_id, "window", attempt, detail)
    except sqlite3.Error as exc:
        log.warning("job %s: could not record a progress note (%s): %s", job_id, exc, detail)


def _record_or_hand_back(what: str, job_id: str, transition, *args, **kwargs) -> None:
    """A transition that uses no attempt (done, deferral, cancel, interruption). A database error must
    not cost the job an attempt (C-6): it is logged and the job is left `running`, for the worker's slot
    to hand back to the queue without using one (worker._release_job, else the worker's reconcile).
    The job then runs again: a done job's PCAP is extracted again and replaced."""
    try:
        transition(*args, **kwargs)
    except sqlite3.Error as exc:
        log.error("job %s: could not record %s: %s; the job is queued again without using an attempt",
                  job_id, what, exc)


def _retry_or_fail(
    store: JobStore, settings: Settings, job_id: str, attempts: int, detail: str, final: str,
    counters: tuple = (),
) -> None:
    """Queue another attempt while any are left, else end the job in `final`; counted either way."""
    if attempts < settings.job_max_attempts:
        log.warning("job %s attempt %d/%d failed (%s); retrying in %ds",
                    job_id, attempts, settings.job_max_attempts, detail,
                    settings.job_retry_delay_seconds)
        store.retry(job_id, time.time() + settings.job_retry_delay_seconds, detail, attempts,
                    counters=counters)
    else:
        log.error("job %s gave up after %d attempts (%s)", job_id, attempts, detail)
        store.finish(job_id, final, detail, attempts, counters=counters)
