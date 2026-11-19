"""The worker process: claims due jobs and owns every npcapextract (`python -m sycope_recorder worker`).

Runs as root next to the web (user sr) in the api container, both under supervisord. The two share
only the job database (store.py): the web adds jobs and operator requests, the worker polls them.

Threads:
- main: heartbeat, control (pause shown, configuration reload), watchdog of the slots;
- housekeeping: self-checks into the database, prune, retention, the "no webhook" warning;
- slot-0..N-1: claim -> run_one -> idle.

Startup cleans up after a predecessor that died hard (SIGKILL, OOM, watchdog): it takes worker.lock
(one worker per state directory), kills npcapextract processes the predecessor recorded (only when
PID, start time and command line all match), removes their temporary files and queues their jobs
again (a job found running that way MAX_RECOVERIES times in a row ends failed: store.recover).
Errors that may pass (database locked, directory missing) are retried inside the process, so
supervisord never sees a crash loop and never gives up.

Exit codes: 0 stopped or reloading (supervisord starts it again with the new configuration),
70 a slot hung (supervisord restarts it, startup cleans up), 1 slots did not stop after the hard stop.
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import signal
import sqlite3
import sys
import threading
import time

from sycope_recorder import __version__
from sycope_recorder import checks as checks_mod
from sycope_recorder.bundle import npcapextract_info
from sycope_recorder.checks import HUNG_MARGIN  # noqa: F401  (tests patch worker.HUNG_MARGIN)
from sycope_recorder.config import Settings, get_settings, legacy_env_warnings
from sycope_recorder.jobs import FAILED, JobCtx, _retry_or_fail, run_one
from sycope_recorder.logging_config import setup_logging
from sycope_recorder.procs import kill_group, proc_cmdline, proc_start
from sycope_recorder.extraction import NewestStart, rolling_snapshot
from sycope_recorder.retention import PART, sweep
from sycope_recorder.store import (
    MAIN_SLOT, META_LAST_WEBHOOK, META_NPCAPEXTRACT_INFO, META_WORKER_STARTED, META_WORKER_VERSION, RUNNING,
    WORKER_BUSY, WORKER_ERROR, WORKER_IDLE, WORKER_PAUSED, WORKER_RUNNING, WORKER_STOPPING, JobStore, db_path,
)
from sycope_recorder.system import ROLLING_META, rolling_interval

log = logging.getLogger("sycope_recorder")

TICK = 1.0
IDLE_WAIT = 2.0
RELEASE_BACKOFF = (0.2, 0.5, 1.0)   # pauses between attempts to hand a job back from a failing slot
RECONCILE_GRACE = 30.0              # a claim younger than this may not have reached its slot's memory yet
EXIT_OK, EXIT_HUNG, EXIT_STUCK = 0, 70, 1
LOCK_NAME = "worker.lock"           # in the state directory: one worker per database
NEWEST_MAX_AGE = 5.0                # seconds the slots reuse one listing of the newest rolling directory


def kill_orphans(store: JobStore, settings: Settings) -> int:
    """Kill npcapextract groups recorded by a previous worker that are still running."""
    binary = os.path.basename(settings.npcapextract_path)
    n = 0
    for r in store.workers():
        pid, start = r.get("child_pid"), r.get("child_start")
        if not pid or start is None or proc_start(pid) != start or binary not in proc_cmdline(pid):
            continue
        log.warning("worker: killing npcapextract left by the previous worker (pid %d, %s, job %s)",
                    pid, r["slot"], r.get("job_id"))
        kill_group(pid)
        n += 1
    return n


def remove_parts(output_dir: str) -> int:
    """Delete temporary npcapextract outputs; called only when no worker is running."""
    n = 0
    try:
        names = os.listdir(output_dir)
    except OSError:
        return 0
    for name in names:
        if PART.search(name) or name.endswith(".pcap.wide"):
            try:
                os.remove(os.path.join(output_dir, name))
                n += 1
            except OSError:
                pass
    return n


class Worker:
    """One worker process's state; `run()` returns the exit code."""

    def __init__(self, settings: Settings, stop: threading.Event | None = None, exit_fn=os._exit) -> None:
        """exit_fn is injectable so tests can observe the hard exits without killing pytest."""
        self.settings = settings
        self.stop = stop or threading.Event()   # soft stop: signal, reload, test
        self.hard = threading.Event()           # grace over: kill running extractions
        self.reason = ""
        self.store: JobStore | None = None
        self._lock_fd: int | None = None
        self._exit = exit_fn
        self._slots: dict[str, threading.Thread] = {}
        # What each slot is doing, in this process's memory. The watchdog and the kill on a hang use
        # only this: the `workers` rows are writable by the web (user sr) and root must not act on them.
        self._ctxs: dict[str, JobCtx] = {}
        self._house: threading.Thread | None = None
        # One listing of the newest rolling directory, shared by the slots (claim holds, readiness checks).
        self._newest = NewestStart(settings.timeline_dir, NEWEST_MAX_AGE)
        self.generation = 0
        self.rc = None

    # ---- startup

    def _retry(self, what: str, fn):
        """Run fn until it succeeds or a stop is requested (None when stopped first): startup must survive
        a locked database or a missing directory, or supervisord would crash-loop. Only the holder of
        worker.lock writes the `main` row: a standby waiting for the lock must not overwrite the live
        worker's pid and state, so it logs its complaint and nothing more."""
        delay = 1.0
        while not self.stop.is_set():
            try:
                return fn()
            except Exception as exc:
                log.error("worker: %s failed: %s; retrying in %d s", what, exc, delay)
                if self.store is not None and self._lock_fd is not None:
                    try:
                        self.store.put_worker(MAIN_SLOT, pid=os.getpid(), heartbeat=time.time(), state=WORKER_ERROR,
                                              detail=f"{what}: {exc}")
                    except Exception:
                        pass
                self.stop.wait(delay)
                delay = min(delay * 2, 60.0)
        return None

    def _open_store(self) -> JobStore:
        """Open the database, but never as long as a file of it is a symlink: this process is root and the
        web (sr) can write the directory, so a planted link would make SQLite write wherever it points."""
        base = db_path(self.settings.state_dir)
        for name in (base, base + "-wal", base + "-shm", base + ".lock",
                     os.path.join(self.settings.state_dir, LOCK_NAME)):
            if os.path.islink(name):
                raise RuntimeError(f"{name} is a symbolic link: refusing to use it (remove it)")
        return JobStore(base)

    def _take_lock(self) -> bool:
        """One worker per state directory: a second one would re-queue the first one's jobs."""
        fd = os.open(os.path.join(self.settings.state_dir, LOCK_NAME),
                     os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o664)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise RuntimeError("another worker is running (worker.lock is held)") from None
        self._lock_fd = fd
        return True

    def _slot_names(self) -> list[str]:
        """Slot names are the keys of the workers table, so the System page and the watchdog share them."""
        return [f"slot-{i}" for i in range(self.settings.max_concurrent_extractions)]

    def _cleanup_and_register(self) -> bool:
        """Cleanup after the predecessor and registration of this worker; every step is idempotent, so a
        transient failure (database locked) is retried as a whole while the lock is held."""
        s = self.settings
        # Before worker_started: whoever sees that marker and bumps the generation must be noticed.
        self.generation = self.store.config_generation()
        killed = kill_orphans(self.store, s)
        removed = remove_parts(s.output_dir)
        recovered = self.store.recover()
        if killed or removed or recovered:
            log.warning("worker: cleaned up after the previous worker: %d npcapextract killed, %d temporary "
                        "file(s) removed, %d job(s) queued again", killed, removed, recovered)
        now = time.time()
        blank = dict(job_id=None, step=None, step_started=None, child_pid=None, child_start=None, detail="")
        self.store.drop_workers(keep=[MAIN_SLOT, *self._slot_names()])
        self.store.put_worker(MAIN_SLOT, pid=os.getpid(), pid_start=proc_start(os.getpid()), heartbeat=now,
                              state=WORKER_RUNNING, **blank)
        for name in self._slot_names():
            self.store.put_worker(name, pid=os.getpid(), heartbeat=now, state=WORKER_IDLE, **blank)
        self.store.set_meta(META_WORKER_STARTED, str(now))
        self.store.set_meta(META_WORKER_VERSION, __version__)
        self.store.set_meta(META_NPCAPEXTRACT_INFO, npcapextract_info(s))
        return True

    def _startup(self) -> bool:
        """Clean up after a predecessor that died hard before any slot may claim a job; False if stopped first."""
        self.store = self._retry("opening the job database", self._open_store)
        if self.store is None or self._retry("taking worker.lock", self._take_lock) is None:
            return False
        if self._retry("startup cleanup", self._cleanup_and_register) is None:
            return False
        for w in legacy_env_warnings():
            log.warning(w)
        log.info("worker: started (pid %d, %d slot(s), configuration generation %d)",
                 os.getpid(), len(self._slot_names()), self.generation)
        return True

    # ---- threads

    def _idle(self, name: str) -> None:
        """Clear the slot's row after every job so the System page never shows a finished one as busy."""
        try:
            self.store.put_worker(name, state=WORKER_IDLE, job_id=None, step=None, step_started=None,
                                  child_pid=None, child_start=None, heartbeat=time.time())
        except Exception:
            log.exception("worker: %s could not record idle", name)

    def _release_job(self, name: str, job_id: str) -> None:
        """Last line of defence of a slot: a job it claimed must not stay `running` with nobody on it.

        Normally run_one has already moved the job out of `running`; when finish/retry both failed
        (database locked for too long), or run_one could not record a transition that uses no attempt
        (jobs._record_or_hand_back), it is still ours, and an idle slot with a running job would
        hold it forever. Hand it back, a few times, since the cause is usually a busy database.
        """
        for pause in (0.0, *RELEASE_BACKOFF):
            if pause:
                time.sleep(pause)
            try:
                row = self.store.get(job_id)
                if row is None or row["state"] != RUNNING or row["claimed_by"] != name:
                    return
                if self.store.interrupt(job_id, f"{name} ended without recording the outcome; "
                                                "queued again", claimed_by=name):
                    log.warning("job %s: %s left it running; queued again", job_id, name)
                return
            except Exception:
                log.exception("job %s: could not release it from %s", job_id, name)
        log.error("job %s: still marked running after %s ended; the worker's check will queue it", job_id, name)

    def _hold(self, now: float) -> tuple[float, float, float] | None:
        """What `claim` needs to leave still-waiting jobs in the queue (E-1), or None.

        Only when a waiting job is due for its check: then the newest rolling file is listed once (shared
        by the slots for NEWEST_MAX_AGE) and every waiting job whose window end it has not passed gets its
        next check time in the claim's transaction, without a claim of its own. An unknown start holds
        nothing: run_one extracts such jobs, as before.
        """
        s = self.settings
        if not s.rolling_check or not self.store.waiting_due(now):
            return None
        newest = self._newest.get()
        if newest is None:
            return None
        return newest, float(s.quiet_wait_seconds), now + s.quiet_poll_seconds

    def _slot(self, name: str) -> None:
        """One extraction slot; an unexpected error fails the job but must never end the slot."""
        ctx = self._ctxs[name] = JobCtx(self.store, name, soft_stop=self.stop, hard_stop=self.hard,
                                        newest=self._newest)
        while not self.stop.is_set():
            try:
                now = time.time()
                job = self.store.claim(now, slot=name, hold=self._hold(now))
            except Exception:
                log.exception("worker: %s could not claim a job", name)
                job = None
            if job is None:
                self.stop.wait(IDLE_WAIT)
                continue
            ctx.begin(job["id"])
            try:
                try:  # the row is for the System page only: a database error must not cost the job (C-6)
                    self.store.put_worker(name, state=WORKER_BUSY, job_id=job["id"], step="claimed",
                                          step_started=time.time(), heartbeat=time.time())
                except sqlite3.Error as exc:
                    log.warning("worker: %s could not record job %s as busy: %s", name, job["id"], exc)
                run_one(self.store, self.settings, job, ctx)
            except Exception as exc:
                log.exception("job %s: unexpected error in %s", job["id"], name)
                try:
                    _retry_or_fail(self.store, self.settings, job["id"], job["attempts"] + 1,
                                   f"internal error: {exc!r}", FAILED, counters=("failed",))
                except Exception:
                    log.exception("job %s: could not record the error", job["id"])
            finally:
                self._release_job(name, job["id"])
                ctx.end()
                self._idle(name)

    def _start_slot(self, name: str) -> None:
        """Start (or restart, after an unexpected death) the thread of one slot."""
        t = threading.Thread(target=self._slot, args=(name,), name=name, daemon=True)
        self._slots[name] = t
        t.start()

    def _housekeeping(self) -> None:
        """Slow periodic work in its own thread so a slow disk cannot delay heartbeats or claims."""
        s = self.settings
        next_checks = next_prune = next_retention = next_rolling = 0.0
        previous: dict[str, str] = {}
        while not self.stop.is_set():
            now = time.time()
            if now >= next_checks:
                next_checks = now + s.watchdog_interval_seconds
                try:
                    results = checks_mod.run_checks(s)
                    self.store.save_checks(results, now)
                    for c in results:
                        if previous.get(c.name) != c.status:
                            level = {"ok": logging.INFO, "warn": logging.WARNING, "fail": logging.ERROR}[c.status]
                            log.log(level, "CHECK %s: %s - %s", c.name, c.status.upper(), c.detail)
                        previous[c.name] = c.status
                    if s.silence_warn_hours > 0:
                        last = float(self.store.get_meta(META_LAST_WEBHOOK) or self.store.get_meta(META_WORKER_STARTED) or now)
                        if now - last > s.silence_warn_hours * 3600:
                            log.warning("no webhook received for over %dh although the service is up",
                                        s.silence_warn_hours)
                except Exception:
                    log.exception("worker: self-checks failed")
            if now >= next_rolling:
                # Only root can list n2disk's directories: the web shows this report instead. A full scan
                # of a large buffer is expensive and a new file appears once per chunk, so it has its own,
                # slower interval (the report carries it, so the web can tell a stale one).
                interval = rolling_interval(s)
                next_rolling = now + interval
                try:
                    report = rolling_snapshot(s.timeline_dir, now)
                    self.store.set_meta(ROLLING_META, json.dumps({**report, "interval": interval}))
                except Exception:
                    log.exception("worker: rolling capture summary failed")
            if now >= next_prune:
                next_prune = now + 3600
                try:
                    cutoff = now - s.job_history_days * 86400
                    n, e = self.store.prune(cutoff), self.store.prune_events(cutoff)
                    if n or e:
                        log.info("jobs: pruned %d old job record(s), %d event(s)", n, e)
                except Exception:
                    log.exception("worker: job prune failed")
            if now >= next_retention:
                next_retention = now + s.retention_interval_seconds
                if s.retention_max_age_days > 0 or s.retention_max_total_bytes > 0:
                    try:
                        # Without the list of persistent files nothing is deleted: the sweep is skipped.
                        sweep(s, self.store.persistent_files(), now)
                    except Exception as exc:
                        log.warning("retention sweep skipped: %s", exc)
            self.stop.wait(TICK)

    # ---- main loop

    def _hung(self, now: float) -> dict | None:
        """The first busy slot whose current step outlived the extraction timeout plus HUNG_MARGIN.

        Measured on the slots' in-memory state, never on `workers` rows: the web can write those, and
        a forged "busy since 1970" row would make the root worker exit (70) on demand.
        """
        limit = self.settings.extract_timeout_seconds + sys.modules[__name__].HUNG_MARGIN
        for ctx in list(self._ctxs.values()):
            snap = ctx.snapshot()
            if snap["busy"] and snap["step_started"] and now - snap["step_started"] > limit:
                return snap
        return None

    def _die_hung(self, r: dict) -> int:
        """A thread cannot be killed: exit the process so supervisord restarts it and startup cleans up.

        Kills only the npcapextract processes this process started (its own memory of their pid and
        start time), never a pid read from the database.
        """
        log.critical("worker: %s stuck in step %s of job %s for %d s: exiting so supervisord restarts the "
                     "worker", r["slot"], r.get("step"), r.get("job_id"), int(time.time() - r["step_started"]))
        for ctx in list(self._ctxs.values()):
            snap = ctx.snapshot()
            pid, start = snap["child_pid"], snap["child_start"]
            if pid and start is not None and proc_start(pid) == start:
                kill_group(pid, grace=0)
        logging.shutdown()
        self._exit(EXIT_HUNG)
        self.stop.set()
        return EXIT_HUNG

    def _reconcile(self, now: float) -> None:
        """Queue again any `running` job that no slot of this process is working on.

        A job can be left that way when a slot's finish, retry and fallback all failed, or by a
        claim whose slot died. Ownership is this process's memory, not the `workers` rows; a claim
        younger than RECONCILE_GRACE may not have reached its slot's memory yet and is left alone.
        """
        owned = {snap["job_id"] for snap in (c.snapshot() for c in list(self._ctxs.values())) if snap["busy"]}
        for row in self.store.running_jobs():
            if row["id"] in owned or now - (row["claimed_at"] or 0) < RECONCILE_GRACE:
                continue
            if self.store.interrupt(row["id"], f"no slot was running this job (claimed by "
                                               f"{row['claimed_by'] or '?'}); queued again",
                                    claimed_by=row["claimed_by"]):
                log.warning("worker: job %s was running without a slot; queued again", row["id"])

    def run(self) -> int:
        """Start, loop until a stop or reload, drain; the exit code."""
        if not self._startup():
            return self._release(EXIT_OK)
        self._house = threading.Thread(target=self._housekeeping, name="housekeeping", daemon=True)
        self._house.start()
        for name in self._slot_names():
            self._start_slot(name)
        last_beat = 0.0
        while not self.stop.is_set():
            now = time.time()
            if now - last_beat >= self.settings.worker_heartbeat_seconds:
                last_beat = now
                try:
                    paused = self.store.paused()
                    self.store.put_worker(MAIN_SLOT, heartbeat=now, state=WORKER_PAUSED if paused else WORKER_RUNNING,
                                          detail="")
                    gen = self.store.config_generation()
                    if gen != self.generation:
                        log.warning("worker: configuration changed (generation %d -> %d): reloading",
                                    self.generation, gen)
                        self.reason = "reload"
                        self.stop.set()
                        break
                    hung = self._hung(now)
                    if hung is not None:
                        return self._die_hung(hung)
                    self._reconcile(now)
                except Exception:
                    log.exception("worker: heartbeat/control failed")
            for name, t in list(self._slots.items()):
                if not t.is_alive() and not self.stop.is_set():
                    log.error("worker: %s thread ended unexpectedly; starting it again", name)
                    self._start_slot(name)
            self.stop.wait(TICK)
        return self._drain()

    def _drain(self) -> int:
        """Let running jobs finish within the grace period, then stop their extractions and re-queue them."""
        grace = self.settings.worker_stop_grace_seconds
        self.reason = self.reason or "signal"
        log.info("worker: stopping (%s): running jobs may finish for up to %d s", self.reason, grace)
        try:
            self.store.put_worker(MAIN_SLOT, state=WORKER_STOPPING, heartbeat=time.time())
        except Exception:
            pass
        deadline = time.monotonic() + grace
        for t in self._slots.values():
            t.join(max(0.0, deadline - time.monotonic()))
        if any(t.is_alive() for t in self._slots.values()):
            log.warning("worker: grace over: stopping running extractions, their jobs go back to the queue")
            self.hard.set()
            deadline = time.monotonic() + 10
            for t in self._slots.values():
                t.join(max(0.0, deadline - time.monotonic()))
            if any(t.is_alive() for t in self._slots.values()):
                log.error("worker: a slot did not stop (I/O hung?): exiting hard")
                logging.shutdown()
                self._exit(EXIT_STUCK)
                return EXIT_STUCK
        if self._house is not None:
            self._house.join(5)
        return self._release(EXIT_OK)

    def _release(self, code: int) -> int:
        """Drop worker.lock and close the database; the exit code passes through."""
        if self._lock_fd is not None:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                os.close(self._lock_fd)
            except OSError:
                pass
            self._lock_fd = None
        if self.store is not None:
            self.store.close()
        return code


def main() -> int:
    """Entry point of `python -m sycope_recorder worker` (supervisord program `worker`)."""
    os.umask(0o002)
    settings = get_settings()
    setup_logging(settings, "worker")
    stop = threading.Event()
    worker = Worker(settings, stop)

    def on_signal(signum, _frame):
        log.info("worker: signal %d received", signum)
        worker.reason = worker.reason or "signal"
        stop.set()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    return worker.run()
