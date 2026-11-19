"""SQLite job queue shared by the web and the worker process; the only module with SQL.

Two processes use one database file: the web (non-root, many threadpool threads) adds jobs, reads
them and records operator requests; the worker (root, N slot threads) claims and finishes them.
So every thread has its own connection, every state change is one conditional UPDATE inside
BEGIN IMMEDIATE (an UPDATE that matches no row changes nothing: whoever comes second loses
cleanly), and a change's history event is written in the same transaction.

Opening runs under an exclusive flock on `<db>.lock`, in both processes, so a database of an older
release can be moved aside without the other process holding it open. Upgrades from 0.3 are clean
installs: that database is moved aside, never migrated and never deleted. A schema-4 database
(0.4 before the persistent flag) is migrated in place, because it holds the job history.
"""

from __future__ import annotations

import fcntl
import ipaddress
import json
import logging
import os
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Iterable, Iterator

from sycope_recorder.extraction import Plan

log = logging.getLogger("sycope_recorder")

SCHEMA_VERSION = 6
QUEUED, RUNNING, DONE, MISS, FAILED, CANCELLED = (
    "queued", "running", "done", "miss", "failed", "cancelled")
STATES = (QUEUED, RUNNING, DONE, MISS, FAILED, CANCELLED)
FINAL = (DONE, MISS, FAILED, CANCELLED)
RETRYABLE = (MISS, FAILED, CANCELLED)
WAITING = "waiting:"  # detail prefix of a due job whose data is not on disk yet
# history events (job_events.state) besides the job states; the values are stored and read by the pages
EVENT_RECOVERED, EVENT_REDELIVERED, EVENT_WAITING, EVENT_RETRY, EVENT_INTERRUPTED = (
    "recovered", "redelivered", "waiting", "retry", "interrupted")
EVENT_CANCEL_REQUESTED, EVENT_CANCEL_IGNORED, EVENT_REEXTRACT = (
    "cancel_requested", "cancel_ignored", "reextract")
# control table keys (web -> worker)
CONTROL_PAUSED, CONTROL_CONFIG_GENERATION = "paused", "config_generation"
# workers table: the worker's own row, and the values of workers.state (main: running/paused/stopping/
# error; a slot: idle/busy). WORKER_RUNNING is a worker row state, not the job state RUNNING.
MAIN_SLOT = "main"
WORKER_IDLE, WORKER_BUSY, WORKER_RUNNING, WORKER_PAUSED, WORKER_STOPPING, WORKER_ERROR = (
    "idle", "busy", "running", "paused", "stopping", "error")
# meta table keys (each process writes its own; stats.py and the pages read them)
META_DB_CREATED, META_WEB_STARTED, META_WORKER_STARTED, META_WORKER_VERSION = (
    "db_created", "web_started", "worker_started", "worker_version")
META_NPCAPEXTRACT_INFO, META_LAST_WEBHOOK, META_LAST_SUCCESS = (
    "npcapextract_info", "last_webhook", "last_success")
_CANCELLED_BY_OPERATOR = "cancelled by operator"  # detail of a job the operator cancelled
# Crash recovery (C-10): a job found `running` at worker start this many times in a row ends `failed`.
# "In a row" restarts at any of these events: a fresh start (queued, an operator's or the worker's
# retry), a graceful hand-back (interrupted), a deferral (waiting) or a final state.
MAX_RECOVERIES = 3
_RECOVERY_RESET = (QUEUED, EVENT_RETRY, EVENT_INTERRUPTED, EVENT_WAITING, DONE, MISS, FAILED, CANCELLED)
_ID_BATCH = 500  # ids per IN (...) list, well below SQLite's bound-parameter limit

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL DEFAULT '',
    alert_key TEXT NOT NULL DEFAULT '',
    alert_meta TEXT NOT NULL DEFAULT '',
    bpf TEXT NOT NULL,
    window_begin TEXT NOT NULL,
    window_end TEXT NOT NULL,
    window_end_epoch REAL NOT NULL,
    output_path TEXT NOT NULL,
    url TEXT NOT NULL DEFAULT '',
    ready_at REAL NOT NULL,
    next_at REAL NOT NULL,
    state TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    detail TEXT NOT NULL DEFAULT '',
    created REAL NOT NULL,
    updated REAL NOT NULL,
    persistent INTEGER NOT NULL DEFAULT 0,
    pcap_bytes INTEGER,
    origin TEXT NOT NULL DEFAULT 'webhook',
    parent_id TEXT NOT NULL DEFAULT '',
    pcap_info TEXT NOT NULL DEFAULT '',
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    claimed_by TEXT NOT NULL DEFAULT '',
    claimed_at REAL
);
CREATE INDEX IF NOT EXISTS jobs_state_next ON jobs(state, next_at);
CREATE INDEX IF NOT EXISTS jobs_alert_key ON jobs(alert_key);
CREATE INDEX IF NOT EXISTS jobs_persistent ON jobs(persistent);
CREATE TABLE IF NOT EXISTS job_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    alert_id TEXT NOT NULL,
    ts REAL NOT NULL,
    state TEXT NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 0,
    detail TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    bytes INTEGER
);
CREATE INDEX IF NOT EXISTS job_events_job ON job_events(job_id, id);
CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL, since REAL NOT NULL);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated REAL NOT NULL);
CREATE TABLE IF NOT EXISTS control (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated REAL NOT NULL,
                                    by TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS workers (
    slot TEXT PRIMARY KEY, pid INTEGER, pid_start INTEGER, heartbeat REAL, state TEXT,
    job_id TEXT, step TEXT, step_started REAL, child_pid INTEGER, child_start INTEGER, detail TEXT
);
CREATE TABLE IF NOT EXISTS checks (name TEXT PRIMARY KEY, status TEXT NOT NULL, detail TEXT NOT NULL,
                                   ts REAL NOT NULL);
"""


class SchemaTooNew(RuntimeError):
    """The database was written by a newer release (image downgrade): refuse to touch it."""


def _chunks(ids: list[str], n: int = _ID_BATCH) -> Iterator[list[str]]:
    """Consecutive slices of at most n ids."""
    for i in range(0, len(ids), n):
        yield ids[i:i + n]


def _pcap_on_disk(path: str) -> bool:
    """A non-empty file at `path` (what the alert link would serve)."""
    try:
        return os.path.isfile(path) and os.path.getsize(path) > 0
    except OSError:
        return False


def db_path(state_dir: str) -> str:
    """Where both processes find the job database."""
    return os.path.join(state_dir, "jobs.db")


@contextmanager
def _file_lock(path: str) -> Iterator[None]:
    """Exclusive flock for the open/initialise step; released by the kernel if the process dies."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o664)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _migrate_4_to_5(path: str) -> None:
    """Schema 4 -> 5 in one transaction: important -> persistent, and the PCAP size in the row.

    `pcap_bytes` is filled from the last `done` event that has a size, so the filter and the sort can
    use it without touching the disk. The caller holds the open lock. Either everything is applied or
    nothing (the schema is DDL in SQLite's transactional journal), so a crash leaves a version-4 file.
    """
    con = sqlite3.connect(path, isolation_level=None)
    try:
        con.execute("BEGIN IMMEDIATE")
        try:
            con.execute("ALTER TABLE jobs RENAME COLUMN important TO persistent")
            con.execute("DROP INDEX IF EXISTS jobs_important")
            con.execute("CREATE INDEX IF NOT EXISTS jobs_persistent ON jobs(persistent)")
            con.execute("ALTER TABLE jobs ADD COLUMN pcap_bytes INTEGER")
            con.execute(
                "UPDATE jobs SET pcap_bytes=(SELECT e.bytes FROM job_events e WHERE e.job_id=jobs.id"
                " AND e.state='done' AND e.bytes IS NOT NULL ORDER BY e.id DESC LIMIT 1)"
                " WHERE state='done'")
            con.execute("PRAGMA user_version=5")
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
    finally:
        con.close()
    log.info("jobs: database migrated from schema 4 to 5 (important is now persistent)")


def _migrate_5_to_6(path: str) -> None:
    """Schema 5 -> 6 in one transaction: where a job came from (webhook or an operator's re-extract, and
    of which job) and the extracted file's summary (packets, first and last packet). Old rows are
    webhook jobs without a summary; nothing is measured again."""
    con = sqlite3.connect(path, isolation_level=None)
    try:
        con.execute("BEGIN IMMEDIATE")
        try:
            con.execute("ALTER TABLE jobs ADD COLUMN origin TEXT NOT NULL DEFAULT 'webhook'")
            con.execute("ALTER TABLE jobs ADD COLUMN parent_id TEXT NOT NULL DEFAULT ''")
            con.execute("ALTER TABLE jobs ADD COLUMN pcap_info TEXT NOT NULL DEFAULT ''")
            con.execute("PRAGMA user_version=6")
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise
    finally:
        con.close()
    log.info("jobs: database migrated from schema 5 to 6 (re-extract origin, PCAP summary)")


def _init_db(path: str) -> None:
    """Create, accept, or move aside the database at `path`. The caller holds the open lock."""
    if os.path.exists(path):
        con = sqlite3.connect(path)
        try:
            version = con.execute("PRAGMA user_version").fetchone()[0]
        finally:
            con.close()
        if version == SCHEMA_VERSION:
            return
        if version in (4, 5):
            if version == 4:
                _migrate_4_to_5(path)
            _migrate_5_to_6(path)
            return
        if version > SCHEMA_VERSION:
            raise SchemaTooNew(f"{path} has schema {version}; this release understands {SCHEMA_VERSION}")
        aside = f"{path}.0.3-{time.strftime('%Y%m%d-%H%M%S')}"
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(path + suffix):
                os.replace(path + suffix, aside + suffix)
        log.warning("jobs: database of an earlier release moved aside to %s; the queue starts empty", aside)
    if not os.path.exists(path):
        # SQLite creates the file 0644 whatever the umask, and gives -wal/-shm the same mode: the web
        # (group sr) could then not write them. Create it first with 0664 (minus umask).
        os.close(os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o664))
    con = sqlite3.connect(path, isolation_level=None)
    try:
        con.execute("PRAGMA journal_mode=WAL")
        con.executescript(_SCHEMA)
        now = time.time()
        con.execute("INSERT OR IGNORE INTO meta VALUES (?, ?, ?)", (META_DB_CREATED, str(now), now))
        con.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
    finally:
        con.close()


# Quick filter ("Search" on the queue page): free text, whitespace-separated tokens ANDed, a double-quoted
# phrase is one token, case-insensitive substring. Fields searched are listed in _SEARCH_META.
_SEARCH_META = ("name", "alertId", "severity", "mitreTactic", "mitreTechnique", "mitreSubtechnique", "mitreId",
                "ruleType", "ruleId", "definitionId", "clientIp", "serverIp", "serverPort", "protocol", "profile")
_HAY = ("LOWER(" + " || char(31) || ".join(
    [f"COALESCE(json_extract(alert_meta, '$.{k}'), '')" for k in _SEARCH_META]
    + ["alert_id", "state", "window_begin", "window_end",
       "CASE WHEN persistent=1 THEN 'persistent' ELSE '' END",
       "COALESCE(strftime('%Y-%m-%d %H:%M:%S', CAST(json_extract(alert_meta, '$.alertTime') AS REAL),"
       " 'unixepoch', 'localtime'), '')"]) + ")")
_TOKEN = re.compile(r'([A-Za-z]+=)?"([^"]*)"|(\S+)')
_SIZE_TOKEN = re.compile(r"^(\d+(?:\.\d+)?)(b|kb|kib|mb|mib|gb|gib)$", re.I)
_UNITS = {"b": 1, "kb": 1024, "kib": 1024, "mb": 1024 ** 2, "mib": 1024 ** 2, "gb": 1024 ** 3, "gib": 1024 ** 3}
MAX_TOKENS = 12
MAX_TOKEN_LEN = 100


def search_tokens(q: str | None) -> list[str]:
    """The tokens of a quick-filter text: quoted phrases kept whole (also `field="a phrase"`), capped in
    number and length."""
    out = []
    for m in _TOKEN.finditer(q or ""):
        tok = ((m.group(1) or "") + m.group(2) if m.group(2) is not None else m.group(3)).strip()[:MAX_TOKEN_LEN]
        if tok:
            out.append(tok)
    return out[:MAX_TOKENS]


# Field filters in the search (`clientIp=10.88.*`, `serverIp=10.0.0.0/8`, `state=done`), like Sycope's
# filter chips: the field from this fixed list, the value only ever a parameter. `*` is a wildcard; an
# address field also takes a network (CIDR). Matching is case-insensitive and exact otherwise.
FIELDS = {
    "alertname": ("Alert Name", "json_extract(alert_meta, '$.name')"),
    "alertid": ("Alert ID", "alert_id"),
    "severity": ("Alert Severity", "json_extract(alert_meta, '$.severity')"),
    "state": ("State", "state"),
    "clientip": ("Client IP", "json_extract(alert_meta, '$.clientIp')"),
    "serverip": ("Server IP", "json_extract(alert_meta, '$.serverIp')"),
    "serverport": ("Server Port", "CAST(json_extract(alert_meta, '$.serverPort') AS TEXT)"),
    "protocol": ("Protocol", "json_extract(alert_meta, '$.protocol')"),
    "profile": ("Profile", "json_extract(alert_meta, '$.profile')"),
}
_IP_FIELDS = ("clientip", "serverip")
_FIELD_TOKEN = re.compile(r"^([A-Za-z]+)=(.+)$")


def field_token(tok: str) -> tuple[str, str] | None:
    """(field key, value) of a `field=value` token with a known field, else None (free text)."""
    m = _FIELD_TOKEN.match(tok)
    if not m or m.group(1).lower() not in FIELDS:
        return None
    return m.group(1).lower(), m.group(2)


def ipkey(text: object) -> str | None:
    """An address as a string that sorts like the number (IPv4 and IPv6 apart), for CIDR ranges in SQL."""
    try:
        a = ipaddress.ip_address(str(text).strip())
    except ValueError:
        return None
    return f"4{int(a):08x}" if a.version == 4 else f"6{int(a):032x}"


_NO_OR = ("alertname", "profile")  # names may contain commas: there a comma is part of the value


def _field_clause(key: str, value: str) -> tuple[str, list]:
    """SQL for one field filter. `a,b` (except for names) means a or b, as Sycope's multi-value filter."""
    alts = [v for v in (value.split(",") if key not in _NO_OR else [value]) if v.strip()]
    if len(alts) > 1:
        parts, args = [], []
        for v in alts[:32]:
            c, a = _one_field_clause(key, v.strip())
            parts.append(c)
            args += a
        return "(" + " OR ".join(parts) + ")", args
    return _one_field_clause(key, value.strip())


def _one_field_clause(key: str, value: str) -> tuple[str, list]:
    expr = FIELDS[key][1]
    if key in _IP_FIELDS and "/" in value:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return "0", []  # not a network: matches nothing rather than everything
        return f"ipkey({expr}) BETWEEN ? AND ?", [ipkey(net.network_address), ipkey(net.broadcast_address)]
    if "*" in value:
        pat = value.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_").replace("*", "%")
        return f"LOWER(COALESCE({expr}, '')) LIKE ? ESCAPE '\\'", [pat]
    return f"LOWER(COALESCE({expr}, '')) = ?", [value.lower()]


def _like(token: str) -> str:
    """A LIKE pattern matching `token` anywhere, with %, _ and the escape character taken literally."""
    esc = token.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{esc}%"


# The time a job is placed at on the queue timeline: the alert's time, else when the job was created.
_TIME = "COALESCE(CAST(json_extract(alert_meta, '$.alertTime') AS REAL), created)"

# timeline ranges relative to now (?t=15m), as in Sycope's range picker
TIME_PRESETS = {"15m": 900, "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800, "30d": 2592000}
_ABS_WINDOW = re.compile(r"(\d{9,11})-(\d{9,11})")
MAX_WINDOW = 400 * 86400


def time_window(t: str | None, now: float) -> tuple[int, int] | None:
    """The [from, to) epoch window of a ?t= value: a preset ending now, or "from-to" (validated
    integers, from < to, at most MAX_WINDOW long). Anything else, or nothing, means no time filter."""
    t = (t or "").strip()
    if t in TIME_PRESETS:
        return int(now) - TIME_PRESETS[t], int(now)
    m = _ABS_WINDOW.fullmatch(t)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        if a < b and b - a <= MAX_WINDOW:
            return a, b
    return None


def where(state: str | None = None, q: str | None = None,
          window: tuple[int, int] | None = None) -> tuple[str, tuple]:
    """` WHERE ...` (or empty) and its arguments for a state chip, a quick filter and a time window.
    Fixed SQL text; the operator's words only ever travel as parameters."""
    parts: list[str] = []
    args: list = []
    if window:
        parts.append(f"{_TIME} >= ? AND {_TIME} < ?")
        args += [int(window[0]), int(window[1])]
    if state == "persistent":
        parts.append("persistent=1")
    elif state and state != "all":
        parts.append("state=?")
        args.append(state)
    for tok in search_tokens(q):
        ft = field_token(tok)
        if ft:
            clause, extra = _field_clause(*ft)
            parts.append(clause)
            args += extra
            continue
        clause = f"{_HAY} LIKE ? ESCAPE '\\'"
        args.append(_like(tok))
        sm = _SIZE_TOKEN.match(tok)
        if sm:  # 1.5MB: also the jobs whose PCAP is that size, as the page shows it (to 5 %)
            size = float(sm.group(1)) * _UNITS[sm.group(2).lower()]
            clause = f"({clause} OR pcap_bytes BETWEEN ? AND ?)"
            args += [int(size * 0.95), int(size * 1.05) + 1]
        parts.append(clause)
    return ((" WHERE " + " AND ".join(parts)) if parts else ""), tuple(args)


class JobStore:
    """The job database as both processes use it: per-thread connections, transactional transitions."""

    # sortable columns of the queue view: SQL expression per key (fixed text, never user input)
    SORTS = {
        "alert": "LOWER(COALESCE(json_extract(alert_meta, '$.name'), ''))",
        "alert_id": "alert_key",
        "severity": "CASE UPPER(COALESCE(json_extract(alert_meta, '$.severity'), '')) WHEN 'CRITICAL' THEN 4 "
                    "WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END",
        "state": "state",
        "attempts": "attempts",
        "alert_time": "COALESCE(CAST(json_extract(alert_meta, '$.alertTime') AS REAL), 0)",
        "due": "ready_at",
        "updated": "updated",
        "client_ip": "LOWER(COALESCE(json_extract(alert_meta, '$.clientIp'), ''))",
        "server_ip": "LOWER(COALESCE(json_extract(alert_meta, '$.serverIp'), ''))",
        "server_port": "COALESCE(CAST(json_extract(alert_meta, '$.serverPort') AS INTEGER), -1)",
        "protocol": "LOWER(COALESCE(json_extract(alert_meta, '$.protocol'), ''))",
        "profile": "LOWER(COALESCE(json_extract(alert_meta, '$.profile'), ''))",
        "persistent": "persistent",
        "pcap": "COALESCE(pcap_bytes, -1)",
    }

    def __init__(self, path: str, busy_timeout_ms: int = 5000) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.path = path
        self._busy = busy_timeout_ms
        self._local = threading.local()
        # (owning thread, connection): a threadpool that grows and shrinks must not leave the
        # connections of dead threads open for the life of the process
        self._all: list[tuple[threading.Thread, sqlite3.Connection]] = []
        self._all_lock = threading.Lock()
        with _file_lock(path + ".lock"):
            _init_db(path)

    def _conn(self) -> sqlite3.Connection:
        """This thread's connection (sqlite3 connections must not be shared between threads)."""
        con = getattr(self._local, "con", None)
        if con is None:
            for name in (self.path, self.path + "-wal", self.path + "-shm"):
                if os.path.islink(name):
                    raise sqlite3.OperationalError(f"{name} is a symbolic link: refusing to connect to it")
            con = sqlite3.connect(self.path, isolation_level=None, timeout=self._busy / 1000,
                                  check_same_thread=False)
            con.row_factory = sqlite3.Row
            con.create_function("ipkey", 1, ipkey, deterministic=True)  # CIDR field filters
            con.execute(f"PRAGMA busy_timeout={int(self._busy)}")
            self._local.con = con
            with self._all_lock:
                self._drop_dead_threads()
                self._all.append((threading.current_thread(), con))
        return con

    def _drop_dead_threads(self) -> None:
        """Close the connections of threads that have ended (caller holds `_all_lock`). Only the owning
        thread used a connection, and it is gone, so closing it from another thread is safe
        (check_same_thread=False)."""
        alive = []
        for thread, con in self._all:
            if thread.is_alive():
                alive.append((thread, con))
                continue
            try:
                con.close()
            except sqlite3.Error:
                pass
        self._all[:] = alive

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        """One write transaction; BEGIN IMMEDIATE takes the write lock up front so checks and
        updates inside it see the same state (no upgrade deadlock between processes)."""
        con = self._conn()
        con.execute("BEGIN IMMEDIATE")
        try:
            yield con
            con.execute("COMMIT")  # inside the try: a COMMIT that fails (busy, disk) must roll back too
        except BaseException:
            try:
                con.execute("ROLLBACK")
            except sqlite3.Error:
                pass  # no transaction left to roll back; the original error is the one to report
            raise

    def _read(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        """A read outside any transaction (WAL: never blocked by the other process's writes)."""
        return self._conn().execute(sql, args).fetchall()

    def close(self) -> None:
        """Close every connection this store opened, from any thread."""
        with self._all_lock:
            for _thread, con in self._all:
                try:
                    con.close()
                except sqlite3.Error:
                    pass
            self._all.clear()
        self._local = threading.local()

    def schema_ok(self) -> bool:
        """True when the file still has this release's schema (/healthz)."""
        try:
            return self._read("PRAGMA user_version")[0][0] == SCHEMA_VERSION
        except sqlite3.Error:
            return False

    # ---- helpers used inside a transaction

    @staticmethod
    def _event(c: sqlite3.Connection, job_id: str, alert_id: str, state: str, attempt: int = 0,
               detail: str = "", url: str = "", size: int | None = None) -> None:
        """Append one history row."""
        c.execute("INSERT INTO job_events (job_id, alert_id, ts, state, attempt, detail, url, bytes)"
                  " VALUES (?,?,?,?,?,?,?,?)",
                  (job_id, alert_id, time.time(), state, attempt, detail, url, size))

    @staticmethod
    def _bump(c: sqlite3.Connection, name: str, n: int = 1) -> None:
        """Add n to a persistent counter."""
        c.execute("INSERT INTO counters (name, value, since) VALUES (?,?,?) "
                  "ON CONFLICT(name) DO UPDATE SET value = value + excluded.value", (name, n, time.time()))

    @staticmethod
    def _upsert_meta(c: sqlite3.Connection, key: str, value: str, now: float) -> None:
        """Set one meta row (value and when) inside the caller's transaction."""
        c.execute("INSERT INTO meta VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE"
                  " SET value=excluded.value, updated=excluded.updated", (key, value, now))

    def _cancel_if_requested(self, c: sqlite3.Connection, job_id: str, attempts: int) -> None:
        """A running job whose cancel was requested ends `cancelled` instead of the transition the
        worker tried; called when that conditional UPDATE matched nothing."""
        row = c.execute("SELECT alert_id, url FROM jobs WHERE id=? AND state=? AND cancel_requested=1",
                        (job_id, RUNNING)).fetchone()
        if row is None:
            return
        c.execute("UPDATE jobs SET state=?, detail=?, attempts=?, claimed_by='', updated=? WHERE id=?",
                  (CANCELLED, _CANCELLED_BY_OPERATOR, attempts, time.time(), job_id))
        self._event(c, job_id, row["alert_id"], CANCELLED, attempts, _CANCELLED_BY_OPERATOR, row["url"])
        self._bump(c, "cancelled")

    # ---- history

    def events(self, job_id: str) -> list[dict]:
        """Full history of one job, oldest first."""
        return [dict(r) for r in self._read(
            "SELECT * FROM job_events WHERE job_id=? ORDER BY id", (job_id,))]

    def events_many(self, job_ids: list[str]) -> dict[str, list[dict]]:
        """History of several jobs at once (the queue view), oldest first per job."""
        out: dict[str, list[dict]] = {j: [] for j in job_ids}
        for chunk in _chunks(job_ids):
            marks = ",".join("?" * len(chunk))
            for r in self._read(f"SELECT * FROM job_events WHERE job_id IN ({marks}) ORDER BY id",
                                tuple(chunk)):
                out[r["job_id"]].append(dict(r))
        return out

    def persistent_files(self) -> set[str]:
        """File names (basename of output_path) of the persistent jobs: retention must never delete them."""
        return {os.path.basename(r["output_path"]) for r in self._read(
            "SELECT output_path FROM jobs WHERE persistent=1")}

    def prune_events(self, older_than: float) -> int:
        """Drop old history rows, except those of jobs flagged persistent."""
        with self._tx() as c:
            return c.execute("DELETE FROM job_events WHERE ts<? AND job_id NOT IN "
                             "(SELECT id FROM jobs WHERE persistent=1)", (older_than,)).rowcount

    # ---- queue

    def recover(self, max_recoveries: int = MAX_RECOVERIES) -> int:
        """Return jobs a dead worker left `running` to the queue; the number queued again. Only the
        worker calls this, and only while it holds worker.lock with the previous worker's children killed.

        A graceful stop hands its jobs back (interrupt), so a job found `running` here was running when
        the worker died hard: watchdog exit, a slot that would not stop, a kill, OOM, power loss. A job
        that takes the worker down would come back forever (C-10), so the recoveries are counted: a job
        recovered for the `max_recoveries`-th time in a row ends `failed` instead (or `cancelled`, if the
        operator asked). In a row means since its last event that shows a run ending normally or a fresh
        start (_RECOVERY_RESET); the count comes from the history, so no column is needed. `attempts`
        is not used: a recovery is not a failed extraction and must not widen the window.
        """
        now = time.time()
        requeued = 0
        reset = ",".join("?" * len(_RECOVERY_RESET))
        with self._tx() as c:
            rows = c.execute("SELECT id, alert_id, url, attempts FROM jobs WHERE state=?",
                             (RUNNING,)).fetchall()
            for r in rows:
                before = c.execute(
                    "SELECT COUNT(*) FROM job_events WHERE job_id=? AND state=? AND id > COALESCE("
                    f"(SELECT MAX(id) FROM job_events WHERE job_id=? AND state IN ({reset})), 0)",
                    (r["id"], EVENT_RECOVERED, r["id"], *_RECOVERY_RESET)).fetchone()[0]
                if before + 1 >= max_recoveries:
                    attempts = r["attempts"] + 1  # the run that took the worker down, as run_one counts it
                    detail = (f"the worker stopped unexpectedly while this job ran, {before + 1} times in a "
                              f"row (hang, crash or kill); not tried again")
                    n = c.execute("UPDATE jobs SET state=?, detail=?, attempts=?, claimed_by='', claimed_at=NULL,"
                                  " updated=? WHERE id=? AND state=? AND cancel_requested=0",
                                  (FAILED, detail, attempts, now, r["id"], RUNNING)).rowcount
                    if n == 0:
                        self._cancel_if_requested(c, r["id"], attempts)
                        continue
                    self._event(c, r["id"], r["alert_id"], FAILED, attempts, detail, r["url"])
                    self._bump(c, "failed")
                    log.error("job %s: %s", r["id"], detail)
                    continue
                c.execute("UPDATE jobs SET state=?, claimed_by='', claimed_at=NULL, updated=? WHERE id=? AND state=?",
                          (QUEUED, now, r["id"], RUNNING))
                self._event(c, r["id"], r["alert_id"], EVENT_RECOVERED, r["attempts"],
                            f"the worker restarted while this job ran; queued again ({before + 1} in a "
                            f"row; at {max_recoveries} the job fails)", r["url"])
                requeued += 1
        return requeued

    def enqueue(self, plan: Plan, ready_at: float, url: str = "", meta: dict | None = None) -> str:
        """Add a job: "queued", "exists" or "conflict".

        "exists": the same file is already queued or running, or done with its PCAP on disk, or there
        is no row but a PCAP of that name is on disk (a row pruned after SR_JOB_HISTORY_DAYS): it is
        never extracted over. A done job whose PCAP is gone, and a job that ended miss/failed/cancelled,
        is queued again: a re-delivered webhook is the operator's way to retry.
        "conflict": the file name or the key already belongs to another alert id (rows written before
        extraction.alert_key, or an id that spells another id's key); nothing is written.
        """
        now = time.time()
        alert_id = str(plan.alert_id)
        with self._tx() as c:
            row = c.execute("SELECT state, persistent, alert_id FROM jobs WHERE id=?",
                            (plan.filename,)).fetchone()
            other = (row is not None and row["alert_id"] not in ("", alert_id)) or (
                row is None and c.execute("SELECT 1 FROM jobs WHERE alert_key=? AND alert_id NOT IN ('', ?)"
                                          " LIMIT 1", (plan.alert_key, alert_id)).fetchone() is not None)
            if other:
                log.warning("alert id=%r: key %s already belongs to another alert; not queued",
                            alert_id, plan.alert_key)
                return "conflict"
            gone = row is not None and row["state"] == DONE and not _pcap_on_disk(plan.output_path)
            if row is not None and row["state"] in (QUEUED, RUNNING, DONE) and not gone:
                self._event(c, plan.filename, alert_id, EVENT_REDELIVERED,
                            detail=f"webhook delivered again; job is {row['state']}", url=url)
                return "exists"
            if row is None and _pcap_on_disk(plan.output_path):
                log.warning("alert id=%r: %s is on disk without a job row (pruned?); not extracted again",
                            alert_id, plan.filename)
                return "exists"
            if gone:
                self._event(c, plan.filename, alert_id, EVENT_REDELIVERED,
                            detail="webhook delivered again; job is done but its PCAP is gone: extracting again",
                            url=url)
            imp = int(row["persistent"]) if row is not None else 0
            c.execute(
                "INSERT OR REPLACE INTO jobs (id, alert_id, bpf, window_begin, window_end,"
                " window_end_epoch, output_path, ready_at, next_at, state, attempts, detail,"
                " created, updated, url, alert_key, alert_meta, persistent, cancel_requested,"
                " claimed_by, claimed_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,0,'',?,?,?,?,?,?,0,'',NULL)",
                (plan.filename, str(plan.alert_id), plan.bpf, plan.begin, plan.end,
                 plan.window_end_epoch, plan.output_path, ready_at, ready_at, QUEUED, now, now,
                 url, plan.alert_key, json.dumps(meta or {}, ensure_ascii=False), imp))
            when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ready_at))
            self._event(c, plan.filename, str(plan.alert_id), QUEUED,
                        detail=f"window {plan.begin} to {plan.end}; runs after {when}", url=url)
            self._bump(c, "queued")
            return "queued"

    def depth(self) -> int:
        """Jobs that still occupy the queue (queued + running)."""
        return self._read("SELECT COUNT(*) FROM jobs WHERE state IN (?,?)", (QUEUED, RUNNING))[0][0]

    def counts(self, q: str | None = None, window: tuple[int, int] | None = None) -> dict[str, int]:
        """Jobs per state plus the number flagged persistent (the filter chips), within a quick filter
        and a time window."""
        w, args = where(None, q, window)
        out = {st: 0 for st in STATES}
        out.update({r["state"]: r["n"] for r in self._read(
            f"SELECT state, COUNT(*) AS n FROM jobs{w} GROUP BY state", args)})
        wp, argsp = where("persistent", q, window)
        out["persistent"] = self._read(f"SELECT COUNT(*) FROM jobs{wp}", argsp)[0][0]
        return out

    def count_jobs(self, state: str | None = None, q: str | None = None,
                   window: tuple[int, int] | None = None) -> int:
        """Total matching jobs (pagination)."""
        w, args = where(state, q, window)
        return self._read(f"SELECT COUNT(*) FROM jobs{w}", args)[0][0]

    def top_values(self, key: str, state: str | None = None, q: str | None = None,
                   window: tuple[int, int] | None = None, limit: int = 12) -> tuple[int, list[tuple[str, int]]]:
        """(matching jobs, [(value, jobs)] most frequent first) of one filter field, for the filter editor."""
        if key not in FIELDS:
            return 0, []
        expr = FIELDS[key][1]
        w, args = where(state, q, window)
        total = self._read(f"SELECT COUNT(*) FROM jobs{w}", args)[0][0]
        rows = self._read(f"SELECT {expr} AS v, COUNT(*) AS n FROM jobs{w} GROUP BY v HAVING v IS NOT NULL "
                          f"AND v != '' ORDER BY n DESC, v LIMIT ?", (*args, int(limit)))
        return total, [(str(r["v"]), r["n"]) for r in rows]

    def time_bounds(self, state: str | None = None, q: str | None = None) -> tuple[float, float] | None:
        """Earliest and latest timeline time of the matching jobs, or None without any."""
        w, args = where(state, q)
        row = self._read(f"SELECT MIN({_TIME}), MAX({_TIME}) FROM jobs{w}", args)[0]
        return (row[0], row[1]) if row[0] is not None else None

    def histogram(self, start: int, step: int, n: int, state: str | None = None,
                  q: str | None = None, window: tuple[int, int] | None = None) -> list[int]:
        """Matching jobs per timeline bucket: n buckets of `step` seconds from `start`, only those inside
        `window` as well (the edge buckets then count exactly what the table lists)."""
        lo, hi = start, start + step * n
        if window:
            lo, hi = max(lo, int(window[0])), min(hi, int(window[1]))
        w, args = where(state, q, (lo, hi))
        out = [0] * n
        for r in self._read(f"SELECT CAST(({_TIME} - ?) / ? AS INTEGER) AS b, COUNT(*) AS c FROM jobs{w} "
                            "GROUP BY b", (start, step, *args)):
            if 0 <= r["b"] < n:
                out[r["b"]] = r["c"]
        return out

    def job_ids(self, state: str | None = None, q: str | None = None,
                only: tuple[str, ...] | None = None, window: tuple[int, int] | None = None) -> list[str]:
        """Every job id matching a chip and a quick filter ("all matching" in the bulk actions),
        optionally only those in the given states (an action that cannot touch the others)."""
        w, args = where(state, q, window)
        if only:
            w += (" AND " if w else " WHERE ") + f"state IN ({','.join('?' * len(only))})"
            args = (*args, *only)
        return [r[0] for r in self._read(f"SELECT id FROM jobs{w}", args)]

    def states(self, job_ids: list[str]) -> dict[str, str]:
        """{job id: state} of the given jobs that exist."""
        out: dict[str, str] = {}
        for chunk in _chunks(job_ids):
            out.update({r["id"]: r["state"] for r in self._read(
                f"SELECT id, state FROM jobs WHERE id IN ({','.join('?' * len(chunk))})", tuple(chunk))})
        return out

    def get(self, job_id: str) -> dict | None:
        """One job row, or None."""
        rows = self._read("SELECT * FROM jobs WHERE id=?", (job_id,))
        return dict(rows[0]) if rows else None

    def toggle_persistent(self, job_id: str) -> bool | None:
        """Flip the persistent flag; the new value, or None if the job does not exist."""
        with self._tx() as c:
            row = c.execute("SELECT persistent FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                return None
            new_val = 0 if row["persistent"] else 1
            c.execute("UPDATE jobs SET persistent=? WHERE id=?", (new_val, job_id))
            return bool(new_val)

    def set_persistent(self, job_id: str, persistent: bool) -> bool:
        """Set the persistent flag; False if the job does not exist."""
        with self._tx() as c:
            return c.execute("UPDATE jobs SET persistent=? WHERE id=?",
                             (1 if persistent else 0, job_id)).rowcount > 0

    def delete_jobs(self, job_ids: list[str] | None = None, filter_state: str | None = None,
                    q: str | None = None, window: tuple[int, int] | None = None) -> tuple[int, int, int]:
        """Delete job rows and their history; never PCAP files. Running and persistent jobs are skipped.

        Without `job_ids` the jobs are those matching `filter_state`, `q` and `window`. Returns (deleted,
        skipped_running, skipped_persistent). One transaction, so a job cannot be claimed between the
        check and the delete.
        """
        with self._tx() as c:
            if job_ids is not None:
                rows = []
                for chunk in _chunks(job_ids):
                    marks = ",".join("?" * len(chunk))
                    rows.extend(c.execute(
                        f"SELECT id, state, persistent FROM jobs WHERE id IN ({marks})", chunk).fetchall())
            else:
                w, args = where(filter_state, q, window)
                rows = c.execute(f"SELECT id, state, persistent FROM jobs{w}", args).fetchall()
            to_delete = [r["id"] for r in rows if r["state"] != RUNNING and not r["persistent"]]
            skipped_running = sum(1 for r in rows if r["state"] == RUNNING)
            skipped_persistent = sum(1 for r in rows if r["state"] != RUNNING and r["persistent"])
            for chunk in _chunks(to_delete):
                marks = ",".join("?" * len(chunk))
                c.execute(f"DELETE FROM job_events WHERE job_id IN ({marks})", chunk)
                c.execute(f"DELETE FROM jobs WHERE id IN ({marks})", chunk)
            return len(to_delete), skipped_running, skipped_persistent

    def jobs_for_key(self, key: str) -> list[dict]:
        """All jobs of one alert (URL-safe id), newest first. Normally one."""
        return [dict(r) for r in self._read(
            "SELECT * FROM jobs WHERE alert_key=? ORDER BY created DESC", (key,))]

    def list_jobs(self, limit: int = 100, offset: int = 0, state: str | None = None,
                  sort: str = "updated", desc: bool = True, q: str | None = None,
                  window: tuple[int, int] | None = None) -> list[dict]:
        """Jobs for the queue view, optionally of one state or persistent, matching a quick filter and
        a time window."""
        order = f"{self.SORTS.get(sort, self.SORTS['updated'])} {'DESC' if desc else 'ASC'}, updated DESC, id"
        w, args = where(state, q, window)
        return [dict(r) for r in self._read(
            f"SELECT * FROM jobs{w} ORDER BY {order} LIMIT ? OFFSET ?", (*args, limit, offset))]

    def set_persistent_many(self, job_ids: list[str], persistent: bool) -> int:
        """Set the flag on many jobs; how many rows exist (and now carry the value)."""
        n = 0
        with self._tx() as c:
            for chunk in _chunks(job_ids):
                marks = ",".join("?" * len(chunk))
                n += c.execute(f"UPDATE jobs SET persistent=? WHERE id IN ({marks})",
                               (1 if persistent else 0, *chunk)).rowcount
        return n

    # ---- worker transitions (all conditional on state='running')

    def waiting_due(self, now: float) -> bool:
        """Whether a waiting job (detail WAITING) is due for its next check: the worker lists the rolling
        directory for `claim(hold=...)` only then."""
        return bool(self._read(
            "SELECT 1 FROM jobs WHERE state=? AND next_at<=? AND substr(detail, 1, ?)=? LIMIT 1",
            (QUEUED, now, len(WAITING), WAITING)))

    def claim(self, now: float, slot: str = "",
              hold: tuple[float, float, float] | None = None) -> dict | None:
        """Take the oldest due job and mark it running; nothing while the worker is paused.

        `hold` is (start of the newest rolling file, quiet wait in seconds, time of the next check).
        With it, every due waiting job whose window end the newest file has not passed and whose quiet
        wait has not run out is given the next check time in this transaction, without a claim or an
        event (the row changes as jobs.run_one's defer would change it, except the detail); the rest
        are claimed as usual. jobs.run_one decides with the same two conditions.
        """
        with self._tx() as c:
            paused = c.execute("SELECT value FROM control WHERE key=?", (CONTROL_PAUSED,)).fetchone()
            if paused is not None and paused["value"] == "1":
                return None
            if hold is not None:
                newest, quiet_wait, next_at = hold
                c.execute("UPDATE jobs SET next_at=?, updated=? WHERE state=? AND next_at<=?"
                          " AND substr(detail, 1, ?)=? AND window_end_epoch>=? AND ready_at>?",
                          (next_at, time.time(), QUEUED, now, len(WAITING), WAITING, newest,
                           now - quiet_wait))
            row = c.execute("SELECT * FROM jobs WHERE state=? AND next_at<=? ORDER BY next_at LIMIT 1",
                            (QUEUED, now)).fetchone()
            if row is None:
                return None
            c.execute("UPDATE jobs SET state=?, claimed_by=?, claimed_at=?, updated=? WHERE id=? AND state=?",
                      (RUNNING, slot, now, now, row["id"], QUEUED))
            if not str(row["detail"]).startswith(WAITING):  # a waiting job is polled: no spam
                self._event(c, row["id"], row["alert_id"], RUNNING, row["attempts"] + 1, url=row["url"])
            return {**dict(row), "state": RUNNING, "claimed_by": slot, "claimed_at": now}

    def running_jobs(self) -> list[dict]:
        """Running jobs with their claimant and claim time (the worker's check for jobs nobody runs)."""
        return [dict(r) for r in self._read(
            "SELECT id, claimed_by, claimed_at FROM jobs WHERE state=?", (RUNNING,))]

    def defer(self, job_id: str, next_at: float, detail: str) -> bool:
        """Back to the queue without using an attempt (the data is not on disk yet)."""
        with self._tx() as c:
            row = c.execute("SELECT alert_id, url, detail FROM jobs WHERE id=?", (job_id,)).fetchone()
            n = c.execute("UPDATE jobs SET state=?, next_at=?, detail=?, claimed_by='', updated=?"
                          " WHERE id=? AND state=? AND cancel_requested=0",
                          (QUEUED, next_at, detail, time.time(), job_id, RUNNING)).rowcount
            if n == 0:
                self._cancel_if_requested(c, job_id, 0)
                return False
            if not str(row["detail"]).startswith(WAITING):  # say it once, not on every poll
                self._event(c, job_id, row["alert_id"], EVENT_WAITING, detail=detail, url=row["url"])
            return True

    def retry(self, job_id: str, next_at: float, detail: str, attempts: int,
              counters: Iterable[str] = ()) -> bool:
        """An attempt failed; queue the job again for a later attempt."""
        with self._tx() as c:
            n = c.execute("UPDATE jobs SET state=?, next_at=?, detail=?, attempts=?, claimed_by='', updated=?"
                          " WHERE id=? AND state=? AND cancel_requested=0",
                          (QUEUED, next_at, detail, attempts, time.time(), job_id, RUNNING)).rowcount
            if n == 0:
                self._cancel_if_requested(c, job_id, attempts)
                return False
            for name in counters:  # only a transition that happened is counted
                self._bump(c, name)
            row = c.execute("SELECT alert_id, url FROM jobs WHERE id=?", (job_id,)).fetchone()
            when = time.strftime("%H:%M:%S", time.localtime(next_at))
            self._event(c, job_id, row["alert_id"], EVENT_RETRY, attempts,
                        f"{detail}; next attempt at {when}", row["url"])
            return True

    def interrupt(self, job_id: str, detail: str, claimed_by: str | None = None) -> bool:
        """The worker stopped during the job: queue it again without using an attempt.

        With `claimed_by` only that slot's claim is released, so a job another slot has since claimed
        is left alone.
        """
        with self._tx() as c:
            n = c.execute("UPDATE jobs SET state=?, next_at=?, claimed_by='', updated=? WHERE id=? AND state=?"
                          + (" AND claimed_by=?" if claimed_by is not None else ""),
                          (QUEUED, time.time(), time.time(), job_id, RUNNING,
                           *(() if claimed_by is None else (claimed_by,)))).rowcount
            if n == 0:
                return False
            row = c.execute("SELECT alert_id, url, attempts FROM jobs WHERE id=?", (job_id,)).fetchone()
            self._event(c, job_id, row["alert_id"], EVENT_INTERRUPTED, row["attempts"], detail, row["url"])
            self._bump(c, "interrupted")
            return True

    def finish(self, job_id: str, state: str, detail: str, attempts: int, size: int | None = None,
               counters: Iterable[str] = (), info: dict | None = None) -> bool:
        """Final state (done/miss/failed) of a running job; a requested cancel wins instead. `info` is
        the summary of the extracted file (packets, first/last packet) for a done job."""
        now = time.time()
        with self._tx() as c:
            n = c.execute("UPDATE jobs SET state=?, detail=?, attempts=?, claimed_by='', updated=?,"
                          " pcap_bytes=?, pcap_info=?"
                          " WHERE id=? AND state=? AND cancel_requested=0",
                          (state, detail, attempts, now, size if state == DONE else None,
                           json.dumps(info) if info and state == DONE else "",
                           job_id, RUNNING)).rowcount
            if n == 0:
                self._cancel_if_requested(c, job_id, attempts)
                return False
            for name in counters:  # only a transition that happened is counted
                self._bump(c, name)
            row = c.execute("SELECT alert_id, url FROM jobs WHERE id=?", (job_id,)).fetchone()
            self._event(c, job_id, row["alert_id"], state, attempts, detail, row["url"], size)
            if state == DONE:
                self._upsert_meta(c, META_LAST_SUCCESS, str(now), now)
            return True

    def cancelled(self, job_id: str, attempts: int, detail: str) -> bool:
        """The worker killed npcapextract for a requested cancel: final state `cancelled`. Without a
        recorded request nothing changes: a cancel is the operator's decision, never the worker's."""
        with self._tx() as c:
            n = c.execute("UPDATE jobs SET state=?, detail=?, attempts=?, claimed_by='', updated=?"
                          " WHERE id=? AND state=? AND cancel_requested=1",
                          (CANCELLED, detail, attempts, time.time(), job_id, RUNNING)).rowcount
            if n == 0:
                return False
            row = c.execute("SELECT alert_id, url FROM jobs WHERE id=?", (job_id,)).fetchone()
            self._event(c, job_id, row["alert_id"], CANCELLED, attempts, detail, row["url"])
            self._bump(c, "cancelled")
            return True

    def note(self, job_id: str, state: str, attempt: int, detail: str) -> None:
        """An informational history row (no state change)."""
        with self._tx() as c:
            row = c.execute("SELECT alert_id, url FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is not None:
                self._event(c, job_id, row["alert_id"], state, attempt, detail, row["url"])

    def prune(self, older_than: float) -> int:
        """Forget finished jobs last touched before `older_than`, except persistent ones (PCAPs untouched)."""
        with self._tx() as c:
            return c.execute(f"DELETE FROM jobs WHERE state IN ({','.join('?' * len(FINAL))})"
                             " AND updated<? AND persistent=0", (*FINAL, older_than)).rowcount

    # ---- operator requests (web)

    def request_cancel(self, job_ids: list[str], by: str) -> dict:
        """Cancel queued jobs at once; flag running ones for the worker to kill. Final ones are skipped."""
        out = {"cancelled": 0, "requested": 0, "skipped": 0}
        now = time.time()
        with self._tx() as c:
            for jid in job_ids:
                row = c.execute("SELECT state, alert_id, url, attempts, cancel_requested FROM jobs WHERE id=?",
                                (jid,)).fetchone()
                if row is None:
                    out["skipped"] += 1
                elif row["state"] == QUEUED:
                    c.execute("UPDATE jobs SET state=?, detail=?, updated=? WHERE id=? AND state=?",
                              (CANCELLED, _CANCELLED_BY_OPERATOR, now, jid, QUEUED))
                    self._event(c, jid, row["alert_id"], CANCELLED, row["attempts"],
                                f"cancelled by operator ({by}) before it ran", row["url"])
                    self._bump(c, "cancelled")
                    out["cancelled"] += 1
                elif row["state"] == RUNNING and not row["cancel_requested"]:
                    c.execute("UPDATE jobs SET cancel_requested=1, updated=? WHERE id=? AND state=?",
                              (now, jid, RUNNING))
                    self._event(c, jid, row["alert_id"], EVENT_CANCEL_REQUESTED, row["attempts"],
                                f"cancel requested by operator ({by}); the worker stops the extraction",
                                row["url"])
                    out["requested"] += 1
                else:
                    self._event(c, jid, row["alert_id"], EVENT_CANCEL_IGNORED, row["attempts"],
                                f"cancel by operator ({by}) ignored: job is already {row['state']}", row["url"])
                    out["skipped"] += 1
        return out

    def retry_jobs(self, job_ids: list[str], by: str, queue_max: int) -> dict:
        """Queue miss/failed/cancelled jobs again with fresh attempts; never more than queue_max in the queue."""
        out = {"requeued": 0, "skipped": 0, "rejected_queue_full": 0}
        now = time.time()
        marks = ",".join("?" * len(RETRYABLE))
        with self._tx() as c:
            depth = c.execute("SELECT COUNT(*) FROM jobs WHERE state IN (?,?)", (QUEUED, RUNNING)).fetchone()[0]
            for jid in job_ids:
                row = c.execute("SELECT state, alert_id, url FROM jobs WHERE id=?", (jid,)).fetchone()
                if row is None or row["state"] not in RETRYABLE:
                    out["skipped"] += 1
                    continue
                if depth >= queue_max:
                    out["rejected_queue_full"] += 1
                    continue
                c.execute(f"UPDATE jobs SET state=?, attempts=0, cancel_requested=0, detail='',"
                          f" next_at=MAX(?, ready_at), claimed_by='', claimed_at=NULL, updated=?"
                          f" WHERE id=? AND state IN ({marks})", (QUEUED, now, now, jid, *RETRYABLE))
                self._event(c, jid, row["alert_id"], EVENT_RETRY, 0,
                            f"queued again by operator ({by}) after {row['state']}", row["url"])
                depth += 1
                out["requeued"] += 1
        return out

    def reextract(self, source_id: str, plan: Plan, ready_at: float, meta: dict, by: str, detail: str,
                  queue_max: int) -> str:
        """An operator's new extraction for the alert of `source_id` (another window or filter): a new
        job next to the old one, whose file stays. "queued", "missing" (no such job), "exists" (the
        file name is taken by a job or a PCAP on disk) or "full" (SR_QUEUE_MAX). Both jobs get the
        event in this transaction."""
        now = time.time()
        with self._tx() as c:
            src = c.execute("SELECT alert_id, alert_key, url FROM jobs WHERE id=?", (source_id,)).fetchone()
            if src is None:
                return "missing"
            if c.execute("SELECT 1 FROM jobs WHERE id=?", (plan.filename,)).fetchone() is not None \
                    or _pcap_on_disk(plan.output_path):
                return "exists"
            if c.execute("SELECT COUNT(*) FROM jobs WHERE state IN (?,?)", (QUEUED, RUNNING)).fetchone()[0] \
                    >= queue_max:
                return "full"
            c.execute(
                "INSERT INTO jobs (id, alert_id, bpf, window_begin, window_end, window_end_epoch, output_path,"
                " ready_at, next_at, state, attempts, detail, created, updated, url, alert_key, alert_meta,"
                " persistent, origin, parent_id)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,0,'',?,?,?,?,?,0,'operator',?)",
                (plan.filename, src["alert_id"], plan.bpf, plan.begin, plan.end, plan.window_end_epoch,
                 plan.output_path, ready_at, ready_at, QUEUED, now, now, src["url"], src["alert_key"],
                 json.dumps(meta, ensure_ascii=False), source_id))
            when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ready_at))
            self._event(c, plan.filename, src["alert_id"], QUEUED,
                        detail=f"re-extract of {source_id} by operator ({by}): {detail}; "
                               f"window {plan.begin} to {plan.end}; filter {plan.bpf}; runs after {when}",
                        url=src["url"])
            self._event(c, source_id, src["alert_id"], EVENT_REEXTRACT,
                        detail=f"re-extracted as {plan.filename} by operator ({by}): {detail}", url=src["url"])
            self._bump(c, "queued")
            return "queued"

    def cancel_requested(self, job_id: str) -> bool:
        """Polled about once a second by the slot running the job."""
        rows = self._read("SELECT cancel_requested FROM jobs WHERE id=?", (job_id,))
        return bool(rows and rows[0][0])

    # ---- counters and meta

    def bump(self, name: str, n: int = 1) -> None:
        """Add n to a counter in its own transaction (rejections that create no job)."""
        with self._tx() as c:
            self._bump(c, name, n)

    def counters(self) -> dict[str, int]:
        """All persistent counters."""
        return {r["name"]: r["value"] for r in self._read("SELECT name, value FROM counters")}

    def record_webhook(self) -> None:
        """Count a webhook and remember when it came (silence warning, System page)."""
        now = time.time()
        with self._tx() as c:
            self._bump(c, "webhook")
            self._upsert_meta(c, META_LAST_WEBHOOK, str(now), now)

    def set_meta(self, key: str, value: str) -> None:
        """Store one fact about the deployment (start times, versions, npcapextract info)."""
        now = time.time()
        with self._tx() as c:
            self._upsert_meta(c, key, value, now)

    def get_meta(self, key: str) -> str | None:
        """One meta value, or None."""
        rows = self._read("SELECT value FROM meta WHERE key=?", (key,))
        return rows[0][0] if rows else None

    def meta(self) -> dict[str, str]:
        """All meta values."""
        return {r["key"]: r["value"] for r in self._read("SELECT key, value FROM meta")}

    # ---- control (web -> worker)

    def _set_control(self, c: sqlite3.Connection, key: str, value: str, by: str) -> None:
        """The single upsert behind pause and config_generation, so value, `by` and `updated` are
        always written together. Runs inside the caller's transaction: the generation bump reads
        and writes in one BEGIN IMMEDIATE, so two operators cannot both take the same number."""
        c.execute("INSERT INTO control VALUES (?, ?, ?, ?) ON CONFLICT(key) DO UPDATE"
                  " SET value=excluded.value, updated=excluded.updated, by=excluded.by",
                  (key, value, time.time(), by))

    def set_paused(self, paused: bool, by: str) -> None:
        """Pause or resume claiming; running jobs are not affected."""
        with self._tx() as c:
            self._set_control(c, CONTROL_PAUSED, "1" if paused else "0", by)

    def paused(self) -> bool:
        """Whether an operator paused the worker."""
        rows = self._read("SELECT value FROM control WHERE key=?", (CONTROL_PAUSED,))
        return bool(rows and rows[0][0] == "1")

    def config_generation(self) -> int:
        """Bumped by the web on every configuration apply/revert; the worker reloads when it changes."""
        rows = self._read("SELECT value FROM control WHERE key=?", (CONTROL_CONFIG_GENERATION,))
        return int(rows[0][0]) if rows else 0

    def bump_config_generation(self, by: str) -> int:
        """Tell the worker to reload; returns the new generation."""
        with self._tx() as c:
            row = c.execute("SELECT value FROM control WHERE key=?", (CONTROL_CONFIG_GENERATION,)).fetchone()
            gen = (int(row[0]) if row else 0) + 1
            self._set_control(c, CONTROL_CONFIG_GENERATION, str(gen), by)
            return gen

    def control(self) -> dict[str, dict]:
        """All control rows with who set them and when (System page, debug bundle)."""
        return {r["key"]: dict(r) for r in self._read("SELECT * FROM control")}

    # ---- worker heartbeats

    _WORKER_COLS = frozenset({"pid", "pid_start", "heartbeat", "state", "job_id", "step", "step_started",
                              "child_pid", "child_start", "detail"})

    def put_worker(self, slot: str, **fields) -> None:
        """Insert or update one worker row; only known column names (they are part of the SQL text)."""
        bad = set(fields) - self._WORKER_COLS
        if bad:
            raise ValueError(f"unknown worker field(s): {sorted(bad)}")
        cols = sorted(fields)
        sets = ", ".join(f"{k}=excluded.{k}" for k in cols) or "slot=slot"
        with self._tx() as c:
            c.execute(f"INSERT INTO workers (slot{''.join(', ' + k for k in cols)})"
                      f" VALUES (?{', ?' * len(cols)}) ON CONFLICT(slot) DO UPDATE SET {sets}",
                      (slot, *(fields[k] for k in cols)))

    def workers(self) -> list[dict]:
        """`main` first, then the slots in name order."""
        return [dict(r) for r in self._read(
            "SELECT * FROM workers ORDER BY CASE slot WHEN ? THEN 0 ELSE 1 END, slot", (MAIN_SLOT,))]

    def drop_workers(self, keep: Iterable[str]) -> None:
        """Forget rows of slots that no longer exist (concurrency lowered)."""
        keep = list(keep)
        with self._tx() as c:
            c.execute(f"DELETE FROM workers WHERE slot NOT IN ({','.join('?' * len(keep))})", keep)

    # ---- self-check results (worker -> web)

    def save_checks(self, results: Iterable, now: float | None = None) -> None:
        """Replace the stored result of each given check."""
        ts = time.time() if now is None else now
        with self._tx() as c:
            for r in results:
                c.execute("INSERT OR REPLACE INTO checks VALUES (?, ?, ?, ?)", (r.name, r.status, r.detail, ts))

    def checks(self) -> list[dict]:
        """Last stored result of every check."""
        return [dict(r) for r in self._read("SELECT * FROM checks ORDER BY name")]
