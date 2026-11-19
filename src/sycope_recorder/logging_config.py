"""Configures root logging (text or JSON) and funnels uvicorn/gunicorn
logs through the same handler so container/journal output has one
consistent format regardless of which component emitted the line.

Each process (web, worker) logs to stdout, which supervisord forwards to
`docker logs`, and to a file: state_dir/logs/web.log for the web, and for the root worker
WORKER_LOG_DIR/worker.log (a directory the web can only read: root must never write into one the
web controls). Without that directory (development, tests) worker.log goes to state_dir/logs too.
The debug bundle reads the files, so the web can show the worker's log although they are separate
processes.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys

from sycope_recorder.config import Settings

WORKER_LOG_DIR = "/var/log/sycope-recorder"
LOG_FILE_BYTES = 10 * 1024 * 1024
LOG_FILE_COUNT = 3


class _JsonFormatter(logging.Formatter):
    """Formats log records as JSON, safely encoding the message.

    Building the JSON string via json.dumps (rather than interpolating
    %(message)s directly into a hand-written JSON template) ensures the
    output is always valid JSON, even if the message contains quotes,
    newlines, or backslashes.
    """

    def __init__(self, process: str) -> None:
        """Records carry the process name so a line in the shared bundle says which process wrote it."""
        super().__init__()
        self.process = process

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "time": self.formatTime(record),
            "level": record.levelname,
            "process": self.process,
            "logger": record.name,
            "message": record.getMessage(),
        }
        return json.dumps(payload)


class _GroupFile(logging.handlers.RotatingFileHandler):
    """Rotating log file kept at mode 0660: the web (group sr) reads the worker's file for the bundle.

    The worker runs as root in a directory the web can write: the file is opened with O_NOFOLLOW and
    chmodded through the descriptor, so a symlink planted at the path is refused instead of followed."""

    def _open(self):
        """Opened and chmodded on every rollover too, so a new file never comes out at 0640."""
        fd = os.open(self.baseFilename, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o660)
        try:
            try:
                os.fchmod(fd, 0o660)
            except PermissionError:
                pass  # a file owned by the other process (root's, opened by sr): usable as it is
            return os.fdopen(fd, self.mode, encoding=self.encoding, errors=self.errors)
        except BaseException:
            os.close(fd)
            raise


def _log_path(settings: Settings, process: str) -> str:
    """One file per process: two writers on one file would interleave and rotate under each other.
    The worker's file lives outside the shared state directory whenever the image provides the place."""
    if process == "worker" and os.path.isdir(WORKER_LOG_DIR):
        return os.path.join(WORKER_LOG_DIR, "worker.log")
    return os.path.join(settings.state_dir, "logs", f"{process}.log")


def log_tail(settings: Settings, process: str, max_bytes: int = 2 * 1024 * 1024) -> str:
    """The last max_bytes of a process's current log file ("" when there is none)."""
    try:
        with open(_log_path(settings, process), "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - max_bytes))
            data = fh.read()
    except OSError:
        return ""
    text = data.decode("utf-8", "replace")
    return text if size <= max_bytes else text.split("\n", 1)[-1]


def setup_logging(settings: Settings, process: str = "web") -> None:
    """Set up the root logger's handlers/formatter and rewire uvicorn/gunicorn
    to use them instead of their own.

    Existing root handlers are cleared first so this is safe to call more
    than once (e.g. re-invoked in tests) without stacking duplicate
    handlers and duplicating every log line. uvicorn/gunicorn loggers are
    then stripped of their own handlers and left to propagate, so every
    log line — ours and theirs — goes through the handlers configured here
    instead of each library formatting independently.

    The file handler is optional: if the log directory is not writable the
    process logs to stdout only and says so once.
    """
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)

    formatter: logging.Formatter
    if settings.log_format == "json":
        formatter = _JsonFormatter(process)
    else:
        formatter = logging.Formatter(f"%(asctime)s [%(levelname)s] [{process}] %(message)s")
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    root.addHandler(handler)
    try:
        os.makedirs(os.path.dirname(_log_path(settings, process)), exist_ok=True)
        fh = _GroupFile(_log_path(settings, process), maxBytes=LOG_FILE_BYTES, backupCount=LOG_FILE_COUNT)
        fh.setFormatter(formatter)
        root.addHandler(fh)
    except OSError as exc:
        root.warning("log file %s not writable (%s): logging to stdout only",
                     _log_path(settings, process), exc)
    root.setLevel(settings.log_level.upper())

    # Route uvicorn/gunicorn logs through the same handlers; drop access spam.
    logging.getLogger("uvicorn.access").disabled = True
    for name in ("uvicorn", "uvicorn.error", "gunicorn.error"):
        lg = logging.getLogger(name)
        lg.handlers = []
        lg.propagate = True
