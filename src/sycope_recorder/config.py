"""Process-wide configuration: env-driven Settings and its loader.

All runtime configuration is read once at import time in main.py via
get_settings(), which either returns a validated Settings instance or exits
the process with an ops-readable error. Values are fixed for the life of a process; a configuration
change restarts both processes (web: gunicorn HUP, worker: exits when control.config_generation
changes, see worker.py).
"""

from __future__ import annotations

import json
import os
import shutil
import sys

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# The recorder's BPF filter modes (bpf.FILTER_MODES); default_filter falls back to
# "full" (see _known_filter) if it isn't one of these.
VALID_FILTER_MODES: frozenset[str] = frozenset(
    {"full", "hosts", "client", "server", "port"}
)


class Settings(BaseSettings):
    """App configuration, populated from SR_-prefixed environment variables.

    Each field maps to an env var of the same name uppercased with an SR_
    prefix (e.g. `public_host` <- `SR_PUBLIC_HOST`); unrecognized env vars
    are ignored rather than rejected. `public_host` is the only required
    field — everything else has a legacy-compatible default.
    """

    model_config = SettingsConfigDict(env_prefix="SR_", env_file=None, extra="ignore")

    public_host: str
    download_prefix: str = "downloads"
    timeline_dir: str = "/storage/pcaps/rolling"
    output_dir: str = "/storage/pcaps/alerts"
    default_filter: str = "full"
    default_before: int = 360
    default_after: int = 360
    max_concurrent_extractions: int = 1
    extract_timeout_seconds: int = 300
    # Overrides public_host in the returned download URL only. Use it when
    # operators reach the files through another address than Caddy's own, e.g.
    # Sycope Passthrough: "sycope.example/npm/api/v1/passthrough/recorder".
    # public_host stays required (Caddy TLS name, default_sni).
    download_url_base: str | None = None
    npcapextract_path: str = "npcapextract"
    # npcapextract drops privileges to "nobody" before opening the output
    # file unless told otherwise (-u). The api container runs as root, so by
    # default stay root; empty string omits -u (npcapextract's own default).
    npcapextract_user: str = "root"
    # PCAPs are evidence attached to alerts: by default nothing is deleted
    # automatically (0 = disabled). Disk is protected by min_free_bytes below.
    retention_max_age_days: int = 0
    retention_max_total_bytes: int = 0
    retention_interval_seconds: int = 3600
    log_level: str = "INFO"
    log_format: str = "text"

    state_dir: str = "/var/lib/sycope-recorder"
    queue_max: int = 2000
    job_max_attempts: int = 3
    job_retry_delay_seconds: int = 120
    job_history_days: int = 30
    # Worker process (worker.py). On stop or reload it lets running extractions finish for up to
    # worker_stop_grace_seconds, then kills them and puts the jobs back in the queue. The web reports
    # the worker as dead when its heartbeat (every worker_heartbeat_seconds) is older than
    # worker_stale_seconds.
    worker_stop_grace_seconds: int = 30
    worker_heartbeat_seconds: int = 5
    worker_stale_seconds: int = 60
    # n2disk closes (and indexes) a file every --max-file-duration seconds
    # (docs/reference/n2disk.conf: 300). Data newer than the last closed file
    # is invisible to npcapextract, so a job is not run before
    # window_end + chunk_seconds + ready_margin_seconds.
    chunk_seconds: int = 300
    ready_margin_seconds: int = 30

    # Per-definition extraction profiles (tools/profiles/gen_profiles.py). When a
    # file is set and an alert's definition has a profile, the profile decides
    # the BPF filter and the window ([T - timeRange - lag, T + margin]) and the
    # before/after/filter query parameters are ignored for that alert.
    # exporter_lag_seconds: how much earlier than its bucket a flow's packets can
    # be: exporter idle timeout + the longest flow to cover (docs/PROFILES.md). Measured
    # in the lab: coverage is complete up to a delay equal to this value and drops sharply
    # above it, silently. Retries after a miss look back further (2x, 4x, ... up to
    # window_max_lag_seconds). A PCAP whose first packet is within window_warn_seconds of the
    # window start gets a "window may have cut the beginning" warning.
    profiles_file: str = ""
    exporter_lag_seconds: int = 300
    window_margin_seconds: int = 30
    window_max_lag_seconds: int = 900
    window_warn_seconds: int = 30
    # n2disk keeps the newest packets in memory and closes a file only when the next packet
    # arrives. A job therefore also waits until a file starting after the window end exists (the
    # proof that the file with the window end is closed); on a quiet link that can take long.
    # After quiet_wait_seconds past the due time it extracts anyway.
    quiet_wait_seconds: int = 21600
    quiet_poll_seconds: int = 30

    # Queue page edits (delete, persistent, cancel, retry, re-extract, pausing the worker, profile
    # actions) change state, so they are off by default.
    # debug_bundle enables GET /logs: a zip of what this container sees (recent log, job table,
    # checks, redacted settings). Both are guarded against cross-site requests (api.py).
    queue_edit: bool = False
    debug_bundle: bool = False

    # Rebuild the profiles from Sycope's alert definitions and macros on request (Profiles page). Needs
    # a Sycope account that can read alert definitions and macros: use a read-only one.
    sycope_url: str = ""
    sycope_user: str = ""
    sycope_password: str = ""
    sycope_verify_tls: bool = True

    # Password for downloading and uploading the configuration (Configuration page). Empty = those
    # actions are disabled. Set it in the environment only: it is never part of the downloadable file.
    config_password: str = ""

    # Refuse extractions when the output filesystem has less free space.
    min_free_bytes: int = 5 * 1024**3

    # Background self-check (see checks.py). stale = newest rolling file older
    # than this means n2disk is not writing. silence_warn_hours=0 disables the
    # "no webhook received" warning.
    # False for hosts without a capture (demo with a fake npcapextract): the
    # rolling_fresh check then reports OK/skipped instead of FAIL.
    rolling_check: bool = True
    watchdog_interval_seconds: int = 60
    rolling_stale_seconds: int = 900
    silence_warn_hours: int = 0
    # Internal Caddy listener used to prove caddy serves the same alerts
    # storage as the api (e.g. http://caddy:8081); empty disables the check.
    probe_url: str = ""

    @field_validator("default_filter")
    @classmethod
    def _known_filter(cls, v: str) -> str:
        """Fall back to "full" for an unrecognized mode instead of raising,
        matching the legacy config loader's defaulting behavior — an unknown filter falls back to the default "full"
        (client IP, server IP and port) rather than block startup."""
        return v if v in VALID_FILTER_MODES else "full"

    @field_validator("log_level")
    @classmethod
    def _known_level(cls, v: str) -> str:
        """Refuse an unknown level here: logging.setLevel would otherwise raise a traceback in both processes
        after get_settings, and supervisord would restart them forever. Same values as an upload (config_store)."""
        if v.upper() not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            raise ValueError("DEBUG, INFO, WARNING, ERROR or CRITICAL")
        return v


OVERRIDE_NAME = "config.override.json"
# Not changeable through an upload: the override lives in state_dir, the password guards the upload,
# and the root worker executes npcapextract_path as npcapextract_user and reads/writes the two
# directories. Changing those needs the environment and a restart: .env for config_password,
# npcapextract_user and the retention keys; compose.yaml fixes state_dir, the two directories,
# npcapextract_path and probe_url (they belong to the volumes, the image and the caddy service), so
# those need a compose override.
# The retention keys and min_free_bytes are locked too: the root worker deletes PCAPs by the first and
# fills the disk up to the second, so a compromised web (which can write config.override.json) could
# otherwise make root delete evidence or fill the disk. probe_url: the root worker fetches it (S-8, S-11).
# public_host and download_prefix are read by Caddy (TLS name, download path) and
# worker_stop_grace_seconds by supervisord (the worker's stop wait, docker/entrypoint.sh), each only at
# container start from the environment: an upload could not reach them, so links or the drain would
# disagree with what those components do (A-5, C-9).
LOCKED = ("state_dir", "config_password", "npcapextract_path", "npcapextract_user", "timeline_dir",
          "output_dir", "retention_max_age_days", "retention_max_total_bytes", "retention_interval_seconds",
          "min_free_bytes", "probe_url", "public_host", "download_prefix", "worker_stop_grace_seconds")

# The range rules, one set for both paths (A-5). An upload that breaks one is refused
# (config_store.validate). A value from the environment (or from an override written before a rule
# existed) that breaks one is replaced by the nearest valid value, with a warning at start and in the
# `settings` self-check (get_settings, checks.check_settings): the way max_concurrent_extractions and
# default_filter always degraded, so an .env that started the service before an update still starts it.
# key: (minimum, maximum); None = no bound on that side.
BOUNDS: dict[str, tuple[int | None, int | None]] = {
    "chunk_seconds": (1, None),
    "queue_max": (1, None),
    "job_max_attempts": (1, None),
    # The hung-slot watchdog fires at this + checks.HUNG_MARGIN: without a ceiling a hung npcapextract
    # could hold a worker slot indefinitely.
    "extract_timeout_seconds": (10, 3600),
    # Worker slots: each one is a root npcapextract reading the rolling buffer (S-11).
    "max_concurrent_extractions": (1, 16),
    # 0 would make the worker prune every finished job row at once (S-11).
    "job_history_days": (1, None),
    "exporter_lag_seconds": (0, None),
    "window_margin_seconds": (0, None),
    "window_max_lag_seconds": (0, None),
    "window_warn_seconds": (0, None),
    "default_before": (0, None),
    "default_after": (0, None),
    "ready_margin_seconds": (0, None),
    "min_free_bytes": (0, None),
    "retention_max_age_days": (0, None),
    "retention_max_total_bytes": (0, None),
    "retention_interval_seconds": (1, None),
    "watchdog_interval_seconds": (1, None),
    "quiet_poll_seconds": (1, None),
    "job_retry_delay_seconds": (1, None),
    # compose stop_grace_period is 90 s and supervisord waits grace + 15 s for the worker
    # (docker/entrypoint.sh applies the same bounds).
    "worker_stop_grace_seconds": (1, 60),
}


def _bound_text(lo: int | None, hi: int | None) -> str:
    if hi is None:
        return "must not be negative" if lo == 0 else f"must be at least {lo}"
    return f"must be between {lo} and {hi}"


def rule_breaks(s: Settings) -> list[tuple[str, str, object]]:
    """(key, what is wrong, value to use instead) for every range rule `s` breaks.

    The value to use is the nearest valid one; for a rule without one (a malformed URL, an empty
    public_host) it is the value itself, which is then kept.
    """
    out: list[tuple[str, str, object]] = []
    fixed: dict[str, int] = {}
    for k, (lo, hi) in BOUNDS.items():
        v = getattr(s, k)
        if lo is not None and v < lo:
            fixed[k] = lo
        elif hi is not None and v > hi:
            fixed[k] = hi
        if k in fixed:
            out.append((k, _bound_text(lo, hi), fixed[k]))
    lag = fixed.get("exporter_lag_seconds", s.exporter_lag_seconds)
    if fixed.get("window_max_lag_seconds", s.window_max_lag_seconds) < lag:
        out.append(("window_max_lag_seconds", "must be at least exporter_lag_seconds", lag))
    if s.log_format not in ("text", "json"):
        out.append(("log_format", "text or json", "text"))  # logging_config treats anything else as text
    if s.sycope_url and not s.sycope_url.startswith(("http://", "https://")):
        out.append(("sycope_url", "must start with http:// or https://", s.sycope_url))
    if s.download_url_base and s.download_url_base.startswith(("http://", "https://")):
        out.append(("download_url_base", "give the host and path without https://", s.download_url_base))
    if not s.public_host.strip():
        out.append(("public_host", "must not be empty", s.public_host))
    return out


def within_rules(s: Settings, source=lambda k: f"SR_{k.upper()}") -> tuple[Settings, list[str]]:
    """`s` with every value that breaks a range rule replaced (rule_breaks), and one warning per break.

    `source(key)` names where the value came from in the warning.
    """
    update: dict[str, object] = {}
    notes: list[str] = []
    for k, why, use in rule_breaks(s):
        old = getattr(s, k)
        shown = f"{source(k)}={old}" if isinstance(old, int) else source(k)
        if use == old:
            notes.append(f"{shown}: {k} {why}; kept as it is")
        else:
            update[k] = use
            notes.append(f"{shown}: {k} {why}; using {use}")
    return (s.model_copy(update=update) if update else s), notes


def override_file(state_dir: str) -> str:
    return os.path.join(state_dir, OVERRIDE_NAME)


def _read_override(state_dir: str) -> dict:
    try:
        with open(override_file(state_dir)) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def load_override(state_dir: str) -> dict:
    """Settings uploaded through the Configuration page (only keys that differ from the environment)."""
    return {k: v for k, v in _read_override(state_dir).items() if k in Settings.model_fields and k not in LOCKED}


def write_keeping_prev(files: list[tuple[str, bytes]], mode: int | None = None) -> None:
    """Replace each (path, data), in order, keeping the file it replaces as `path + ".prev"`.

    Every new content is written and fsynced to a temporary file next to its path first; only then
    is the current file kept as `.prev` (a hard link, a copy where the filesystem cannot link) and
    the temporary renamed over it. A path that exists is therefore never absent, and a failure while
    writing (disk full, I/O error) raises OSError with every path and `.prev` as they were and no
    temporary file left. The new file is created like the rest of the state directory: mode
    0666 & ~umask, owned by the writing process. Not atomic across paths: put the one that decides
    what is active last.

    With `mode` (0o600 for a file holding a secret, S-12) the temporary is created with that mode, never
    wider, and `.prev` is set to it too. Being a hard link, that also tightens the still-active file of an
    older version; a link to a file this process cannot chmod (another owner) is replaced by a copy.
    """
    pid = os.getpid()
    temps: list[str] = []
    try:
        for path, data in files:
            temps.append(f"{path}.tmp{pid}")
            with open(temps[-1], "wb", opener=None if mode is None else _opener(mode)) as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
        keep: list[tuple[str, str]] = []
        for path, _ in files:
            if os.path.exists(path):
                temps.append(f"{path}.prev.tmp{pid}")
                _link_or_copy(path, temps[-1])
                if mode is not None:
                    _restrict(path, temps[-1], mode)
                keep.append((temps[-1], path + ".prev"))
        for tmp, prev in keep:
            os.replace(tmp, prev)
        for (path, _), tmp in zip(files, temps):
            os.replace(tmp, path)
    finally:
        for tmp in temps:  # renamed ones are gone already
            try:
                os.remove(tmp)
            except OSError:
                pass


def _link_or_copy(src: str, dst: str) -> None:
    try:
        os.remove(dst)  # left by a crashed run of the same pid
    except FileNotFoundError:
        pass
    try:
        os.link(src, dst)
    except OSError:  # no hard links here (some FUSE/vfat), or fs.protected_hardlinks refused them
        shutil.copy2(src, dst)


def _opener(mode: int):
    """For open(..., opener=): create with `mode` and set it on a file that already existed."""
    def opener(path: str, flags: int) -> int:
        fd = os.open(path, flags, mode)
        try:
            os.fchmod(fd, mode)
        except OSError:
            os.close(fd)
            raise
        return fd
    return opener


def _restrict(src: str, dst: str, mode: int) -> None:
    """chmod `dst` (a hard link to or copy of `src`) to `mode`; a link to a file of another owner,
    which cannot be changed, is replaced by a copy owned by this process."""
    try:
        os.chmod(dst, mode)
    except PermissionError:
        os.remove(dst)
        shutil.copy2(src, dst)
        os.chmod(dst, mode)


# What the last get_settings() in this process replaced or ignored (one line each); the `settings`
# self-check (checks.py) reports it, so doctor and the System page show it, not only the start log.
NOTES: list[str] = []


def get_settings() -> Settings:
    """Build Settings, or exit the process with a clean stderr message.

    Environment first, then the uploaded override on top (init values beat the environment). An
    override that no longer validates is ignored with a message, so a bad upload cannot stop the
    service from starting. A value that breaks a range rule is replaced by the nearest valid one
    (within_rules), and a locked key in the override is ignored; each with a WARNING line here and
    in NOTES.

    This runs at import time in main.py, before logging or anything else is
    set up — an unhandled pydantic ValidationError there would surface as a
    raw traceback with no operational context. Converting it to a one-line
    stderr message and SystemExit(1) gives ops a readable reason (e.g.
    missing SR_PUBLIC_HOST) instead of a stack trace to decipher.
    """
    try:
        base = Settings()
    except Exception as exc:  # pragma: no cover - exercised at process start
        print(f"ERROR: invalid configuration: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    path = override_file(base.state_dir)
    notes = [f"{path}: {k} can only be set in the environment (SR_{k.upper()} in .env): the uploaded value "
             "is ignored" for k in sorted(_read_override(base.state_dir)) if k in LOCKED]
    override = load_override(base.state_dir)
    settings = base
    if override:
        try:
            settings = Settings(**override)
        except Exception as exc:  # pragma: no cover - a stale override must not stop the service
            print(f"WARNING: ignoring {path}: {exc}", file=sys.stderr)
            override = {}

    def source(k: str) -> str:
        if k in override:
            return f"{path}: {k}"
        return f"SR_{k.upper()}" if f"SR_{k.upper()}" in os.environ else f"{k} (default)"

    settings, broke = within_rules(settings, source)
    notes += broke
    NOTES[:] = notes
    for note in notes:
        print(f"WARNING: {note}", file=sys.stderr)
    return settings


def legacy_env_warnings() -> list[str]:
    """Settings of earlier releases that are still in the environment but do nothing now.

    Logged by both processes at start so a forgotten SR_MODE=sync in an old .env is visible instead
    of silently ignored.
    """
    out = []
    if "SR_MODE" in os.environ:
        out.append("SR_MODE is set but no longer used: 0.4 always queues (remove it from .env)")
    return out
