"""Download, check and upload the configuration (Configuration page).

The recorder is configured by SR_* environment variables. An upload cannot rewrite the host's .env
from inside the container, so it is stored as an *override*, `config.override.json` in the state
directory, holding only the keys that differ from the environment. get_settings() applies it on
start; applying an upload reloads the web (gunicorn HUP) and the worker (control.config_generation,
worker.py). A candidate is validated by building a real Settings from it, staged for review, and
only then applied. Everything is gated by SR_CONFIG_PASSWORD.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import signal
import stat
import time

from pydantic import ValidationError

from sycope_recorder.config import (LOCKED, Settings, load_override, override_file, rule_breaks, within_rules,
                                     write_keeping_prev)

log = logging.getLogger("sycope_recorder")

SECRET = ("sycope_password",)
EDITABLE = [k for k in Settings.model_fields if k not in LOCKED]
_FAILS: list[float] = []
LOCK_AFTER, LOCK_WINDOW = 5, 300


def password_ok(settings: Settings, given: object) -> tuple[bool, str]:
    """Constant-time check with a lockout after repeated failures. (ok, reason when not)."""
    if not settings.config_password:
        return False, "Configuration upload/download is disabled: set SR_CONFIG_PASSWORD"
    now = time.time()
    _FAILS[:] = [t for t in _FAILS if now - t < LOCK_WINDOW]
    if len(_FAILS) >= LOCK_AFTER:
        return False, "Too many wrong passwords: try again in a few minutes"
    if isinstance(given, str) and hmac.compare_digest(given.encode(), settings.config_password.encode()):
        return True, ""
    _FAILS.append(now)
    return False, "Wrong configuration password"


def mask(key: str, value):
    return "***" if key in SECRET and value else value


def current(settings: Settings) -> dict:
    return {k: getattr(settings, k) for k in EDITABLE}


def env_baseline(settings: Settings) -> Settings:
    """Settings as the environment alone gives them (no override), with the range rules applied as at
    start (config.within_rules): a value the service replaced is not written into the override."""
    try:
        return within_rules(Settings())[0]
    except ValidationError:  # no SR_PUBLIC_HOST in this process's environment (tests)
        return within_rules(Settings(public_host=settings.public_host))[0]


def export(settings: Settings) -> dict:
    """The downloadable file: every editable setting with its current value (secrets in clear)."""
    return current(settings)


def rows(settings: Settings) -> list[dict]:
    """For the page: key, value (secrets masked), default, where the value comes from."""
    override = load_override(settings.state_dir)
    out = []
    for k in [f for f in Settings.model_fields if f != "config_password"]:
        field = Settings.model_fields[k]
        default = None if field.is_required() else field.default
        if k in override:
            source = "uploaded"
        elif f"SR_{k.upper()}" in os.environ:
            source = "environment"
        else:
            source = "default"
        out.append({"key": k, "value": mask(k, getattr(settings, k)), "default": mask(k, default),
                    "source": source, "locked": k in LOCKED})
    return out


def validate(settings: Settings, candidate: object) -> dict:
    """{"errors", "warnings", "changes", "override"}; `override` (the file to store) only when no errors."""
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(candidate, dict):
        return {"errors": ["the configuration must be a JSON object {setting: value}"], "warnings": [],
                "changes": [], "override": None}
    cand = {k: v for k, v in candidate.items() if not str(k).startswith("_")}
    for k in cand:
        if k in LOCKED:
            errors.append(f"{k}: cannot be changed here (locked)")
        elif k not in Settings.model_fields:
            errors.append(f"{k}: unknown setting")
    if errors:
        return {"errors": errors, "warnings": [], "changes": [], "override": None}
    old = current(settings)
    merged = dict(old)
    for k, v in cand.items():
        if k in SECRET and v == "***":
            continue  # a masked secret keeps its value
        merged[k] = v
    try:
        new = Settings(**merged, config_password=settings.config_password)
    except ValidationError as exc:
        for e in exc.errors():
            errors.append(f"{'.'.join(str(x) for x in e['loc'])}: {e['msg']}")
        return {"errors": errors, "warnings": [], "changes": [], "override": None}
    errors += _rules(new)
    changes = [{"key": k, "old": mask(k, old[k]), "new": mask(k, getattr(new, k))}
               for k in EDITABLE if getattr(new, k) != old[k]]
    if new.chunk_seconds != settings.chunk_seconds:
        warnings.append("chunk_seconds must equal n2disk --max-file-duration: change n2disk too")
    if new.sycope_url and not new.sycope_password:
        warnings.append("sycope_url is set without a password: Rebuild from Sycope will fail to log in")
    if new.sycope_url and new.sycope_url != old["sycope_url"]:
        from sycope_recorder import sycope_import  # S-8: the same rule the import applies
        try:
            why = sycope_import.refused_target(new.sycope_url)
        except sycope_import.SycopeError as exc:
            why = str(exc)
        if why:
            warnings.append(f"sycope_url: Rebuild from Sycope will refuse it ({why})")
    base = env_baseline(settings)
    override = {k: getattr(new, k) for k in EDITABLE if getattr(new, k) != getattr(base, k)}
    return {"errors": errors, "warnings": warnings, "changes": changes,
            "override": None if errors else override}


def _rules(s: Settings) -> list[str]:
    """The range rules (config.rule_breaks, the same ones applied to the environment at start) for the
    keys an upload can change: a locked key's value comes from the environment, where an out-of-range
    one is replaced at start and reported there, not here. Plus the two directories, which must exist."""
    e = [f"{k}: {why}" for k, why, _ in rule_breaks(s) if k not in LOCKED]
    if not os.path.isdir(s.timeline_dir):
        e.append(f"timeline_dir: {s.timeline_dir} does not exist in the container")
    if not os.path.isdir(s.output_dir):
        e.append(f"output_dir: {s.output_dir} does not exist in the container")
    return e


def _dir(settings: Settings) -> str:
    return os.path.join(settings.state_dir, "config.staged")


# The staged configuration and the override can hold sycope_password in clear (S-12): owner only. The web
# (`sr`) writes and reads them, the root worker reads the override; nothing else does.
SECRET_MODE = 0o600
# Staged candidates of both stores (and profile_store): an upload is reviewed and applied in one sitting
# (upload, review page, Apply), so a candidate older than a day, or beyond the newest ten, is a leftover.
STAGED_MAX_AGE = 24 * 3600
STAGED_KEEP = 10


def prune_staged(directory: str, keep: str = "") -> None:
    """Remove staged candidates older than STAGED_MAX_AGE and all but the newest STAGED_KEEP. A candidate
    is every file named `<token>.*` (its age is its newest file's); the token `keep` always stays."""
    groups: dict[str, list[tuple[str, float]]] = {}
    try:
        names = os.listdir(directory)
    except OSError:
        return
    for name in names:
        path = os.path.join(directory, name)
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if not stat.S_ISDIR(st.st_mode):
            groups.setdefault(name.split(".", 1)[0], []).append((path, st.st_mtime))
    now = time.time()
    newest = sorted(groups, key=lambda t: max(m for _, m in groups[t]), reverse=True)
    for rank, token in enumerate(newest):
        if token == keep:
            continue
        if rank < STAGED_KEEP and now - max(m for _, m in groups[token]) < STAGED_MAX_AGE:
            continue
        for path, _ in groups[token]:
            try:
                os.remove(path)
            except OSError:
                pass


def clear_staged(directory: str) -> None:
    """Remove every staged candidate: after an apply they were reviewed against what is no longer active."""
    try:
        names = os.listdir(directory)
    except OSError:
        return
    for name in names:
        path = os.path.join(directory, name)
        try:
            if not stat.S_ISDIR(os.lstat(path).st_mode):
                os.remove(path)
        except OSError:
            pass


def stage(settings: Settings, candidate: object) -> dict:
    report = validate(settings, candidate)
    ov = report.pop("override")
    token = hashlib.sha256(json.dumps(ov, sort_keys=True, default=str).encode()).hexdigest()[:16]
    report["token"] = token
    if ov is not None:
        os.makedirs(_dir(settings), exist_ok=True)
        fd = os.open(os.path.join(_dir(settings), f"{token}.json"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                     SECRET_MODE)
        try:
            os.fchmod(fd, SECRET_MODE)  # a file left by an older version with 0664
        except OSError:
            os.close(fd)
            raise
        with open(fd, "w") as fh:
            json.dump({"override": ov, "changes": report["changes"], "warnings": report["warnings"]}, fh,
                      default=str)
        prune_staged(_dir(settings), keep=token)
    return report


def staged(settings: Settings, token: str) -> dict | None:
    if not token.isalnum():
        return None
    try:
        with open(os.path.join(_dir(settings), f"{token}.json")) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def apply(settings: Settings, token: str) -> tuple[bool, str]:
    st = staged(settings, token)
    if st is None:
        return False, "the staged configuration is gone: upload it again"
    # one more real validation of the stored override against the current state
    check = validate(settings, st["override"])
    if check["errors"]:
        return False, "validation failed: " + check["errors"][0]
    target = override_file(settings.state_dir)
    try:
        data = json.dumps(st["override"], indent=1, default=str).encode()
    except (TypeError, ValueError) as exc:
        return False, f"the staged configuration cannot be saved: {exc}"
    try:  # the running configuration stays active, and on disk, unless the new file is complete
        os.makedirs(settings.state_dir, exist_ok=True)
        write_keeping_prev([(target, data)], mode=SECRET_MODE)
    except OSError as exc:
        log.error("could not save the configuration to %s: %s", target, exc)
        return False, f"could not save {target}: {exc.strerror or exc}; the running configuration is unchanged"
    clear_staged(_dir(settings))
    return True, f"configuration applied ({len(st['changes'])} change(s)); the service reloads"


def revert(settings: Settings) -> tuple[bool, str]:
    """Drop the uploaded configuration (kept as .prev): (done, why not) - why is empty when done."""
    target = override_file(settings.state_dir)
    if not os.path.exists(target):
        return False, "No uploaded configuration"
    try:
        os.replace(target, target + ".prev")
    except OSError as exc:
        log.error("could not remove the uploaded configuration %s: %s", target, exc)
        return False, f"NOT removed: {target}: {exc.strerror or exc}; the uploaded configuration stays active"
    try:  # an override written by an older version is still 0664
        os.chmod(target + ".prev", SECRET_MODE)
    except OSError as exc:
        log.warning("could not restrict %s.prev to owner-only: %s", target, exc)
    return True, ""


def reload_service() -> bool:
    """Gracefully reload gunicorn (HUP to the master): new workers read the new configuration.
    False when not running under gunicorn (tests, a development server)."""
    ppid = os.getppid()
    try:
        with open(f"/proc/{ppid}/cmdline", "rb") as fh:
            cmd = fh.read().decode(errors="replace")
    except OSError:
        return False
    if "gunicorn" not in cmd:
        return False
    os.kill(ppid, signal.SIGHUP)
    return True
