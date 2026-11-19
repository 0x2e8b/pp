"""Uploaded profiles: check a profiles.json before it replaces what is running.

The mounted profiles directory is read-only, so an uploaded file lives in the state directory as an
override: `profiles.override.json`. A candidate is first *staged* (validated, diffed against the
active profiles, nothing changes), then *applied* (re-validated, previous override kept as
`profiles.override.json.prev`, written atomically, book reloaded). Removing the override (revert)
goes back to the mounted file. A candidate with errors can never be applied.

The descriptive fields read from Sycope live in a sidecar (`profiles.info_path`). A rebuild from Sycope
stages its own sidecar; an uploaded file has none, so applying it keeps what the running profiles show.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from typing import Any

from sycope_recorder.alert import parse_alert
from sycope_recorder.config import Settings, write_keeping_prev
from sycope_recorder.config_store import clear_staged, prune_staged
from sycope_recorder.profiles import (
    EDITABLE, INFO, MAX_RANGE_S, PACKET_DIMS, ProfileBook, dumps_info, info_of, info_path, profile_bpf,
    profiles_of, range_seconds,
)

log = logging.getLogger("sycope_recorder")

MAX_BYTES = 5_000_000
MAX_PROFILES = 5000
_KNOWN = set(EDITABLE) | set(INFO)  # the older single-list format carries the descriptive fields too
_TOP = {"_help", "format", "profiles"}
_SYNTH = {"id": "check", "clientIp": "10.0.0.1", "serverIp": "10.0.0.2", "serverPort": 443,
          "protocol": "tcp", "unixTimestamp": 1782050580}


def _read(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def override_path(settings: Settings) -> str:
    return os.path.join(settings.state_dir, "profiles.override.json")


def _staged_dir(settings: Settings) -> str:
    return os.path.join(settings.state_dir, "profiles.staged")


def active_path(settings: Settings) -> tuple[str, str]:
    """(path, source): the uploaded override when it is a valid file, else the mounted file."""
    path = override_path(settings)
    if os.path.exists(path):
        try:
            if not validate(_read(path))["errors"]:
                return path, "uploaded"
        except OSError:
            pass
    return settings.profiles_file, ("file" if settings.profiles_file else "none")


def active_info(settings: Settings) -> dict:
    path, source = active_path(settings)
    info: dict[str, Any] = {"path": path, "source": source, "sha": None, "mtime": None,
                            "has_prev": os.path.exists(override_path(settings) + ".prev")}
    try:
        info["sha"] = hashlib.sha256(_read(path)).hexdigest()[:12]
        info["mtime"] = int(os.stat(path).st_mtime)
    except OSError:
        pass
    return info


def validate(raw: bytes) -> dict:
    """{"errors": [...], "warnings": [...], "profiles": [...] | None}. Errors block applying."""
    errors: list[str] = []
    warnings: list[str] = []
    if len(raw) > MAX_BYTES:
        return {"errors": [f"file is larger than {MAX_BYTES // 1_000_000} MB"], "warnings": [], "profiles": None}
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        return {"errors": [f"not valid UTF-8 JSON: {exc}"], "warnings": [], "profiles": None}
    if isinstance(data, dict) and set(data) - _TOP:
        warnings.append(f"unknown top-level keys ignored: {', '.join(sorted(set(data) - _TOP)[:8])}")
    legacy = isinstance(data, list)
    data = profiles_of(data)
    if data is None:
        return {"errors": ['the file must be {"profiles": [...]} (or the older JSON list of profiles)'],
                "warnings": [], "profiles": None}
    if not data:
        return {"errors": ["the list is empty: applying it would remove every profile"], "warnings": [],
                "profiles": None}
    if len(data) > MAX_PROFILES:
        return {"errors": [f"more than {MAX_PROFILES} profiles"], "warnings": [], "profiles": None}

    seen: set[str] = set()
    unknown: set[str] = set()
    no_filter = 0
    for i, p in enumerate(data):
        where = f"profile {i + 1}"
        before = len(errors)
        if not isinstance(p, dict):
            errors.append(f"{where}: not an object")
            continue
        did = p.get("def_id")
        where = f"profile {i + 1} ({p.get('name') or did or '?'})"
        if not isinstance(did, str) or not did:
            errors.append(f"{where}: def_id must be a non-empty string")
        elif did in seen:
            errors.append(f"{where}: duplicate def_id {did}")
        else:
            seen.add(did)
        if not isinstance(p.get("name"), str) or not p.get("name"):
            errors.append(f"{where}: name must be a non-empty string")
        if "rule_id" in p and p["rule_id"] is not None and not isinstance(p["rule_id"], str):
            errors.append(f"{where}: rule_id must be a string")
        rng = range_seconds(p)
        if rng is None:
            errors.append(f"{where}: time_range_s must be an integer from 1 to {MAX_RANGE_S}")
        elif rng > 6 * 3600:
            warnings.append(f"{where}: time_range_s {rng} needs a rolling buffer of more than 6 h")
        dims = p.get("packet_dims", [])
        if not isinstance(dims, list) or not all(
                isinstance(d, dict) and d.get("field") in PACKET_DIMS and isinstance(d.get("alias"), str)
                for d in dims):
            errors.append(f"{where}: packet_dims must be a list of {{alias, field}} with field in {list(PACKET_DIMS)}")
            dims = []
        static = p.get("static", {})
        if not isinstance(static, dict) or any(
                k not in ("serverPort", "protocol") or not isinstance(v, list)
                or not all(isinstance(n, int) and not isinstance(n, bool) and 0 <= n <= 65535 for n in v)
                for k, v in static.items()):
            errors.append(f"{where}: static must map serverPort/protocol to lists of integers")
            static = {}
        for key in ("alert_key", "macros", "notes", "unfilterable"):
            if key in p and not (isinstance(p[key], list)):
                errors.append(f"{where}: {key} must be a list")
        if "active" in p and not isinstance(p["active"], bool):
            errors.append(f"{where}: active must be true or false")
        if "lists" in p and not isinstance(p["lists"], dict):
            errors.append(f"{where}: lists must be an object")
        unknown |= set(p) - (_KNOWN if legacy else set(EDITABLE))
        shape = p.get("shape")
        if isinstance(shape, str) and not shape.startswith(("aggregate", "alerts:", "unknown")):
            expect = "+".join(f for f in PACKET_DIMS if f in {d.get("field") for d in dims}) or "static"
            if shape != expect:
                warnings.append(f"{where}: shape \"{shape}\" does not match its packet_dims (\"{expect}\"): the "
                                "recorder filters by packet_dims; shape is only a label")
        if not dims and not static and p.get("active", True):
            no_filter += 1
        if len(errors) == before:
            try:  # the real code path: a filter for a synthetic alert must build
                profile_bpf(p, parse_alert(dict(_SYNTH)))
            except Exception as exc:
                errors.append(f"{where}: cannot build a filter: {exc!r}")
    if unknown:
        info = sorted(unknown & set(INFO))
        if info:
            warnings.append(f"descriptive keys ignored: {', '.join(info[:8])} (read from Sycope into the profiles' "
                            "info file; editing them here changes nothing)")
        if unknown - set(INFO):
            warnings.append(f"unknown keys ignored: {', '.join(sorted(unknown - set(INFO))[:8])}")
    if no_filter:
        warnings.append(f"{no_filter} active profile(s) have no packet keys (whole-link aggregates answer NO BPF FILTER)")
    return {"errors": errors[:50] + ([f"... and {len(errors) - 50} more"] if len(errors) > 50 else []),
            "warnings": warnings, "profiles": None if errors else data}


USED = ("time_range_s", "packet_dims", "static", "rule_id")  # what the recorder acts on (besides def_id)
LABELS = ("name", *INFO)  # shown, never used to build a filter or window


def diff(old: list[dict], new: list[dict], new_info: dict[str, dict] | None = None) -> dict:
    """What applying `new` changes. Without `new_info` (an upload) the descriptive fields stay as they are."""
    o = {p["def_id"]: p for p in old if p.get("def_id")}
    n = {p["def_id"]: ({**o.get(p["def_id"], {}), **p} if new_info is None else
                       {**new_info.get(str(p["def_id"]), {}), **p}) for p in new if p.get("def_id")}
    changed = []
    for k in sorted(set(o) & set(n)):
        used = [f for f in USED if o[k].get(f) != n[k].get(f)]
        info = [f for f in LABELS if o[k].get(f) != n[k].get(f)]
        if used or info:
            changed.append({"name": n[k].get("name"), "fields": used, "informational": info})
    return {"added": sorted(str(n[k].get("name")) for k in set(n) - set(o)),
            "removed": sorted(str(o[k].get("name")) for k in set(o) - set(n)), "changed": changed}


def _staged_info(settings: Settings, token: str) -> dict[str, dict] | None:
    try:
        data = json.loads(_read(os.path.join(_staged_dir(settings), f"{token}.info.json")))
    except (OSError, ValueError):
        return None
    defs = data.get("definitions") if isinstance(data, dict) else None
    return defs if isinstance(defs, dict) else None


def stage(settings: Settings, raw: bytes, current: ProfileBook, info: dict[str, dict] | None = None) -> dict:
    """Validate `raw`, keep it for review, and report what applying would change. `info` is the sidecar of a
    rebuild from Sycope (an upload has none)."""
    report = validate(raw)
    token = hashlib.sha256(raw + json.dumps(info, sort_keys=True).encode()).hexdigest()[:16]
    report["token"] = token
    if info is None:
        info = _staged_info(settings, token)
    report["diff"] = (diff(current.profiles, report["profiles"], info) if report["profiles"] is not None
                      else None)
    report["count"] = len(report["profiles"]) if report["profiles"] is not None else 0
    report.pop("profiles")
    if not report["errors"]:
        os.makedirs(_staged_dir(settings), exist_ok=True)
        with open(os.path.join(_staged_dir(settings), f"{token}.json"), "wb") as fh:
            fh.write(raw)
        if info is not None:
            with open(os.path.join(_staged_dir(settings), f"{token}.info.json"), "w") as fh:
                fh.write(dumps_info(info))
        prune_staged(_staged_dir(settings), keep=token)
    return report


def staged_report(settings: Settings, token: str, current: ProfileBook) -> dict | None:
    if not token.isalnum():
        return None
    try:
        raw = _read(os.path.join(_staged_dir(settings), f"{token}.json"))
    except OSError:
        return None
    return stage(settings, raw, current, _staged_info(settings, token))


def apply(settings: Settings, token: str, current: ProfileBook | None = None) -> tuple[bool, str]:
    """Replace the active profiles by the staged file, atomically, keeping the previous override. The sidecar
    is the staged one (a rebuild) or, for an upload, what the running profiles show (`current`)."""
    if not token.isalnum():
        return False, "bad token"
    try:
        raw = _read(os.path.join(_staged_dir(settings), f"{token}.json"))
    except OSError:
        return False, "the staged file is gone: upload it again"
    report = validate(raw)
    if report["errors"]:
        return False, "validation failed: " + report["errors"][0]
    target = override_path(settings)
    info = _staged_info(settings, token)
    if info is None:
        info = info_of(current.profiles) if current is not None else {}
    try:  # the profiles file last: it decides what is active
        os.makedirs(settings.state_dir, exist_ok=True)
        write_keeping_prev([(info_path(target), dumps_info(info).encode()), (target, raw)])
    except OSError as exc:
        log.error("could not save the uploaded profiles to %s: %s", target, exc)
        return False, f"could not save {target}: {exc.strerror or exc}; the active profiles are unchanged"
    clear_staged(_staged_dir(settings))  # this candidate, its import report, and the ones it supersedes
    return True, f"{len(report['profiles'])} profiles applied at {time.strftime('%H:%M:%S', time.gmtime())} UTC"


def revert(settings: Settings) -> tuple[bool, str]:
    """Drop the uploaded override (kept as .prev) so the mounted file is active again: (done, message)."""
    target = override_path(settings)
    if not os.path.exists(target):
        return False, "No uploaded profiles to remove"
    try:
        os.replace(target, target + ".prev")
    except OSError as exc:
        log.error("could not remove the uploaded profiles %s: %s", target, exc)
        return False, f"NOT removed: {target}: {exc.strerror or exc}; the uploaded profiles stay active"
    try:  # the override is gone already; a sidecar left behind is replaced by the next apply
        if os.path.exists(info_path(target)):
            os.replace(info_path(target), info_path(target) + ".prev")
    except OSError as exc:
        log.warning("uploaded profiles removed, but their sidecar %s stays: %s", info_path(target), exc)
    return True, "Back to the mounted profiles file"


def save_meta(settings: Settings, token: str, meta: dict) -> None:
    """The import report (what was read from Sycope) kept next to the staged candidate."""
    os.makedirs(_staged_dir(settings), exist_ok=True)
    with open(os.path.join(_staged_dir(settings), f"{token}.meta.json"), "w") as fh:
        json.dump(meta, fh)


def load_meta(settings: Settings, token: str) -> dict | None:
    if not token.isalnum():
        return None
    try:
        return json.loads(_read(os.path.join(_staged_dir(settings), f"{token}.meta.json")))
    except (OSError, ValueError):
        return None
