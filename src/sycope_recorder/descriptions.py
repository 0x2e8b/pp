"""Alert descriptions from the Sycope definitions, shown on the queue and status pages.

Display only: nothing here reaches a BPF filter or a profile. The text comes from
`miscAlertData.alertDescription` of each definition and is stored by definition id in
`alert_descriptions.json` in the state dir, rewritten on every "Rebuild from Sycope". The page
looks it up at render time, so a refresh also updates jobs that are already in the queue.
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # the installer imports this on a host without pydantic: Settings is only an annotation
    from sycope_recorder.config import Settings

NAME = "alert_descriptions.json"
MAX_LEN = 2000

_cache: dict[str, tuple[float, dict[str, str]]] = {}


def _path(settings: Settings) -> str:
    return os.path.join(settings.state_dir, NAME)


def extract(defs: list[dict]) -> dict[str, str]:
    """definition id -> description, for the definitions that have one."""
    out: dict[str, str] = {}
    for d in defs:
        misc = d.get("miscAlertData")
        if isinstance(misc, str):
            try:
                misc = json.loads(misc)
            except ValueError:
                continue
        text = misc.get("alertDescription") if isinstance(misc, dict) else None
        if d.get("id") and isinstance(text, str) and text.strip():
            out[str(d["id"])] = text.strip()[:MAX_LEN]
    return out


def save(settings: Settings, descriptions: dict[str, str]) -> None:
    os.makedirs(settings.state_dir, exist_ok=True)
    tmp = _path(settings) + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(descriptions, fh)
    os.replace(tmp, _path(settings))


def load(settings: Settings) -> dict[str, str]:
    """Cached by mtime; empty when nothing was imported yet or the file is unreadable."""
    path = _path(settings)
    try:
        mtime = os.stat(path).st_mtime
    except OSError:
        return {}
    hit = _cache.get(path)
    if hit and hit[0] == mtime:
        return hit[1]
    try:
        with open(path) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    data = {str(k): v for k, v in data.items() if isinstance(v, str)} if isinstance(data, dict) else {}
    _cache[path] = (mtime, data)
    return data


def attach(settings: Settings, jobs: list[dict]) -> None:
    """Put `alert_desc` on each job whose alert definition has a description."""
    descs = load(settings)
    if not descs:
        return
    for j in jobs:
        try:
            def_id = json.loads(j.get("alert_meta") or "{}").get("definitionId")
        except (ValueError, AttributeError):
            continue
        if def_id and def_id in descs:
            j["alert_desc"] = descs[def_id]
