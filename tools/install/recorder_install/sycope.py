"""Read-only look at the Sycope instance: can we log in, what do the definitions and macros look
like, is there an External Destination that posts to this recorder, is the clock close."""

from __future__ import annotations

import importlib.util
import os
import re
import urllib.parse
from email.utils import parsedate_to_datetime
from typing import Any

import time


def load_client_module(repo: str):
    path = os.path.join(repo, "tools", "profiles", "gen_profiles.py")
    spec = importlib.util.spec_from_file_location("gen_profiles", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def clock_skew_seconds(date_header: str | None, now: float | None = None) -> float | None:
    """Sycope's clock minus ours, from the HTTP Date header (second resolution)."""
    if not date_header:
        return None
    try:
        return parsedate_to_datetime(date_header).timestamp() - (time.time() if now is None else now)
    except (TypeError, ValueError):
        return None


def destination_rows(payload: Any) -> list[dict[str, str]]:
    rows = []
    for it in (payload or {}).get("data", []) if isinstance(payload, dict) else []:
        c = it.get("config") or {}
        rows.append({"name": str(it.get("name") or c.get("name")), "type": str(c.get("type")), "host": str(c.get("host")),
                     "port": str(c.get("port")), "path": str(c.get("path") or ""),
                     "method": str(c.get("method"))})
    return rows


DEAD = "does not exist in Sycope"  # marks the hint of a destination whose Passthrough is gone
_VIA = re.compile(r"^/npm/api/v1/passthrough/([^/]+)/extract/?$")


def analyze_destinations(rows: list[dict[str, str]], expected_path: str,
                         passthroughs: set[str] | None = None) -> list[tuple[str, str, str, str]]:
    """(status, name, detail, hint) for the REST destinations that look like ours.

    `expected_path` is e.g. /npm/api/v1/passthrough/recorder/extract. A trailing slash is a real
    failure: Passthrough path rules such as ^/([A-Za-z0-9_-]+)?$ answer 403 for `/extract/`.
    `passthroughs` are the names of the Passthrough entries Sycope has (None = not known): a destination
    that posts to one that is not there (renamed, or removed by the uninstaller) is said so, because the
    alert definitions that use it record nothing.
    """
    rest = [r for r in rows if r["type"] == "restClient" and "/extract" in r["path"].lower()]
    if not rest:
        return [("warn", "External Destination", "no REST destination posting to .../extract found",
                 f"create one: POST {expected_path} (HTTPS, Sycope's own host and port, no query "
                 "parameters)")]
    out = []
    for r in rest:
        problems = []
        if r["path"].endswith("/"):
            problems.append("the path ends with '/': Passthrough answers 403 for it, drop the slash")
        if r["path"].rstrip("/") != expected_path:
            via = _VIA.match(r["path"])
            if via and passthroughs is not None and via.group(1) not in passthroughs:
                problems.append(f"it posts to the Passthrough '{via.group(1)}', which {DEAD}: alert definitions "
                                f"that use this destination record nothing. Give them the destination of this "
                                f"install as their action, or change this one's path to {expected_path}")
            else:
                problems.append(f"the path differs from the one this install expects ({expected_path})")
        out.append(("warn" if problems else "ok", f"External Destination {r['name']}",
                    f"{r['method']} {r['host']}:{r['port']}{r['path']}", "; ".join(problems)))
    return out


def inspect(repo: str, url: str, user: str, password: str, passthrough_name: str,
            verify: bool = False) -> dict[str, Any]:
    """Log in and collect everything the installer reports about Sycope. Never raises."""
    out: dict[str, Any] = {"ok": False, "error": "", "defs_total": 0, "defs_active": 0,
                           "macros": {}, "destinations": [], "skew": None}
    try:
        mod = load_client_module(repo)
        client = mod.Sycope(url, user, password, verify)
    except Exception as exc:  # network, TLS, import problems
        out["error"] = f"{type(exc).__name__}: {exc}"
        return out
    out["ok"] = True
    out["skew"] = clock_skew_seconds(client.server_date)
    try:
        defs = client.alert_defs()
        out["defs_total"], out["defs_active"] = len(defs), sum(1 for d in defs if d.get("active"))
        out["macros"] = mod.read_macros(client, defs)
    except Exception as exc:
        out["error"] = f"could not read the alert definitions: {exc}"
    try:
        flt = urllib.parse.quote('category = "destination.external"')
        payload = client.get(f"config-elements?offset=0&limit=200&filter={flt}")
        out["destinations"] = destination_rows(payload)
    except Exception as exc:
        out["destinations_error"] = str(exc)
    try:  # the names of the Passthrough entries, to tell a destination that posts to one that is gone
        from . import passthrough as pt
        flt = urllib.parse.quote(f'category = "{pt.CATEGORY}"')
        payload = client.get(f"config-elements?offset=0&limit=200&filter={flt}")
        rows = payload.get("data") if isinstance(payload, dict) else None
        if isinstance(rows, list):
            out["passthroughs"] = {str((r.get("config") or {}).get("name")) for r in rows if isinstance(r, dict)}
    except Exception:  # not known: analyze_destinations then only compares the paths
        pass
    out["expected_destination_path"] = f"/npm/api/v1/passthrough/{passthrough_name}/extract"
    return out
