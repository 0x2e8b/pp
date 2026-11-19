"""The Sycope External Destination (REST client) that posts alerts to the recorder through its Passthrough.

Sycope keeps it as a configuration element of category `destination.external` (type `restClient`), read,
created and changed like the Passthrough entry (passthrough.py `_send`). It posts to Sycope itself:
`POST https://<sycope>/npm/api/v1/passthrough/<passthrough_name>/extract`, with Basic auth of the Sycope
account the installer was given (the Passthrough sits behind Sycope's own login). Its password is
write-only, like the Passthrough's: Sycope answers `password: null` and a PUT with null keeps it.

The installer only touches the destination named `destination_name`, and only when it is missing or posts to
this recorder's Passthrough; one that posts elsewhere is left alone. When another destination (made by hand,
under another name) already posts to the Passthrough, no second one is created. Nothing is ever deleted here.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any

from . import passthrough as pt

CATEGORY = "destination.external"
DEFAULT_NAME = "Traffic_Recorder"


def path_of(passthrough: str) -> str:
    return f"/npm/api/v1/passthrough/{passthrough}/extract"


def endpoint(sycope_url: str) -> tuple[str, str, int]:
    """(protocol, host, port) of the Sycope URL: the destination posts to Sycope itself."""
    m = re.match(r"^(https?)://([^/:]+|\[[^\]]+\])(?::(\d+))?", sycope_url.strip())
    if not m:
        raise ValueError(f"not a Sycope URL: {sycope_url!r}")
    proto = m.group(1).upper()
    return proto, m.group(2), int(m.group(3) or (443 if proto == "HTTPS" else 80))


def listing(client: Any) -> list[dict]:
    flt = urllib.parse.quote(f'category = "{CATEGORY}"')
    data = pt._send(client, "GET", f"config-elements?offset=0&limit=200&filter={flt}")
    rows = data.get("data") if isinstance(data, dict) else None
    return [r for r in rows or [] if isinstance(r, dict)]


def posts_to(conf: dict, sycope_url: str, passthrough: str) -> bool:
    """The destination posts to this recorder's Passthrough on this Sycope host (a wrong port or a trailing
    slash still count: they are what the installer corrects)."""
    try:
        _, host, _port = endpoint(sycope_url)
    except ValueError:
        return False
    return (conf.get("type") == "restClient" and str(conf.get("host") or "").strip() == host
            and str(conf.get("path") or "").strip().rstrip("/") == path_of(passthrough))


def find(client: Any, name: str, sycope_url: str, passthrough: str) -> tuple[dict | None, list[dict]]:
    """(the destination named `name`, the other destinations that post to the Passthrough)."""
    rows = listing(client)
    mine = next((r for r in rows if (r.get("config") or {}).get("name") == name), None)
    others = [r for r in rows if r is not mine and posts_to(r.get("config") or {}, sycope_url, passthrough)]
    return mine, others


def desired(name: str, sycope_url: str, passthrough: str, user: str, password: str | None,
            current: dict | None = None) -> dict:
    """The destination's config as the installer wants it. Fields Sycope added to an existing one are kept."""
    proto, host, port = endpoint(sycope_url)
    want = dict(current or {})
    want.update({"active": True, "type": "restClient", "name": name, "protocol": proto, "host": host, "port": port,
                 "method": "POST", "path": path_of(passthrough), "params": {}, "contentType": "application/json",
                 "auth": "basicAuth", "username": user, "password": password, "bearerToken": None,
                 "sslVerify": False})
    want.setdefault("headers", {})
    want.setdefault("customPayloadEnabled", False)
    return want


def differences(current: dict, want: dict) -> list[str]:
    out = []
    for key in ("active", "type", "protocol", "host", "port", "method", "path", "contentType", "auth", "username",
                "sslVerify"):
        have = current.get(key)
        if isinstance(have, str):
            have = have.strip()
        if key == "port":
            have = str(have)
            if have != str(want[key]):
                out.append(f"port is {current.get(key)!r}, want {want[key]!r}")
            continue
        if have != want[key]:
            out.append(f"{key} is {current.get(key)!r}, want {want[key]!r}")
    if current.get("params"):
        out.append(f"params {current.get('params')!r} (profiles decide the window and filter)")
    if current.get("customPayloadEnabled"):
        out.append("a custom payload is enabled (the recorder reads Sycope's own alert body)")
    return out


def create(client: Any, config: dict) -> None:
    ans = pt._send(client, "POST", "config-element", {"category": CATEGORY, "tags": [], "config": config})
    if isinstance(ans, dict) and ans.get("status") not in (None, 200):
        raise pt.PassthroughError(f"Sycope did not create the destination: {ans.get('message') or ans.get('code')}")


def update(client: Any, current: dict, config: dict) -> None:
    element = {k: v for k, v in current.items() if k in ("id", "category", "tags", "module", "attributes")}
    element["config"] = config
    ans = pt._send(client, "PUT", f"config-element/{urllib.parse.quote(str(current['id']))}", element)
    if isinstance(ans, dict) and ans.get("status") not in (None, 200):
        raise pt.PassthroughError(f"Sycope did not save the destination: {ans.get('message') or ans.get('code')}")
