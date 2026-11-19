"""The Sycope Passthrough entry that points at this recorder: the one thing the installer writes to Sycope.

Sycope keeps a Passthrough as a configuration element (category `passthrough.passthrough`): read with
`GET config-elements?filter=...`, created with `POST config-element`, changed with `PUT config-element/<id>`
(its password is write-only: Sycope answers `password: null`, and a PUT with `password: null` keeps it).
The installer only ever touches the entry with the configured name, never deletes anything, and leaves an
entry that points somewhere else alone (it only reports it). Stdlib only.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

CATEGORY = "passthrough.passthrough"
DEFAULT_ROLES = ["ROLE_ADMIN", "ROLE_USER"]
# The access rules of README_DEPLOY section 10: pages, alert links and ?download=1 (one segment, the query string
# is not part of the path), the legacy /downloads/ links, and every POST (webhook and the pages' actions).
RULES = [("GET", "^/([A-Za-z0-9_-]+)?/?$"), ("GET", "^/downloads/.*"), ("POST", "^/.*")]
# Sycope Triage (sycope_clusters README "Sycope Passthrough"): every page one segment, POST only to its three actions.
TRIAGE_RULES = [("GET", "^/([A-Za-z0-9_-]+)?/?$"), ("POST", "^/(scoring-model|pcap-request|action)$")]


class PassthroughError(Exception):
    """Sycope refused or could not be reached; the message says which."""


def _send(client: Any, method: str, path: str, body: dict | None = None) -> Any:
    """One call through the logged-in client's session (`client._opener` keeps its cookie)."""
    req = urllib.request.Request(f"{client.base}/npm/api/v1/{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", "Accept": "application/json"})
    try:
        with client._opener.open(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        if path.startswith("passthrough/"):  # through the entry: the answer is the recorder's (or the upstream's)
            hint = " (the recorder refused the entry's password)" if exc.code == 401 else ""
        else:
            hint = " (the Sycope user needs the right to edit Passthrough)" if exc.code in (401, 403) else ""
        raise PassthroughError(f"Sycope answered HTTP {exc.code} to {method} {path.split('?')[0]}{hint}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise PassthroughError(f"cannot reach Sycope: {getattr(exc, 'reason', exc)}") from exc
    try:
        return json.loads(raw)
    except ValueError:
        return raw


def find(client: Any, name: str) -> dict | None:
    """The Passthrough entry named `name`, or None."""
    flt = urllib.parse.quote(f'category = "{CATEGORY}"')
    data = _send(client, "GET", f"config-elements?offset=0&limit=200&filter={flt}")
    rows = data.get("data") if isinstance(data, dict) else None
    for row in rows or []:
        if isinstance(row, dict) and (row.get("config") or {}).get("name") == name:
            return row
    return None


def upstream(public_host: str, port: int | str | None = None) -> str:
    return f"https://{public_host}" + (f":{port}" if port and str(port) != "443" else "")


def desired(name: str, public_host: str, user: str, password: str | None, current: dict | None = None,
            rules: list[tuple[str, str]] | None = None, port: int | str | None = None) -> dict:
    """The entry's config as the installer wants it. The roles of an existing entry are kept (they are the
    instance's own roles); a new one gets DEFAULT_ROLES."""
    old = {(r.get("method"), r.get("path")): r.get("roles") for r in (current or {}).get("access") or []
           if isinstance(r, dict)}
    roles_any = next((v for v in old.values() if v), None)
    return {"active": True, "name": name, "type": "passthrough", "url": upstream(public_host, port),
            "timeoutMillis": 30000, "sslVerify": False, "auth": "basicAuth", "username": user,
            "password": password, "bearerToken": None, "headers": {}, "auditCalls": True,
            "access": [{"path": p, "method": m, "roles": list(old.get((m, p)) or roles_any or DEFAULT_ROLES)}
                       for m, p in (rules or RULES)]}


def differences(current: dict, want: dict, rules: list[tuple[str, str]] | None = None) -> list[str]:
    """What differs between an entry's config and the wanted one (the write-only password cannot be compared)."""
    out = []
    for key in ("active", "url", "sslVerify", "auth", "username"):
        have = current.get(key)
        if isinstance(have, str):
            have = have.strip()
        if have != want[key]:
            out.append(f"{key} is {current.get(key)!r}, want {want[key]!r}")
    have_rules = {(r.get("method"), r.get("path")) for r in current.get("access") or [] if isinstance(r, dict)}
    missing = [f"{m} {p}" for m, p in (rules or RULES) if (m, p) not in have_rules and ("*", p) not in have_rules]
    if missing:
        out.append("access rules missing: " + ", ".join(missing))
    return out


def points_here(current: dict, public_host: str, port: int | str | None = None) -> bool:
    return str(current.get("url") or "").strip().rstrip("/") == upstream(public_host, port)


def same_host(current: dict, public_host: str) -> bool:
    """The entry points at this host, whatever the port."""
    url = re.sub(r"^https?://", "", str(current.get("url") or "").strip()).split("/")[0]
    return (url.rsplit(":", 1)[0] if url.count(":") == 1 else url) == public_host


def create(client: Any, config: dict) -> None:
    ans = _send(client, "POST", "config-element", {"category": CATEGORY, "tags": [], "config": config})
    if isinstance(ans, dict) and ans.get("status") not in (None, 200):
        raise PassthroughError(f"Sycope did not create the entry: {ans.get('message') or ans.get('code')}")


def update(client: Any, current: dict, config: dict) -> None:
    element = {k: v for k, v in current.items() if k in ("id", "category", "tags", "module", "attributes")}
    element["config"] = config
    ans = _send(client, "PUT", f"config-element/{urllib.parse.quote(str(current['id']))}", element)
    if isinstance(ans, dict) and ans.get("status") not in (None, 200):
        raise PassthroughError(f"Sycope did not save the entry: {ans.get('message') or ans.get('code')}")


def probe(client: Any, name: str) -> tuple[bool, str]:
    """Reach the recorder through the entry: GET /stats needs the recorder's Basic auth (unlike /healthz), so an
    answer proves the upstream URL, TLS, the password and the GET rule together."""
    try:
        ans = _send(client, "GET", f"passthrough/{urllib.parse.quote(name)}/stats")
    except PassthroughError as exc:
        return False, str(exc)
    ok = isinstance(ans, dict) and "version" in ans
    return ok, (f"the recorder ({ans.get('version')}) answered through the Passthrough" if ok
                else f"no recorder answer through the Passthrough: {str(ans)[:120]}")


def probe_webhook(client: Any, name: str) -> tuple[bool, str]:
    """POST the installer's self-test webhook through the entry, as Sycope's External Destination will.

    The body has nothing to filter on, so the recorder answers NO BPF FILTER and queues nothing. This proves the
    POST rule and the path the alert action uses, which GET /stats does not.
    """
    try:
        ans = _send(client, "POST", f"passthrough/{urllib.parse.quote(name)}/extract", {"id": "installer-selftest"})
    except PassthroughError as exc:
        return False, str(exc)
    ok = isinstance(ans, str) and ans.strip() == "NO BPF FILTER"
    return ok, ("POST /extract through the Passthrough reached the recorder (NO BPF FILTER)" if ok
                else f"unexpected answer to POST /extract through the Passthrough: {str(ans)[:120]}")


def get(client: Any, name: str, path: str) -> Any:
    """GET <path> (one segment, with its query) through the entry; raises PassthroughError."""
    return _send(client, "GET", f"passthrough/{urllib.parse.quote(name)}/{path}")


def post(client: Any, name: str, path: str, body: dict) -> Any:
    return _send(client, "POST", f"passthrough/{urllib.parse.quote(name)}/{path}", body)


def fetch_raw(client: Any, name: str, path: str, limit: int = 64) -> tuple[int, bytes]:
    """(HTTP status, first `limit` bytes) of GET <path> through the entry: for a PCAP, whose bytes are not text."""
    req = urllib.request.Request(f"{client.base}/npm/api/v1/passthrough/{urllib.parse.quote(name)}/{path}")
    try:
        with client._opener.open(req, timeout=60) as resp:
            return resp.status, resp.read(limit)
    except urllib.error.HTTPError as exc:
        return exc.code, b""
    except (urllib.error.URLError, OSError) as exc:
        raise PassthroughError(f"cannot reach Sycope: {getattr(exc, 'reason', exc)}") from exc
