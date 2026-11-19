"""Read alert definitions and macros from a Sycope instance and build extraction profiles from them.

The same client the CLI (`tools/profiles/gen_profiles.py`) uses, here inside the package so the
System page can rebuild the profiles on request. Read-only against Sycope (login, `alert-defs`,
`pipeline/macro/<name>`, lookups). Nothing is applied: the result is a *candidate* that goes
through the same validation and review as an uploaded file (profile_store.py).

Stdlib only. Needs Sycope credentials in the recorder (SR_SYCOPE_URL / _USER / _PASSWORD): use a
read-only account.
"""

from __future__ import annotations

import http.client
import http.cookiejar
import ipaddress
import json
import logging
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import TYPE_CHECKING

from sycope_recorder import descriptions
from sycope_recorder.profiles import (
    build_profiles, dumps, info_of, lookup_matches, macro_lookup_refs, macro_text, macros_in,
)

if TYPE_CHECKING:  # the installer imports this module on a host without pydantic: stdlib only at import time
    from sycope_recorder.config import Settings

log = logging.getLogger("sycope_recorder")

# Bounds of one answer and of the paging (S-8, C-19). The socket timeout applies to each read, so a
# deadline bounds the whole answer too. 400 pages of 25 = 10000 alert definitions.
TIMEOUT = 30
ANSWER_DEADLINE = 120
MAX_ANSWER = 32 * 1024**2
PAGE, MAX_PAGES = 25, 400
# The recorder's own compose services and loopback names: never a Sycope server (S-8).
OWN_NAMES = ("localhost", "api", "caddy")


class SycopeError(Exception):
    """Anything that stops the import: not configured, unreachable, login refused.

    Its text is shown to the operator, so it never holds anything the remote host sent (S-8)."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A 3xx is an error (HTTPError with that code): the credentials and the session cookie never go to
    another address (S-8)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _checked(conn_cls, refuse):
    """`conn_cls` that checks the address it actually connected to before anything is sent (S-8): the
    check is on the peer of the open socket, so a name that resolves to a refused address is caught
    however it resolves (also on a second lookup, DNS rebinding)."""
    class Checked(conn_cls):
        def connect(self):
            super().connect()
            why = refuse(self.sock.getpeername()[0])
            if why:
                self.sock.close()
                raise SycopeError(f"SR_SYCOPE_URL is refused: it leads to a {why}")
    return Checked


class _HTTP(urllib.request.HTTPHandler):
    def __init__(self, refuse) -> None:
        super().__init__()
        self._cls = _checked(http.client.HTTPConnection, refuse)

    def http_open(self, req):
        return self.do_open(self._cls, req)


class _HTTPS(urllib.request.HTTPSHandler):
    def __init__(self, context, refuse) -> None:
        super().__init__(context=context)
        self._cls = _checked(http.client.HTTPSConnection, refuse)

    def https_open(self, req):
        return self.do_open(self._cls, req, context=self._context)


def origin(url: str) -> tuple[str, str]:
    """(base, netloc) of a Sycope URL: scheme, host, port and path prefix as given; raises SycopeError for
    anything else in it (S-8). Every request URL is built from `base`, never from a value Sycope returns."""
    try:
        p = urllib.parse.urlsplit(url.strip())
        port = p.port
    except ValueError as exc:
        raise SycopeError("SR_SYCOPE_URL is not a valid URL") from exc
    if p.scheme not in ("http", "https") or not p.hostname:
        raise SycopeError("SR_SYCOPE_URL must be http(s)://<host>[:<port>]")
    if p.username is not None or p.password is not None:
        raise SycopeError("SR_SYCOPE_URL must not hold a user or password (use SR_SYCOPE_USER/_PASSWORD)")
    if p.query or p.fragment:
        raise SycopeError("SR_SYCOPE_URL must not hold a query or fragment")
    host = f"[{p.hostname}]" if ":" in p.hostname else p.hostname
    netloc = f"{host}:{port}" if port is not None else host
    return f"{p.scheme}://{netloc}{p.path.rstrip('/')}", netloc


def refused_address(ip: str) -> str | None:
    """Why the import must not connect to this address, or None (S-8). A Sycope server is normally on a
    private (RFC 1918) address, so those are allowed; refused are only addresses that are never a Sycope
    server: loopback (this container), link-local (169.254.0.0/16 holds the cloud metadata service),
    unspecified, multicast and reserved."""
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return None
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    for test, what in ((a.is_loopback, "loopback address"), (a.is_link_local, "link-local address"),
                       (a.is_unspecified, "unspecified address"), (a.is_multicast, "multicast address"),
                       (a.is_reserved, "reserved address")):
        if test:
            return what
    return None


def refused_target(url: str) -> str | None:
    """Why the recorder must not log in to this URL, or None; raises SycopeError for a malformed one (S-8).

    Refused by name: localhost (and *.localhost) and the recorder's own compose services; by address: what
    refused_address refuses (an address in the URL here, a resolved name when the connection is made)."""
    host = urllib.parse.urlsplit(origin(url)[0]).hostname.lower().rstrip(".")
    if host in OWN_NAMES or host.endswith(".localhost"):
        return f"'{host}' is this recorder, not Sycope"
    why = refused_address(host)
    return f"{host} is a {why}" if why else None


def _reach_error(exc: BaseException) -> str:
    """A short, fixed description of a failed connection: the error class, never text the remote sent."""
    r = getattr(exc, "reason", exc)
    if isinstance(r, ssl.SSLCertVerificationError):
        return f"certificate verify failed: {r.verify_message}"
    if isinstance(r, ssl.SSLError):
        return f"TLS error ({r.reason or type(r).__name__})"
    if isinstance(r, TimeoutError):
        return "timed out"
    if isinstance(r, socket.gaierror):
        return "host name not resolved"
    if isinstance(r, OSError) and r.strerror:
        return r.strerror
    return type(r).__name__


class Sycope:
    """Minimal session client: login once, GET JSON (or text) afterwards.

    Never follows a redirect, sends requests only to the configured scheme, host and port, and reads at
    most MAX_ANSWER bytes per answer (S-8). `refuse(ip)` (optional) is checked on every connection; with it,
    proxies from the environment are not used (the check would see the proxy).
    """

    def __init__(self, base: str, user: str, password: str, verify: bool, refuse=None) -> None:
        self.base, self._netloc = origin(base)
        self.server_date: str | None = None  # the Date header of the latest answer (clock check)
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        handlers = [urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), _NoRedirect()]
        if refuse is None:
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        else:
            handlers += [urllib.request.ProxyHandler({}), _HTTP(refuse), _HTTPS(ctx, refuse)]
        self._opener = urllib.request.build_opener(*handlers)
        login = self._call("login", {"username": user, "password": password})
        if not isinstance(login, dict) or login.get("status") != 200:
            status = login.get("status") if isinstance(login, dict) else None
            raise SycopeError("login refused" + (f" (status {status})" if isinstance(status, int) else "")
                              + ": check SR_SYCOPE_USER and SR_SYCOPE_PASSWORD")

    def _call(self, path: str, body: dict | None = None, text_ok: bool = False):
        url = f"{self.base}/npm/api/v1/{path}"
        if urllib.parse.urlsplit(url).netloc != self._netloc:  # a path from Sycope cannot change the host
            raise SycopeError("refused a request to another host than SR_SYCOPE_URL")
        what = path.split("?")[0].split("/")[0]  # our own endpoint name, for the messages
        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json"},
        )
        try:
            with self._opener.open(req, timeout=TIMEOUT) as resp:
                status, ctype = resp.status, resp.headers.get("Content-Type", "")
                self.server_date = resp.headers.get("Date")
                data, deadline = bytearray(), time.monotonic() + ANSWER_DEADLINE
                while len(data) <= MAX_ANSWER:
                    chunk = resp.read(min(65536, MAX_ANSWER + 1 - len(data)))
                    if not chunk:
                        break
                    data += chunk
                    if time.monotonic() > deadline:
                        raise SycopeError(f"Sycope's answer to {what} took longer than {ANSWER_DEADLINE} s")
        except urllib.error.HTTPError as exc:
            exc.close()
            if 300 <= exc.code < 400:
                raise SycopeError(f"Sycope answered HTTP {exc.code} to {what} (a redirect, not followed): "
                                  "set SR_SYCOPE_URL to the address Sycope answers on") from None
            raise
        except http.client.HTTPException as exc:
            log.warning("Sycope %s: not an HTTP answer (%s)", what, type(exc).__name__)
            raise SycopeError(f"the answer to {what} is not HTTP: check SR_SYCOPE_URL") from None
        if len(data) > MAX_ANSWER:
            raise SycopeError(f"Sycope's answer to {what} is larger than {MAX_ANSWER // 1024**2} MiB")
        raw = data.decode("utf-8", "replace")
        try:
            return json.loads(raw)
        except ValueError:
            if text_ok:
                return raw
            log.warning("Sycope %s: HTTP %s, %d bytes of %r, not JSON", what, status, len(data), ctype[:60])
            raise SycopeError(f"Sycope answered HTTP {status} to {what} with something that is not JSON: "
                              "check SR_SYCOPE_URL") from None

    def get(self, path: str, text_ok: bool = False):
        return self._call(path, text_ok=text_ok)

    def alert_defs(self) -> list[dict]:
        """Every alert definition, page by page; raises SycopeError when the paging does not end (C-19)."""
        defs: list[dict] = []
        last = None
        for _ in range(MAX_PAGES):
            got = self.get(f"alert-defs?offset={len(defs)}&limit={PAGE}") or {}
            if not isinstance(got, dict):
                raise SycopeError("Sycope's answer to alert-defs is not a JSON object")
            page = got.get("data") or []
            if not isinstance(page, list):
                raise SycopeError("Sycope's answer to alert-defs is not a list of definitions")
            if page and page == last:
                raise SycopeError("Sycope returned the same page of alert definitions twice (offset ignored)")
            last = page
            defs += [d for d in page if isinstance(d, dict)]
            if len(page) < PAGE:
                return defs
        raise SycopeError(f"more than {MAX_PAGES * PAGE} alert definitions: stopped reading")

    def lookup_index(self) -> dict[str, dict]:
        """lower-case lookup name -> {id, type}, from the config elements (empty if unreadable)."""
        flt = urllib.parse.quote('category = "lookup.lookup"')
        try:
            items = (self.get(f"config-elements?offset=0&limit=200&filter={flt}") or {}).get("data") or []
            return {str(i.get("name")).lower(): {"id": i.get("id"), "type": (i.get("config") or {}).get("type")}
                    for i in items if i.get("name") and i.get("id")}
        except (urllib.error.URLError, OSError, AttributeError, TypeError, SycopeError):
            return {}

    def macro(self, name: str) -> tuple[str | None, str]:
        """(NQL text or None, status text) of one macro; never raises."""
        try:
            payload = self.get(f"pipeline/macro/{urllib.parse.quote(name, safe='')}", text_ok=True)
        except urllib.error.HTTPError as exc:
            return None, f"HTTP {exc.code}"
        except (urllib.error.URLError, OSError) as exc:
            return None, f"unreachable ({_reach_error(exc)})"
        except SycopeError as exc:
            return None, str(exc)
        text = macro_text(payload)
        return (text, "ok") if text else (None, "readable but no NQL text in the answer")


def resolve_lookup(client: Sycope, ref: dict, index: dict[str, dict]) -> dict:
    """What a macro's lookup condition selects: the networks of that lookup holding the values.

    Never raises; `status` says why nothing was found.
    """
    out = {**ref, "status": "ok", "networks": []}
    entry = index.get(ref["lookup"].lower())
    if entry is None:
        out["status"] = "lookup not found: the macro matches nothing on this instance"
        return out
    try:
        payload = client.get(f"config-element-lookup/{urllib.parse.quote(str(entry['type']), safe='')}/"
                             f"{urllib.parse.quote(str(entry['id']), safe='')}")
    except urllib.error.HTTPError as exc:
        out["status"] = f"HTTP {exc.code} reading the lookup"
        return out
    except (urllib.error.URLError, OSError) as exc:
        out["status"] = f"unreachable ({_reach_error(exc)})"
        return out
    except SycopeError as exc:
        out["status"] = str(exc)
        return out
    out["networks"] = lookup_matches(payload, ref["field"], ref["values"], ref["key"])
    if not out["networks"]:
        out["status"] = "readable, but no entry has that value (or the entries were not recognised)"
    return out


def read_macros(client: Sycope, defs: list[dict]) -> dict[str, dict]:
    """name -> {nql, status, lookups}; unreadable macros have nql None."""
    names = sorted({m for d in defs if d.get("active") for m in macros_in(d.get("nql") or "")})
    index: dict[str, dict] | None = None
    out: dict[str, dict] = {}
    for n in names:
        text, status = client.macro(n)
        lookups = []
        for ref in macro_lookup_refs(text):
            if index is None:
                index = client.lookup_index()
            lookups.append(resolve_lookup(client, ref, index))
        out[n] = {"nql": text, "status": status, "lookups": lookups}
    return out


def fetch(settings: Settings) -> dict:
    """Login, read every definition and macro, build the profiles. Raises SycopeError."""
    if not (settings.sycope_url and settings.sycope_user and settings.sycope_password):
        raise SycopeError("Sycope is not configured: set SR_SYCOPE_URL, SR_SYCOPE_USER, SR_SYCOPE_PASSWORD")
    why = refused_target(settings.sycope_url)
    if why:
        raise SycopeError(f"SR_SYCOPE_URL is refused: {why}")
    try:
        client = Sycope(settings.sycope_url, settings.sycope_user, settings.sycope_password,
                        settings.sycope_verify_tls, refuse=refused_address)
        defs = client.alert_defs()
        read = read_macros(client, defs)
    except SycopeError:
        raise
    except urllib.error.HTTPError as exc:
        raise SycopeError(f"Sycope answered HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
        why = _reach_error(exc)
        raise SycopeError(f"cannot reach Sycope: {why}"
                          + (" (set SR_SYCOPE_VERIFY_TLS=false for a self-signed certificate)"
                             if "CERTIFICATE" in why.upper() else "")) from exc
    if not defs:
        raise SycopeError("Sycope returned no alert definitions")
    macros = {n: m["nql"] for n, m in read.items()}
    profiles = build_profiles(defs, True, macros)
    return {"profiles_json": dumps(profiles), "info": info_of(profiles), "descriptions": descriptions.extract(defs), "definitions": len(defs), "profiles": len(profiles),
            "macros": {n: {"status": m["status"], "readable": bool(m["nql"]),
                           "lookups": [{"lookup": lk["lookup"], "field": lk["field"], "networks": len(lk["networks"]),
                                        "status": lk["status"]} for lk in m["lookups"]]}
                       for n, m in read.items()},
            "source": settings.sycope_url, "at": int(time.time())}
