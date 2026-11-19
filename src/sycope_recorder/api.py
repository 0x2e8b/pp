"""FastAPI app: the Sycope alert webhook listener and its web UI.

The webhook is a catch-all POST (Sycope calls `/extract`). The other routes
serve the queue, alert, profiles, configuration and system pages, the
operator actions on them, `/healthz` and `/stats`. The webhook handler
always returns HTTP 200 for extraction outcomes (success or failure),
using only the response body text (and a duplicate `X-Result` header) to
signal which — Sycope's webhook consumer parses body text, not status
code, so this can't be changed without breaking the legacy contract. Non-200 statuses are used only for
pre-extraction validation failures (bad Content-Length, bad JSON), a full queue (429) and an internal error (500).

The app runs no background work: the worker process (worker.py) claims and extracts jobs. Every
database call from an async route goes through the threadpool, so a busy database never stalls the
event loop.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import json
import logging
import os
import re
import sqlite3
import time
import zipfile
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from starlette.concurrency import run_in_threadpool
from urllib.parse import parse_qs, urlsplit

from sycope_recorder import bundle as bundle_mod
from sycope_recorder import checks as checks_mod
from sycope_recorder import config_store
from sycope_recorder import profile_store
from sycope_recorder import profiles as profiles_mod
from sycope_recorder import sycope_import
from sycope_recorder import stats as stats_mod
from sycope_recorder import jobs as jobs_mod
from sycope_recorder import reextract as rx_mod
from sycope_recorder import system as system_mod
from sycope_recorder import pages
from sycope_recorder import descriptions
from sycope_recorder.alert import alert_meta, parse_alert
from sycope_recorder.profiles import ProfileBook, range_seconds
from sycope_recorder.config import Settings, VALID_FILTER_MODES, legacy_env_warnings
from sycope_recorder.extraction import (
    ERR_DISK,
    NO_BPF,
    Kind,
    free_bytes,
    plan_extraction,
)
from sycope_recorder.jobs import (
    FAILED,
    MISS,
    QUEUED,
    RUNNING,
    JobStore,
    ready_at_for,
)
from sycope_recorder import store as store_mod
from sycope_recorder.store import CANCELLED, DONE, META_WEB_STARTED, SchemaTooNew, db_path

log = logging.getLogger("sycope_recorder")

MAX_BODY_BYTES = 2 * 1024 * 1024
CLAMP_MIN, CLAMP_MAX = 0, 86400
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,160}$")
_KEY = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_RESTART_WORKER = "docker compose restart api"
_RESERVED_KEYS = {"healthz", "stats", "status", "queue", "downloads", "extract", "delete", "persistent", "logs", "system", "reload-profiles", "profiles-file", "profiles-upload", "profiles-apply", "profiles-revert", "profiles-sync", "profiles", "configuration", "configuration-download", "configuration-upload", "configuration-apply", "configuration-revert", "queue-cancel", "queue-retry", "worker-pause", "queue-persistent", "queue-reextract", "queue-zip", "queue-values"}
_PCAP_MEDIA = "application/vnd.tcpdump.pcap"
ERR_CONFLICT = "ERROR: alert id conflict"  # the alert's key already belongs to another alert id (store.enqueue)


def _help_body(settings: Settings) -> dict:
    """Build the JSON body for the `/` help endpoint, echoing the caller's effective defaults."""
    return {
        "status": "ok",
        "usage": {
            "endpoint": "POST /extract?filter=MODE&before=SEC&after=SEC",
            "filter_modes": {
                "full": "client IP, server IP, and port",
                "hosts": "client IP and server IP",
                "client": "client IP only",
                "server": "server IP only",
                "port": "server IP and port",
            },
            "defaults": {
                "filter": settings.default_filter,
                "before": settings.default_before,
                "after": settings.default_after,
            },
        },
        "examples": [
            "POST /extract?filter=full&before=30&after=60",
            "POST /extract?filter=hosts",
            "POST /extract?filter=port&before=120&after=120",
        ],
    }


def _client_ip(request: Request) -> str:
    """The operator's address for audit lines: Caddy's X-Forwarded-For, else the socket peer."""
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def create_app(settings: Settings) -> FastAPI:
    """Build and wire up the FastAPI app: routes and per-app state; it starts no background work.

    The job database is opened here, not in the lifespan, so a test can use the app (and its store)
    without running the lifespan. A database written by a newer release leaves the app up without a
    store: every route that needs it answers 503 and the webhook 500, instead of the process crashing.
    """

    db_error = ""
    try:
        store: JobStore | None = JobStore(db_path(settings.state_dir))
    except (SchemaTooNew, OSError, sqlite3.Error) as exc:
        # too new a schema, or a state directory the web cannot write (permissions, a symlinked file)
        log.error("jobs: %s; the web runs without the job database", exc)
        store, db_error = None, str(exc)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Record the start; the app has no background tasks (they live in the worker)."""
        for w in legacy_env_warnings():
            log.warning(w)
        if store is not None:
            await run_in_threadpool(store.set_meta, META_WEB_STARTED, str(time.time()))
        try:
            yield
        finally:
            if store is not None:
                store.close()

    def _no_db() -> PlainTextResponse:
        """The answer of every route that needs the job database when it could not be opened."""
        return PlainTextResponse(f"job database unavailable: {db_error}", status_code=503)

    def _guard(request: Request, enabled: bool, flag: str):
        """None when allowed, else the refusal response.

        A browser sends the operator's Basic-auth credentials on any request to this host, also
        one triggered by another site, so state changes (and the log bundle) must prove they come
        from our own pages: `Sec-Fetch-Site` must be same-origin (or none = typed address), and an
        `Origin` header, when present, must name this host, the Host header, X-Forwarded-Host or
        the Passthrough address. Non-browser clients send neither header and pass.
        """
        if not enabled:
            return PlainTextResponse(f"Disabled: set {flag}=true to enable", status_code=403)
        site = request.headers.get("sec-fetch-site")
        if site and site not in ("same-origin", "none"):
            return PlainTextResponse("Cross-site request refused", status_code=403)
        origin = request.headers.get("origin")
        if origin and origin != "null":
            host = urlsplit(origin).netloc.lower()
            allowed = {request.headers.get("host", "").lower(),
                       request.headers.get("x-forwarded-host", "").lower(),
                       (settings.download_url_base or "").split("/")[0].lower(),
                       settings.public_host.lower()}
            if host not in allowed:
                return PlainTextResponse("Cross-site request refused", status_code=403)
        elif origin == "null":
            return PlainTextResponse("Cross-site request refused", status_code=403)
        return None

    def _refuse_first(refusal):
        """Decorator: call `refusal(request)` before the route; when it answers (not None), that answer
        is the response and the route does not run. Works for `def` and `async def` routes (a `def`
        route stays one, so FastAPI still runs it in the threadpool); FastAPI sees the route's own
        signature through functools.wraps, so its parameters are injected as before."""
        def decorate(route):
            if inspect.iscoroutinefunction(route):
                @functools.wraps(route)
                async def checked(*args, **kwargs):
                    refused = refusal(kwargs.get("request"))
                    if refused is not None:
                        return refused
                    return await route(*args, **kwargs)
            else:
                @functools.wraps(route)
                def checked(*args, **kwargs):
                    refused = refusal(kwargs.get("request"))
                    if refused is not None:
                        return refused
                    return route(*args, **kwargs)
            return checked
        return decorate

    # Decorator: the route answers `_no_db()` when the job database could not be opened.
    _needs_store = _refuse_first(lambda request: _no_db() if store is None else None)

    def _guarded(setting: str | None = None):
        """Decorator for an operator action: `_guard` (cross-site check) runs before the route, with the
        route disabled unless `settings.<setting>` is true (refusal names SR_<SETTING>); no setting means
        always enabled, only the cross-site check. Put it above `@_needs_store` (guard first, then store).
        The route must take `request: Request`."""
        flag = f"SR_{setting.upper()}" if setting else ""

        def decorate(route):
            if "request" not in inspect.signature(route).parameters:
                raise TypeError(f"{route.__name__}: a guarded route needs a `request: Request` parameter")
            return _refuse_first(
                lambda request: _guard(request, getattr(settings, setting) if setting else True, flag))(route)
        return decorate

    app = FastAPI(
        docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan
    )
    app.state.settings = settings
    book = ProfileBook.load(profile_store.active_path(settings)[0])
    app.state.profiles = book
    if len(book):
        log.info("loaded %d extraction profiles from %s", len(book), profile_store.active_path(settings)[0])
    app.state.store = store
    app.state.db_error = db_error
    app.state.last_dead_warning = 0.0

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        """Report whether the directories are mounted and the job database opens, for container liveness checks.

        Web only and cheap: a dead worker or n2disk is reported by /healthz/deep, not by making Docker
        restart a healthy web.
        """
        db = "ok" if store is not None and store.schema_ok() else (db_error or "unavailable")
        return JSONResponse(
            {
                "status": "ok" if db == "ok" else "error",
                "timeline_dir_present": os.path.isdir(settings.timeline_dir),
                "output_dir_present": os.path.isdir(settings.output_dir),
                "db": db,
            },
            status_code=200 if db == "ok" else 503,
        )

    @app.get("/healthz/deep")
    @_needs_store
    async def healthz_deep() -> JSONResponse:
        """Report the self-checks the worker stored plus the live worker check; 503 if any FAILs.

        Not exempt from Caddy's auth (only /healthz is). The container's
        Docker healthcheck deliberately stays on the shallow /healthz: a dead
        n2disk should be reported, not make Docker restart a healthy api.
        """
        results = await run_in_threadpool(checks_mod.stored_checks, store, settings)
        status = checks_mod.overall(results)
        return JSONResponse(
            {
                "status": status,
                "checks": [{"name": c.name, "status": c.status, "detail": c.detail}
                           for c in results],
            },
            status_code=503 if status == checks_mod.FAIL else 200,
        )

    @app.get("/stats")
    @_needs_store
    async def stats_endpoint():
        """Counters from the database, the queue, the stored checks and the worker's state."""

        def build() -> dict:
            """All reads in one threadpool hop: they are each a short SQLite query."""
            body: dict = {"version": system_mod.version(), **stats_mod.snapshot(store)}
            body["queue"] = store.counts()
            body["checks"] = {c.name: c.status for c in checks_mod.stored_checks(store, settings)}
            body["worker"] = stats_mod.worker_summary(store, settings)
            body["output_free_bytes"] = free_bytes(settings.output_dir)
            return body

        return JSONResponse(await run_in_threadpool(build))

    @app.get("/status/{name}")
    def job_status(name: str) -> PlainTextResponse:
        """Human-readable state of one download, shown when Caddy has no such file (yet).

        Caddy rewrites a 404 under /<download_prefix>/ to this route. Plain text
        because it is read by a person who clicked a link in a Sycope alert.
        """
        if not _SAFE_NAME.match(name):
            return PlainTextResponse("Unknown file", status_code=404)
        if store is None:
            return _no_db()
        job = store.get(name)
        if job is None:
            return PlainTextResponse(
                "No such PCAP (never created, or deleted)", status_code=404)
        if job["state"] in (QUEUED, RUNNING):
            when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(max(job["next_at"], time.time())))
            return PlainTextResponse(
                f"PCAP is being prepared (state: {job['state']}, attempt "
                f"{job['attempts'] + 1}/{settings.job_max_attempts}). The traffic window is "
                f"not fully on disk yet; expected after {when} (server time). Reload then.",
                status_code=202, headers={"Retry-After": "30"})
        if job["state"] == MISS:
            return PlainTextResponse(
                "No packets matched this alert's flow in the recorded window "
                f"({job['window_begin']} to {job['window_end']}). Nothing to download.",
                status_code=404)
        if job["state"] == FAILED:
            return PlainTextResponse(
                f"Extraction failed after {job['attempts']} attempts: {job['detail']}",
                status_code=502)
        if job["state"] == CANCELLED:
            return PlainTextResponse("Extraction was cancelled by an operator. Nothing to download.",
                                     status_code=404)
        # done but file absent: removed after extraction
        return PlainTextResponse("PCAP was extracted but has since been deleted", status_code=410)

    def _wants_html(request: Request) -> bool:
        if request.query_params.get("format") == "json":
            return False
        return "text/html" in request.headers.get("accept", "")

    def _file_size(path: str) -> int | None:
        try:
            size = os.path.getsize(path)
        except OSError:
            return None
        return size or None

    def _base_href() -> str | None:
        """Canonical page address, only when links go through another host (Passthrough)."""
        return f"https://{settings.download_url_base}" if settings.download_url_base else None

    def _queue_url() -> str:
        """The queue page address (through the Passthrough host when there is one)."""
        return f"{_base_href()}/queue" if _base_href() else "/queue"

    def _state_filter(value):
        """A state chip as a store filter: empty and "all" mean no filter (None)."""
        return value if value and value != "all" else None

    def _quick_filter(raw: object) -> str:
        """The quick-filter text of a request: trimmed and capped; its words only ever become parameters."""
        return str(raw or "").strip()[:300]

    def _queue_view(request: Request):
        """The queue table: browsers get HTML, everything else (or ?format=json) JSON."""
        state = _state_filter(request.query_params.get("state"))
        raw_size = request.query_params.get("size") or request.query_params.get("limit") or "100"
        try:
            size = max(1, min(1000, int(raw_size)))
        except ValueError:
            size = 100
        try:
            page = max(1, int(request.query_params.get("page", "1")))
        except ValueError:
            page = 1

        if store is None:
            return _no_db()

        # The search box sends its free text as q and the filter chips as qf (field=value tokens).
        q = _quick_filter(" ".join(x for x in (request.query_params.get("qf"), request.query_params.get("q")) if x))
        now = time.time()
        t = request.query_params.get("t") or ""
        window = store_mod.time_window(t, now)
        if window is None:
            t = ""
        total = store.count_jobs(state=state, q=q, window=window)
        pages_count = max(1, (total + size - 1) // size) if total > 0 else 1
        page = max(1, min(page, pages_count))
        offset = (page - 1) * size

        sort = request.query_params.get("sort") or ("due" if state == QUEUED else "alert_time")
        if sort not in JobStore.SORTS:
            sort = "alert_time"
        desc = (request.query_params.get("dir") or ("asc" if sort == "due" and state == QUEUED else "desc")) != "asc"
        jobs = store.list_jobs(limit=size, offset=offset, state=state, sort=sort, desc=desc, q=q, window=window)
        sizes = {j["id"]: _file_size(j["output_path"]) for j in jobs if j["state"] == DONE}
        if _wants_html(request):
            descriptions.attach(settings, jobs)
            events = store.events_many([j["id"] for j in jobs])
            start, step, n = pages.timeline_span(window, store.time_bounds(state, q), now)
            hist = {"start": start, "step": step, "counts": store.histogram(start, step, n, state, q, window)}
            return HTMLResponse(pages.queue_page(
                jobs, store.counts(q, window), state=state, q=q, limit=size, events=events,
                t=t, window=window, hist=hist, sycope_url=settings.sycope_url,
                open_key=request.query_params.get("open"), sizes=sizes,
                base_href=_base_href(),
                params={**{k: v for k, v in request.query_params.items() if k != "qf"}, **({"q": q} if q else {})},
                page=page, size=size, total=total, pages=pages_count,
                msg=request.query_params.get("msg"), sort=sort, desc=desc,
                editable=settings.queue_edit, bundle=settings.debug_bundle,
                worker=stats_mod.worker_summary(store, settings),
                slots={r["job_id"]: r for r in store.workers() if r.get("job_id")}
            ))
        slim = [{**{k: j[k] for k in ("alert_key", "id", "state", "attempts", "window_begin",
                                      "window_end", "ready_at", "updated", "detail")},
                 "alert_info": pages.meta_of(j), "pcap_bytes": sizes.get(j["id"]),
                 "persistent": bool(j.get("persistent", 0))} for j in jobs]
        return JSONResponse({
            "counts": store.counts(q, window),
            "q": q,
            "t": t,
            "window": list(window) if window else None,
            "jobs": slim,
            "page": page,
            "pages": pages_count,
            "total": total,
            "sort": sort,
            "dir": "desc" if desc else "asc",
        })

    @app.get("/queue-values")
    @_needs_store
    def queue_values(request: Request):
        """The most frequent values of one filter field among the jobs the queue shows (state, search
        and time range of the page, minus the filter being edited): the filter editor's list."""
        qp = request.query_params
        key = (qp.get("field") or "").lower()
        if key not in store_mod.FIELDS:
            return JSONResponse({"error": "unknown field"}, status_code=400)
        window = store_mod.time_window(qp.get("t") or "", time.time())
        total, values = store.top_values(key, _state_filter(qp.get("state")), _quick_filter(qp.get("q")), window)
        return JSONResponse({"field": key, "total": total, "values": [{"v": v, "n": n} for v, n in values]})

    @app.get("/queue")
    def queue_route(request: Request):
        """Queue table (also served at `/` for browsers)."""
        return _queue_view(request)

    @app.get("/")
    def root(request: Request):
        """Browsers: the status table. Anything else: the JSON usage help (legacy)."""
        if _wants_html(request):
            return _queue_view(request)
        return JSONResponse(_help_body(settings))

    def _pcap_for_key(key: str, rows: list[dict]) -> tuple[str, str] | None:
        """(path, file name) of the newest finished PCAP of this alert (`rows`: its jobs), if it is on disk.

        Only `done` jobs count; a file beside a miss/failed/cancelled job is not offered. The
        alerts directory is looked at only for a key without any job row (files from before the job
        table, or whose rows were pruned)."""
        names = [j["id"] for j in rows if j["state"] == DONE]
        if not rows:  # files from before the job table existed, or whose rows were pruned
            pat = re.compile(r"^\d{8}_\d{6}_" + re.escape(key) + r"\.pcap$")
            try:
                names = sorted((n for n in os.listdir(settings.output_dir) if pat.match(n)),
                               reverse=True)
            except OSError:
                names = []
        for n in names:
            path = os.path.join(settings.output_dir, n)
            if os.path.isfile(path) and os.path.getsize(path) > 0:
                return path, n
        return None

    def _system_url(view: str = "profiles", **params) -> str:
        return (f"{_base_href()}/{view}" if _base_href() else f"/{view}") + pages._url(params)

    @app.get("/profiles-file")
    def profiles_download():
        """The active profiles (uploaded or mounted) as a profiles.json to edit: the field help and the editable
        fields only, whatever format the active file has. The descriptive fields stay in the info file."""
        if not len(app.state.profiles):
            return PlainTextResponse("No profiles file", status_code=404)
        return Response(profiles_mod.dumps(app.state.profiles.profiles), media_type="application/json",
                        headers={"Cache-Control": "no-store",
                                 "Content-Disposition": 'attachment; filename="profiles.json"'})

    @app.post("/profiles-upload")
    @_guarded("queue_edit")
    async def profiles_upload(request: Request):
        """Stage a candidate profiles.json (raw JSON body): validate and diff, change nothing."""
        raw = await request.body()
        report = await asyncio.get_running_loop().run_in_executor(
            None, profile_store.stage, settings, raw, app.state.profiles)
        return JSONResponse({"ok": not report["errors"], **report}, status_code=200 if not report["errors"] else 422)

    @app.post("/profiles-sync")
    @_guarded("queue_edit")
    async def profiles_sync(request: Request):
        """Read alert definitions and macros from Sycope and stage the rebuilt profiles for review."""
        loop = asyncio.get_running_loop()
        try:
            got = await loop.run_in_executor(None, sycope_import.fetch, settings)
        except sycope_import.SycopeError as exc:
            log.warning("profile import from Sycope failed: %s", exc)
            return RedirectResponse(url=_system_url(msg=f"Import from Sycope failed: {exc}"), status_code=303)
        report = await loop.run_in_executor(
            None, profile_store.stage, settings, got["profiles_json"].encode(), app.state.profiles, got["info"])
        if report["errors"]:
            log.warning("profiles built from Sycope did not validate: %s", report["errors"][:3])
            return RedirectResponse(url=_system_url(msg="Import built an invalid file: " + report["errors"][0]),
                                    status_code=303)
        descriptions.save(settings, got["descriptions"])
        profile_store.save_meta(settings, report["token"], {k: got[k] for k in
                                ("definitions", "profiles", "macros", "source", "at")})
        log.info("profiles rebuilt from Sycope: %d definitions, %d profiles, %d macros", got["definitions"],
                 got["profiles"], len(got["macros"]))
        return RedirectResponse(url=_system_url(review=report["token"]) , status_code=303)

    @app.post("/profiles-apply")
    @_guarded("queue_edit")
    async def profiles_apply(request: Request):
        """Apply a staged candidate: atomic replace, previous override kept, book reloaded."""
        data = await _read_post_data(request)
        ok, msg = profile_store.apply(settings, str(data.get("token", "")), app.state.profiles)
        if ok:
            app.state.profiles = ProfileBook.load(profile_store.active_path(settings)[0])
            log.info("profiles uploaded and applied: %s", msg)
        return RedirectResponse(url=_system_url(msg=msg if ok else "NOT applied: " + msg), status_code=303)

    @app.post("/profiles-revert")
    @_guarded("queue_edit")
    async def profiles_revert(request: Request):
        """Drop the uploaded profiles: the mounted file is active again."""
        done, msg = profile_store.revert(settings)
        if done:
            app.state.profiles = ProfileBook.load(profile_store.active_path(settings)[0])
            log.info("uploaded profiles removed: mounted file active again")
        return RedirectResponse(url=_system_url(msg=msg), status_code=303)

    def _cfg_denied(request: Request, data: dict, json_answer: bool):
        """None when the configuration password was given and right, else the refusal."""
        refused = _guard(request, True, "SR_CONFIG_PASSWORD")
        if refused:
            return refused
        ok, why = config_store.password_ok(settings, data.get("password"))
        if ok:
            return None
        if json_answer:
            return JSONResponse({"ok": False, "errors": [why]}, status_code=403 if "disabled" not in why else 404)
        return RedirectResponse(url=_system_url("configuration", msg="NOT done: " + why), status_code=303)

    async def _schedule_reload(request: Request) -> bool:
        """Tell the worker (it drains and restarts) and reload the web shortly (gunicorn HUP).

        Returns False when the worker could not be told: the web still reloads (the saved file must take
        effect somewhere) and the caller tells the operator to restart the worker. Without a job database
        there is no channel to the worker either: only the web reloads.
        """
        notified = False
        if store is None:
            log.error("no job database: the worker cannot be told about the new configuration")
        else:
            try:
                gen = await run_in_threadpool(store.bump_config_generation, _client_ip(request))
                notified = True
                log.warning("configuration generation %d: the web reloads now, the worker after its running jobs", gen)
            except sqlite3.Error as exc:
                log.error("could not tell the worker about the new configuration: %s", exc)
        asyncio.get_running_loop().call_later(1.5, config_store.reload_service)
        return notified

    @app.post("/configuration-download")
    async def configuration_download(request: Request):
        """The editable settings as a JSON file (secrets in clear): needs the configuration password."""
        data = await _read_post_data(request)
        denied = _cfg_denied(request, data, True)
        if denied:
            return denied
        log.info("configuration downloaded")
        return Response(json.dumps(config_store.export(settings), indent=1, default=str),
                        media_type="application/json",
                        headers={"Content-Disposition": 'attachment; filename="recorder-config.json"',
                                 "Cache-Control": "no-store"})

    @app.post("/configuration-upload")
    async def configuration_upload(request: Request):
        """Stage a configuration file: validate against real Settings and diff, change nothing."""
        data = await _read_post_data(request)
        denied = _cfg_denied(request, data, True)
        if denied:
            return denied
        report = await asyncio.get_running_loop().run_in_executor(
            None, config_store.stage, settings, data.get("config"))
        return JSONResponse({"ok": not report["errors"], **report}, status_code=200 if not report["errors"] else 422)

    @app.post("/configuration-apply")
    async def configuration_apply(request: Request):
        """Apply a staged configuration and reload the service (a few seconds)."""
        data = await _read_post_data(request)
        denied = _cfg_denied(request, data, False)
        if denied:
            return denied
        ok, msg = config_store.apply(settings, str(data.get("token", "")))
        if ok:
            log.warning("configuration uploaded and applied: %s", msg)
            notified = await _schedule_reload(request)
            msg = (f"{msg}. The web reloads now; the worker reloads after its running jobs finish "
                   f"(up to {settings.worker_stop_grace_seconds} s)." if notified else
                   f"{msg}. The web reloads now, but the worker was not notified (job database error): "
                   f"it keeps the old configuration until you run `{_RESTART_WORKER}`.")
        return RedirectResponse(url=_system_url("configuration", msg=msg if ok else "NOT applied: " + msg),
                                status_code=303)

    @app.post("/configuration-revert")
    async def configuration_revert(request: Request):
        """Drop the uploaded configuration: the environment alone applies again (service reloads)."""
        data = await _read_post_data(request)
        denied = _cfg_denied(request, data, False)
        if denied:
            return denied
        done, msg = config_store.revert(settings)
        notified = False
        if done:
            log.warning("uploaded configuration removed")
            notified = await _schedule_reload(request)
        msg = (msg if not done else
               "Back to the environment configuration; the service reloads" if notified else
               "Back to the environment configuration; the web reloads, but the worker was not notified "
               f"(job database error): run `{_RESTART_WORKER}` for it to follow")
        return RedirectResponse(url=_system_url("configuration", msg=msg), status_code=303)

    async def _system_view(request: Request, view: str):
        """One of the system pages: HTML for browsers, the same JSON otherwise."""
        if store is None:
            return _no_db()
        data = await run_in_threadpool(system_mod.gather, settings, store, app.state.profiles)
        data["profiles"]["active"] = profile_store.active_info(settings)
        data["profiles"]["sycope"] = {"configured": bool(settings.sycope_url and settings.sycope_user
                                                         and settings.sycope_password),
                                      "url": settings.sycope_url}
        if _wants_html(request) and request.query_params.get("format") != "json":
            review = None
            if view == "configuration" and request.query_params.get("review"):
                review = config_store.staged(settings, request.query_params["review"])
                if review:
                    review["token"] = request.query_params["review"]
            elif settings.queue_edit and request.query_params.get("review"):
                review = profile_store.staged_report(
                    settings, request.query_params["review"], app.state.profiles)
                if review:
                    review["import"] = profile_store.load_meta(settings, request.query_params["review"])
            return HTMLResponse(pages.system_page(
                data, editable=settings.queue_edit, bundle=settings.debug_bundle,
                msg=request.query_params.get("msg"), base_href=_base_href(), review=review, view=view))
        return JSONResponse(data)

    @app.get("/system")
    async def system_status(request: Request):
        """System status: checks, capture and storage, queue."""
        return await _system_view(request, "status")

    @app.get("/profiles")
    async def profiles_page(request: Request):
        """Profiles: the table, reload, upload with review, rebuild from Sycope."""
        return await _system_view(request, "profiles")

    @app.get("/configuration")
    async def configuration_page(request: Request):
        """Effective configuration (secrets masked)."""
        return await _system_view(request, "configuration")

    @app.post("/reload-profiles")
    @_guarded("queue_edit")
    async def reload_profiles(request: Request):
        """Re-read SR_PROFILES_FILE (after the profiles were regenerated from Sycope)."""
        path = profile_store.active_path(settings)[0]
        fresh = ProfileBook.load(path)
        old = len(app.state.profiles)
        if len(fresh) == 0 and path:
            msg = "Profiles file is missing, unreadable or empty: keeping the " + f"{old} loaded profiles"
        else:
            app.state.profiles = fresh
            msg = f"Profiles reloaded: {len(fresh)} (was {old})"
            log.info("%s from %s", msg, path)
        return RedirectResponse(url=_system_url(msg=msg), status_code=303)

    @app.get("/logs")
    @_guarded("debug_bundle")
    @_needs_store
    def logs_bundle(request: Request):
        """Debug bundle (zip) of what this container sees; see bundle.py."""
        data = bundle_mod.build(settings, store)
        name = time.strftime("recorder-debug-%Y%m%d-%H%M%S.zip", time.gmtime())
        return Response(data, media_type="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="{name}"',
                                 "Cache-Control": "no-store"})

    @app.get("/{key}")
    def alert_link(key: str, request: Request):
        """The link in a Sycope alert: always the status page of that alert, never the file.

        The PCAP is a separate, explicit request: `?download=1` (same path, so Passthrough access
        rules that allow the link also allow the download). Browsers get the HTML page, anything
        else (or `?format=json`) gets the same information as JSON, with `"ready"`, the file name
        and a `download` path. Status codes mirror the state: 200 (PCAP ready), 202 still being
        prepared, 404 no packets matched / unknown alert, 502 extraction failed, 410 extracted but
        deleted since. A `?download=1` for a PCAP that is not available answers with that status
        and a one-line text.
        """
        if not _KEY.match(key) or key in _RESERVED_KEYS:
            return PlainTextResponse("Unknown alert", status_code=404)
        if store is None:
            return _no_db()
        jobs = store.jobs_for_key(key)
        found = _pcap_for_key(key, jobs)
        events = {j["id"]: store.events(j["id"]) for j in jobs}
        descriptions.attach(settings, jobs)
        state = pages.overall_state(jobs)
        code = 200 if found else {QUEUED: 202, RUNNING: 202, MISS: 404, FAILED: 502,
                                  DONE: 410, CANCELLED: 404}.get(state, 404)
        headers = {"Retry-After": "30"} if code == 202 else {}

        if request.query_params.get("download") == "1":
            want = request.query_params.get("job")
            if want:  # one file of an alert with several extractions (re-extract)
                job = next((j for j in jobs if j["id"] == want), None)
                path = os.path.join(settings.output_dir, want) if job else ""
                if job and job["state"] == DONE and os.path.isfile(path) and os.path.getsize(path) > 0:
                    return FileResponse(path, media_type=_PCAP_MEDIA, filename=want)
                return PlainTextResponse("PCAP not available for this job", status_code=404)
            if found:
                return FileResponse(found[0], media_type=_PCAP_MEDIA, filename=found[1])
            return PlainTextResponse(f"PCAP not available (state: {state})", status_code=code,
                                     headers=headers)

        params = dict(request.query_params)
        if request.query_params.get("format") == "json" or not _wants_html(request):
            return JSONResponse(
                {"alert": key, "state": state, "ready": found is not None,
                 "file": found[1] if found else None,
                 "download": f"{key}?download=1" if found else None,
                 "warning": next((j["detail"] for j in jobs if j["state"] == DONE
                                  and str(j["detail"]).startswith("warning:")), None),
                 "alert_info": pages.meta_of(jobs[0]) if jobs else {}, "jobs": [
                    {"file": j["id"], "state": j["state"], "attempts": j["attempts"],
                     "window": [j["window_begin"], j["window_end"]], "due_after": j["ready_at"],
                     "detail": j["detail"],
                     "history": [{"ts": e["ts"], "state": e["state"], "attempt": e["attempt"],
                                  "bytes": e["bytes"], "detail": e["detail"]}
                                 for e in events.get(j["id"], [])]} for j in jobs]},
                status_code=code, headers=headers)
        pcap = (found[1], os.path.getsize(found[0])) if found else None
        if not jobs and pcap:  # files from before the job table: no history to show
            return HTMLResponse(pages.file_only_page(key, pcap, _base_href(), params))
        if not jobs:
            return HTMLResponse(pages.not_found_page(key, _base_href(), params), status_code=404)
        return HTMLResponse(pages.alert_page(key, jobs, events, _base_href(), pcap, params),
                            status_code=code, headers=headers)

    def _resolve_params(request: Request) -> tuple[str, int, int]:
        """Resolve filter/before/after query params, falling back to configured defaults (with a warning logged) on anything missing or unparseable rather than rejecting the request."""
        q = request.query_params
        mode = q.get("filter") or settings.default_filter
        if mode not in VALID_FILTER_MODES:
            log.warning("unknown filter mode %r; using %s", mode, settings.default_filter)
            mode = settings.default_filter if settings.default_filter in VALID_FILTER_MODES else "full"

        def _int(name: str, default: int) -> int:
            """Parse one integer query param, clamped to [CLAMP_MIN, CLAMP_MAX]; falls back to `default` if absent or not an int."""
            raw = q.get(name)
            if raw is None:
                return default
            try:
                val = int(raw)
            except ValueError:
                log.warning("invalid %s=%r; using default %d", name, raw, default)
                return default
            return max(CLAMP_MIN, min(CLAMP_MAX, val))

        return mode, _int("before", settings.default_before), _int("after", settings.default_after)

    async def _enqueue(request: Request, alert: dict) -> PlainTextResponse:
        """Plan the extraction, queue it, answer at once with the alert's link."""
        try:
            mode, before, after = _resolve_params(request)
            parsed = parse_alert(alert)
            log.info("Alert id=%s name=%s keys=%s", parsed.alert_id, parsed.alert_name, list(alert))
            profile = app.state.profiles.lookup(alert)
            plan = plan_extraction(parsed, mode, before, after, settings, profile)
            if plan is None:
                log.info("NO BPF FILTER for alert id=%s", parsed.alert_id)
                await run_in_threadpool(store.bump, Kind.NO_BPF.value)
                return PlainTextResponse(NO_BPF, headers={"X-Result": NO_BPF, "X-Outcome": Kind.NO_BPF.value})
            free = free_bytes(settings.output_dir)
            if free is not None and free < settings.min_free_bytes:
                log.error("LOW DISK: %d bytes free; refusing to queue id=%s", free, parsed.alert_id)
                await run_in_threadpool(store.bump, Kind.DISK_LOW.value)
                return PlainTextResponse(ERR_DISK, headers={"X-Result": ERR_DISK, "X-Outcome": Kind.DISK_LOW.value})
            if await run_in_threadpool(store.depth) >= settings.queue_max:
                await run_in_threadpool(store.bump, "rejected_429")
                return PlainTextResponse("Queue full", status_code=429, headers={"Retry-After": "60", "X-Result": "Queue full",
                                                                         "X-Outcome": "queue_full"})
            url = plan.url(settings)
            meta = alert_meta(alert, parsed)
            if profile is not None:
                # shape comes only from the sidecar, which may be absent; a range plan_extraction could not
                # use (range_seconds) gave the default window
                shape = f"{profile['shape']}, " if profile.get("shape") else ""
                rng = range_seconds(profile)
                meta["profile"] = (f"{profile.get('name') or str(profile.get('def_id') or 'profile')}: {shape}"
                                   + (f"range {rng // 60} min" if rng is not None else
                                      "time_range_s unusable, default window"))
            outcome = await run_in_threadpool(store.enqueue, plan, ready_at_for(plan, settings), url, meta)
            if outcome == "conflict":  # the link would show another alert's jobs and file
                # HTTP 200 like every other outcome of /extract (legacy contract): the result is the body
                # and X-Outcome, never the status.
                return PlainTextResponse(ERR_CONFLICT, headers={"X-Result": ERR_CONFLICT, "X-Outcome": "conflict"})
            try:  # a diagnostic only: Sycope gets its 200 and the link once the job is queued
                await run_in_threadpool(_warn_if_worker_dead)
            except Exception as exc:
                log.warning("worker liveness check failed: %s", exc)
            return PlainTextResponse(url, headers={"X-Result": url,
                                                   "X-Outcome": "queued" if outcome == "queued" else "exists"})
        except sqlite3.OperationalError as exc:
            log.error("job database busy or unavailable while queueing: %s", exc)
            try:
                await run_in_threadpool(store.bump, "db_busy")
            except sqlite3.Error:
                pass
            return PlainTextResponse("Internal error", status_code=500)
        except Exception:  # generic 500, no detail leak
            log.exception("unhandled error while queueing")
            return PlainTextResponse("Internal error", status_code=500)

    def _warn_if_worker_dead() -> None:
        """At most once a minute: jobs are queued but no worker runs them."""
        now = time.time()
        if now - app.state.last_dead_warning < 60:
            return
        w = stats_mod.worker_summary(store, settings, now)
        if not w["alive"]:
            app.state.last_dead_warning = now
            log.warning("job queued but the worker is not running (state %s, heartbeat age %s s)",
                        w["state"], w["heartbeat_age"])

    async def _read_post_data(req: Request) -> dict:
        """Body (JSON or urlencoded) plus query parameters. The Sycope Passthrough answers 502 to an
        urlencoded body, so our pages post JSON from a script; a query string works too."""
        data = await _read_body(req)
        for k, v in req.query_params.items():
            data.setdefault(k, v)
        return data

    async def _read_body(req: Request) -> dict:
        ct = req.headers.get("content-type", "")
        if "application/json" in ct:
            try:
                b = await req.json()
                if isinstance(b, dict):
                    res: dict = dict(b)
                    jid, jids = res.get("job_id"), res.get("job_ids")
                    if jids is None and jid is not None:
                        res["job_ids"] = jid if isinstance(jid, list) else [jid]
                    if isinstance(jid, list):  # a bulk form sends every ticked row under job_id
                        res["job_id"] = jid[0] if jid else ""
                    elif jids is not None and jid is None:
                        res["job_id"] = jids[0] if jids else ""
                    return res
            except Exception:
                return {}
        raw = await req.body()
        text = raw.decode("utf-8", errors="replace")
        qs = parse_qs(text, keep_blank_values=True)
        res = {}
        for k, v in qs.items():
            if k == "job_id":
                res["job_ids"] = v
                res["job_id"] = v[0] if v else ""
            else:
                res[k] = v[0] if v else ""
        return res

    def _wants_json(request: Request) -> bool:
        """API clients get JSON; our own pages post JSON too (Passthrough) but ask for text/html."""
        accept = request.headers.get("accept", "")
        if "text/html" in accept:
            return False
        return "application/json" in accept or "application/json" in request.headers.get("content-type", "")

    @app.post("/delete")
    @app.post("/queue/delete")
    @_guarded("queue_edit")
    @_needs_store
    async def delete_jobs_route(request: Request):
        data = await _read_post_data(request)
        job_ids = data.get("job_ids") or []
        if isinstance(job_ids, str):
            job_ids = [job_ids]
        select_all_matching = str(data.get("select_all_matching", "")).lower() in ("1", "true")
        filter_state = _state_filter(data.get("state"))
        confirm = str(data.get("confirm", "")).lower() in ("1", "true")
        q = _quick_filter(data.get("q"))
        t = str(data.get("t") or "")
        # `tw` is the window the page showed, resolved to absolute times: "all matching" stays what was seen
        window = store_mod.time_window(str(data.get("tw") or t), time.time())

        if select_all_matching:
            count = await run_in_threadpool(store.count_jobs, state=filter_state, q=q, window=window)
            target_ids = None
        else:
            target_ids = [str(jid) for jid in job_ids if jid]
            count = len(target_ids)

        is_json = _wants_json(request)

        if count == 0:
            if is_json:
                return JSONResponse({"error": _NO_JOBS, "deleted": 0}, status_code=400)
            return RedirectResponse(url="queue?msg=No+jobs+selected", status_code=303)

        if not confirm:
            if is_json:
                return JSONResponse({"error": "Confirmation required", "count": count}, status_code=400)
            return HTMLResponse(pages.confirm_delete_page(
                target_ids, select_all_matching, filter_state, count,
                _base_href(), dict(request.query_params) or data, q=q,
                window=window
            ))

        deleted, skipped_running, skipped_persistent = await run_in_threadpool(
            store.delete_jobs, job_ids=target_ids, filter_state=filter_state if select_all_matching else None,
            q=q if select_all_matching else None, window=window if select_all_matching else None
        )

        if is_json:
            return JSONResponse({
                "deleted": deleted,
                "skipped_running": skipped_running,
                "skipped_persistent": skipped_persistent,
            })

        msg_parts = [f"Deleted {deleted} job(s)"]
        skipped_notes = []
        if skipped_running:
            skipped_notes.append(f"{skipped_running} running refused")
        if skipped_persistent:
            skipped_notes.append(f"{skipped_persistent} persistent skipped")
        if skipped_notes:
            msg_parts.append(f"({', '.join(skipped_notes)})")
        msg = " ".join(msg_parts)
        return _queue_redirect(request, data, msg)

    @app.post("/queue/persistent")
    @app.post("/persistent")
    @_guarded("queue_edit")
    @_needs_store
    async def toggle_persistent_route(request: Request):
        data = await _read_post_data(request)
        job_id = data.get("job_id")
        if not job_id:
            return PlainTextResponse("Missing job_id", status_code=400)
        new_val = await run_in_threadpool(store.toggle_persistent, str(job_id))
        if new_val is None:
            return PlainTextResponse("Job not found", status_code=404)

        if _wants_json(request):
            return JSONResponse({"ok": True, "job_id": job_id, "persistent": new_val})

        return_to = str(data.get("return_to") or "")
        queue_base = _queue_url()
        if not return_to or return_to in ("queue", "/queue", "./"):
            target_url = queue_base
        elif return_to.startswith("?"):
            target_url = queue_base + return_to
        elif return_to.startswith("/queue") or return_to.startswith("queue"):
            target_url = queue_base + return_to.removeprefix("/queue").removeprefix("queue")
        else:
            target_url = queue_base
        return RedirectResponse(url=target_url, status_code=303)

    async def _ids(data: dict, only: tuple[str, ...] | None = None) -> list[str]:
        """The job ids an operator action works on: the ticked rows (capped, a form posts every one),
        or with `select_all_matching` every job of the current chip and quick filter."""
        if str(data.get("select_all_matching", "")).lower() in ("1", "true"):
            window = store_mod.time_window(str(data.get("tw") or data.get("t") or ""), time.time())
            return await run_in_threadpool(store.job_ids, _state_filter(data.get("state")),
                                           _quick_filter(data.get("q")), only, window)
        raw = data.get("job_ids") or data.get("ids") or []
        if isinstance(raw, str):
            raw = [raw]
        return [str(x) for x in raw if x][:5000]

    _KEEP = ("state", "size", "page", "q", "sort", "dir", "t")  # what a redirect back to the queue keeps
    _NO_JOBS = "No jobs selected"

    def _queue_redirect(request: Request, data: dict, msg: str) -> RedirectResponse:
        """Back to the queue page the operator came from, keeping its filter and page."""
        ret: dict = {k: (data.get(k) or request.query_params.get(k)) for k in _KEEP}
        ret = {k: v for k, v in ret.items() if v}
        ret["msg"] = msg
        return RedirectResponse(url=_queue_url() + pages._url(ret), status_code=303)

    def _no_jobs(request: Request, data: dict) -> Response:
        """An operator action with nothing to work on: 400 for API clients, the queue page with a note otherwise."""
        return (JSONResponse({"error": _NO_JOBS}, status_code=400) if _wants_json(request)
                else _queue_redirect(request, data, _NO_JOBS))

    @app.post("/queue-cancel")
    @_guarded("queue_edit")
    @_needs_store
    async def queue_cancel(request: Request):
        """Cancel queued jobs now; ask the worker to stop running ones (it kills npcapextract)."""
        data = await _read_post_data(request)
        ids = await _ids(data, (store_mod.QUEUED, store_mod.RUNNING))
        if not ids:
            return _no_jobs(request, data)
        who = _client_ip(request)
        res = await run_in_threadpool(store.request_cancel, ids, who)
        log.info("operator %s cancelled %d job(s): %s", who, len(ids), res)
        if _wants_json(request):
            return JSONResponse(res)
        msg = f"Cancelled {res['cancelled']}, stopping {res['requested']} running"
        if res["skipped"]:
            msg += f", {res['skipped']} already finished"
        return _queue_redirect(request, data, msg)

    @app.post("/queue-retry")
    @_guarded("queue_edit")
    @_needs_store
    async def queue_retry(request: Request):
        """Queue miss/failed/cancelled jobs again with fresh attempts (within SR_QUEUE_MAX)."""
        data = await _read_post_data(request)
        ids = await _ids(data, store_mod.RETRYABLE)
        if not ids:
            return _no_jobs(request, data)
        who = _client_ip(request)
        res = await run_in_threadpool(store.retry_jobs, ids, who, settings.queue_max)
        log.info("operator %s retried %d job(s): %s", who, len(ids), res)
        if _wants_json(request):
            return JSONResponse(res)
        msg = f"Queued again: {res['requeued']}"
        if res["skipped"]:
            msg += f", {res['skipped']} not retryable"
        if res["rejected_queue_full"]:
            msg += f", {res['rejected_queue_full']} refused (queue full)"
        return _queue_redirect(request, data, msg)

    @app.post("/queue-reextract")
    @_guarded("queue_edit")
    @_needs_store
    async def queue_reextract(request: Request):
        """A new extraction of the ticked job(s) with another window and, for one job, another filter
        (reextract.py builds it from validated parts). `preview=1` only answers what would run."""
        data = await _read_post_data(request)
        preview = str(data.get("preview", "")).lower() in ("1", "true")
        raw = data.get("job_ids") or data.get("job_id") or []
        ids = list(dict.fromkeys(str(x) for x in (raw if isinstance(raw, list) else [raw]) if x))[:500]
        if not ids:
            return (JSONResponse({"error": _NO_JOBS}, status_code=400) if preview or _wants_json(request)
                    else _queue_redirect(request, data, _NO_JOBS))
        try:
            req = rx_mod.parse_request(data)
            if req.custom and len(ids) > 1:
                raise rx_mod.Invalid("a changed filter is for one job; several jobs only get a wider window")
        except rx_mod.Invalid as e:
            return (JSONResponse({"error": str(e)}, status_code=400) if preview or _wants_json(request)
                    else _queue_redirect(request, data, f"Re-extract refused: {e}"))
        rolling = system_mod.rolling_info(store).get("retention_minutes")

        def build(jid: str):
            job = store.get(jid)
            if job is None:
                raise rx_mod.Invalid(f"job {jid} does not exist")
            taken = {j["id"] for j in store.jobs_for_key(job["alert_key"])}
            p, what = rx_mod.plan(job, req, settings, taken)
            reason = jobs_mod.validate_job_row(
                {"id": p.filename, "output_path": p.output_path, "bpf": p.bpf,
                 "window_begin": p.begin, "window_end": p.end}, settings)
            if reason:
                raise rx_mod.Invalid(reason)
            return job, p, what

        if preview:
            try:
                job, p, what = await run_in_threadpool(build, ids[0])
            except rx_mod.Invalid as e:
                return JSONResponse({"error": str(e)}, status_code=400)
            return JSONResponse({"file": p.filename, "bpf": p.bpf, "begin": p.begin, "end": p.end,
                                 "change": what, "warning": rx_mod.on_disk_warning(p, rolling),
                                 "jobs": len(ids)})
        free = free_bytes(settings.output_dir)
        if free is not None and free < settings.min_free_bytes:
            return (JSONResponse({"error": "low disk space"}, status_code=507) if _wants_json(request)
                    else _queue_redirect(request, data, "Re-extract refused: low disk space"))
        who = _client_ip(request)
        res: dict = {"queued": 0, "refused": 0, "full": 0, "files": [], "errors": []}
        for jid in ids:
            try:
                job, p, what = await run_in_threadpool(build, jid)
            except rx_mod.Invalid as e:
                res["refused"] += 1
                res["errors"].append(f"{jid}: {e}")
                continue
            out = await run_in_threadpool(store.reextract, jid, p, jobs_mod.ready_at_for(p, settings),
                                          rx_mod.meta_for(job, req, jid), who, what, settings.queue_max)
            if out == "queued":
                res["queued"] += 1
                res["files"].append(p.filename)
            elif out == "full":
                res["full"] += 1
            else:
                res["refused"] += 1
                res["errors"].append(f"{jid}: {out}")
        log.info("operator %s re-extracted %d job(s): %s", who, len(ids), res)
        if _wants_json(request):
            return JSONResponse(res)
        msg = f"Re-extract queued: {res['queued']}"
        if res["full"]:
            msg += f", {res['full']} refused (queue full)"
        if res["refused"]:
            msg += f", {res['refused']} refused ({'; '.join(res['errors'])[:300]})"
        return _queue_redirect(request, data, msg)

    ZIP_MAX_FILES = 500
    ZIP_MAX_BYTES = 4 * 1024 ** 3

    class _ZipSink:
        """A write-only stream zipfile can write to (it then adds data descriptors); drained per chunk."""

        def __init__(self) -> None:
            self.parts: list[bytes] = []
            self.n = 0

        def write(self, b: bytes) -> int:
            self.parts.append(bytes(b))
            self.n += len(b)
            return len(b)

        def tell(self) -> int:
            return self.n

        def flush(self) -> None:
            pass

        def drain(self) -> bytes:
            out, self.parts = b"".join(self.parts), []
            return out

    @app.post("/queue-zip")
    @_guarded()
    @_needs_store
    async def queue_zip(request: Request):
        """The ticked (or all matching) finished jobs' PCAPs as one zip, streamed and not compressed
        (captures hardly compress). The same files each row offers; only a cross-site request is refused."""
        data = await _read_post_data(request)
        ids = await _ids(data, (store_mod.DONE,))
        # Only finished jobs (ticked rows are not filtered by _ids), and the file limit before any disk access:
        # this handler shares the one web worker with the pages and the webhook.
        states = await run_in_threadpool(store.states, ids)
        ids = [jid for jid in ids if states.get(jid) == store_mod.DONE]
        if len(ids) > ZIP_MAX_FILES:
            return PlainTextResponse(f"Too much for one zip: {len(ids)} finished jobs (at most {ZIP_MAX_FILES} "
                                     "files); narrow the selection", status_code=413)
        alerts = os.path.realpath(settings.output_dir)

        def on_disk() -> list[tuple[str, str, int]]:
            out = []
            for jid in ids:
                path = os.path.join(alerts, jid)
                if (jobs_mod._NAME.match(jid) and os.path.dirname(os.path.realpath(path)) == alerts
                        and os.path.isfile(path)):
                    out.append((jid, path, os.path.getsize(path)))
            return out

        files = await run_in_threadpool(on_disk)
        if not files:
            return PlainTextResponse("None of the selected jobs has a PCAP on disk", status_code=404)
        total = sum(f[2] for f in files)
        if len(files) > ZIP_MAX_FILES or total > ZIP_MAX_BYTES:
            return PlainTextResponse(f"Too much for one zip: {len(files)} files, {total} bytes (at most "
                                     f"{ZIP_MAX_FILES} files and {ZIP_MAX_BYTES} bytes)", status_code=413)
        log.info("operator %s downloads %d PCAP(s) as zip (%d bytes)", _client_ip(request), len(files), total)

        def chunks():
            sink = _ZipSink()
            with zipfile.ZipFile(sink, "w", zipfile.ZIP_STORED) as zf:
                for name, path, _size in files:
                    try:
                        with open(path, "rb") as src, zf.open(name, "w", force_zip64=True) as dst:
                            while True:
                                b = src.read(1024 * 1024)
                                if not b:
                                    break
                                dst.write(b)
                                yield sink.drain()
                    except OSError:
                        continue  # removed meanwhile: the zip simply lacks it
                    yield sink.drain()
            yield sink.drain()

        name = time.strftime("recorder-pcaps-%Y%m%d-%H%M%S.zip")
        return StreamingResponse(chunks(), media_type="application/zip",
                                 headers={"Content-Disposition": f'attachment; filename="{name}"',
                                          "Cache-Control": "no-store"})

    @app.post("/queue-persistent")
    @_guarded("queue_edit")
    @_needs_store
    async def queue_persistent(request: Request):
        """Mark (value=1) or unmark (value=0) the ticked or all matching jobs as persistent."""
        data = await _read_post_data(request)
        ids = await _ids(data)
        if not ids:
            return _no_jobs(request, data)
        value = str(data.get("value", "1")).lower() in ("1", "true", "yes", "on")
        n = await run_in_threadpool(store.set_persistent_many, ids, value)
        log.info("operator %s %s %d job(s) persistent", _client_ip(request), "marked" if value else "unmarked", n)
        if _wants_json(request):
            return JSONResponse({"ok": True, "persistent": value, "changed": n})
        return _queue_redirect(request, data, f"{n} job(s) {'marked' if value else 'unmarked'} persistent")

    @app.post("/worker-pause")
    @_guarded("queue_edit")
    @_needs_store
    async def worker_pause(request: Request):
        """Pause or resume the worker: no new job starts while paused; running ones finish."""
        data = await _read_post_data(request)
        paused = str(data.get("paused", "")).lower() in ("1", "true", "yes", "on")
        who = _client_ip(request)
        await run_in_threadpool(store.set_paused, paused, who)
        log.warning("operator %s %s the worker", who, "paused" if paused else "resumed")
        if _wants_json(request):
            return JSONResponse({"paused": paused})
        return RedirectResponse(url=_system_url("system", msg="Worker paused: no new job starts"
                                                if paused else "Worker resumed"), status_code=303)

    @app.post("/{full_path:path}")
    async def extract(request: Request) -> PlainTextResponse:
        """Handle the Sycope alert webhook: validate, parse, queue, respond.

        Routed as a catch-all on any POST path (not just `/extract`)
        because the legacy listener never inspected the request path at
        all - Sycope's configured webhook URL must keep working
        regardless of exact path.

        Validation order is deliberate and each step short-circuits with
        a specific status, checked in this sequence: Content-Length
        present, Content-Length within MAX_BODY_BYTES, body non-empty,
        body is valid JSON. Content-Length is checked before the body is
        even read so oversized/missing-header requests are rejected
        without paying for a read.

        Once validation passes, every outcome - the alert's link, "NO
        BPF FILTER" or "ERROR: low disk space" - is reported as HTTP 200,
        with the result string duplicated into the X-Result header. This
        matches the legacy contract: Sycope's webhook consumer
        distinguishes success from failure by reading the body text, not
        the status code. Outcomes are queued; the worker
        extracts later.

        The final bare `except Exception` in `_enqueue` returns a generic
        "Internal error" 500 without the exception text, unlike the legacy listener
        which leaked `str(exception)` to the caller - an intentional
        hardening, not an oversight; the real error is only logged
        server-side.
        """
        if store is None:
            log.error("webhook refused: %s", db_error)
            return PlainTextResponse("Internal error", status_code=500)
        try:
            await run_in_threadpool(store.record_webhook)
        except sqlite3.Error as exc:
            log.warning("could not count the webhook: %s", exc)
        cl = request.headers.get("content-length")
        if cl is None:
            return PlainTextResponse("Missing Content-Length", status_code=411)
        try:
            length = int(cl)
        except ValueError:
            return PlainTextResponse("Invalid Content-Length", status_code=400)
        if length > MAX_BODY_BYTES:
            return PlainTextResponse("Payload too large", status_code=413)

        body = await request.body()
        if not body:
            return PlainTextResponse("Empty request body", status_code=400)
        try:
            alert = json.loads(body)
            # A lone surrogate ("\ud800") is valid JSON text but no UTF-8: storing the alert failed (a 500).
            json.dumps(alert, ensure_ascii=False).encode()
        except (json.JSONDecodeError, ValueError, RecursionError) as exc:  # RecursionError: deep nesting (was a 500)
            log.warning("invalid JSON body (%d bytes): %s", len(body), exc)
            return PlainTextResponse("Invalid JSON", status_code=400)
        if not isinstance(alert, dict):  # valid JSON, but a list or a bare value is no alert (was a 500)
            log.warning("JSON body is not an object (%s)", type(alert).__name__)
            return PlainTextResponse("Invalid JSON object", status_code=400)

        return await _enqueue(request, alert)

    return app
