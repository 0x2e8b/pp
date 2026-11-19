"""Sycope Triage (the sycope_clusters project) beside the recorder, reached through its own Sycope Passthrough.

Optional (answer `triage=yes`). Triage is two containers (app, Caddy on its own port, 8444 by default) with
SQLite in a volume and no other service: it shares nothing with the recorder but the host, Docker and the
Sycope it reads. It is copied from a release given as `triage_src`: a directory, or a zip (a package may
bring one in `bundled/`, which the wizard offers; it is unpacked into a temporary directory for the run),
built and started in `triage_dir`, and gets a Passthrough entry (default `clusters`) with the rules of its
README. Its memory is capped (`mem_limit` = `SC_MEMORY_MB`) and the step refuses to start it
when the host does not have that much available: n2disk must never be the one the OOM killer picks.

Like the recorder's Passthrough, the entry is created, or corrected when it points at this Triage; one with
that name pointing elsewhere is left alone, nothing is ever deleted.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import tempfile
import time
import zipfile

from . import paths
from .report import Result
from .system import healthz_status

DEFAULT_DIR = "/opt/sycope-triage"
DEFAULT_PORT = "8444"
DEFAULT_PASSTHROUGH = "clusters"
MEMORY_MB = 2048  # SC_MEMORY_MB: Triage's own default and its minimum (sycope_clusters README "Sizing")
HEADROOM_MB = 512  # left for the host on top of Triage's cap when deciding whether it fits
DEPLOYED = ".deployed"
HEALTH_TIMEOUT = 180
LIMITS_FILE = "compose.limits.yaml"
RELEASE_PARTS = ("compose.yaml", "Dockerfile", "pyproject.toml", "caddy/Caddyfile", "src/sycope_clusters")
FINGERPRINT_TREES = ("src", "caddy")
FINGERPRINT_FILES = ("Dockerfile", "compose.yaml", "pyproject.toml", "uv.lock")


def chosen(a: dict) -> bool:
    return str(a.get("triage") or "no").lower() in ("yes", "y", "true", "1")


def is_release_dir(path: str) -> bool:
    """A sycope_clusters checkout or release: what the build needs is there."""
    return all(os.path.exists(os.path.join(path, f)) for f in RELEASE_PARTS)


def is_release_zip(path: str) -> bool:
    """A release packed as a zip (bundled/sycope_clusters-*.zip): one top directory holding a release."""
    try:
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist())
    except (OSError, zipfile.BadZipFile):
        return False
    tops = {n.split("/", 1)[0] for n in names}
    return len(tops) == 1 and all(any(n.startswith(f"{t}/{f}") for n in names for t in tops) for f in RELEASE_PARTS)


def is_release(path: str) -> bool:
    return is_release_dir(path) or (path.endswith(".zip") and os.path.isfile(path) and is_release_zip(path))


BUNDLED = "bundled"  # triage_src: whatever Triage zip the recorder package carries in bundled/ (no version to answer)


def bundled(repo: str) -> str | None:
    """The newest Triage zip that came with the recorder package (any .zip in bundled/ holding a release), None
    when there is none."""
    d = os.path.join(repo, "bundled")
    try:
        zips = sorted(f for f in os.listdir(d) if f.endswith(".zip"))
    except OSError:
        return None
    zips = [os.path.join(d, f) for f in zips if is_release_zip(os.path.join(d, f))]
    return max(zips, key=os.path.getmtime) if zips else None


def unpack(path: str, into: str) -> str:
    """Extract a release zip into `into` and return the release directory inside it. Members that would land
    outside `into` (absolute paths, `..`) are refused: the zip is trusted no more than any download."""
    root = os.path.realpath(into)
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():
            if not os.path.realpath(os.path.join(root, n)).startswith(root + os.sep):
                raise ValueError(f"unsafe member in {path}: {n}")
        z.extractall(root)
    top = {n.split("/", 1)[0] for n in zipfile.ZipFile(path).namelist()}.pop()
    return os.path.join(root, top)


def version_of(src: str) -> str:
    """The release in pyproject.toml (`0.5.1b0`), "" when it cannot be read."""
    try:
        with open(os.path.join(src, "pyproject.toml")) as fh:
            m = re.search(r'^version\s*=\s*"([^"]+)"', fh.read(), re.M)
    except OSError:
        return ""
    return m.group(1) if m else ""


def fingerprint(src: str) -> str:
    """sha256 over what the image and the containers are built from (tests and docs do not count)."""
    paths: list[str] = []
    for tree in FINGERPRINT_TREES:
        for dirpath, dirnames, filenames in os.walk(os.path.join(src, tree)):
            dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
            paths += [os.path.relpath(os.path.join(dirpath, f), src) for f in filenames if not f.endswith(".pyc")]
    paths += [f for f in FINGERPRINT_FILES if os.path.isfile(os.path.join(src, f))]
    h = hashlib.sha256()
    for rel in sorted(set(paths)):
        with open(os.path.join(src, rel), "rb") as fh:
            data = fh.read()
        h.update(f"{rel}\0{len(data)}\0".encode())
        h.update(data)
    return h.hexdigest()


def mem_available_mb(path: str = "/proc/meminfo") -> int | None:
    try:
        with open(path) as fh:
            m = re.search(r"^MemAvailable:\s+(\d+) kB", fh.read(), re.M)
    except OSError:
        return None
    return int(m.group(1)) // 1024 if m else None


def memory_mb(a: dict) -> int:
    v = str(a.get("triage_memory_mb") or MEMORY_MB)
    return int(v) if v.isdigit() and int(v) >= MEMORY_MB else MEMORY_MB


def fits(available: int | None, need: int, running: bool) -> tuple[str, str]:
    """(status, detail): may Triage start with `need` MB on a host with `available` MB? A running Triage already
    holds its memory, so it is not counted twice."""
    if available is None:
        return "warn", "MemAvailable unknown; the container is capped at its budget anyway"
    if running or available >= need + HEADROOM_MB:
        return "ok", f"{available} MB available, Triage capped at {need} MB"
    return "fail", f"{available} MB available, Triage needs {need} MB plus {HEADROOM_MB} MB for the host"


# What polars' default runtime (x86-64-v3) needs, as /proc/cpuinfo names it (lzcnt is "abm" there). Without them
# the app dies on its first query and its Caddy answers 502: a VM with a generic CPU type (Proxmox kvm64,
# x86-64-v2-AES). A release whose Dockerfile knows polars-runtime-compat builds that runtime by itself.
CPUINFO = "/proc/cpuinfo"  # a module constant, so that tests do not depend on the CPU they run on
POLARS_FLAGS = ("avx", "avx2", "fma", "bmi1", "bmi2", "abm", "pclmulqdq", "movbe")


def missing_cpu_flags(path: str | None = None) -> list[str] | None:
    """The POLARS_FLAGS this host's CPU lacks; None when the CPU flags cannot be read (not x86, no /proc)."""
    try:
        with open(path or CPUINFO) as fh:
            m = re.search(r"^flags\s*:\s*(.*)$", fh.read(), re.M)
    except OSError:
        return None
    if not m:
        return None
    have = set(m.group(1).split())
    return [f for f in POLARS_FLAGS if f not in have]


def handles_old_cpus(src: str) -> bool:
    """The release's Dockerfile adds polars' compat runtime on a CPU without AVX2 (sycope_clusters after 0.5.1b0)."""
    try:
        return "polars-runtime-compat" in open(os.path.join(src, "Dockerfile")).read()
    except OSError:
        return False


def cpu_item(src: str, cpuinfo: str | None = None) -> tuple[str, str, str]:
    """(status, detail, hint) of the CPU check: fail stops the build of a release that would crash on this CPU."""
    missing = missing_cpu_flags(cpuinfo)
    if missing is None:
        return "warn", "CPU flags unknown (/proc/cpuinfo has none)", ""
    if not missing:
        return "ok", "AVX2 and the rest present: polars' default runtime", ""
    lacks = ", ".join(missing)
    vm = ("in the VM settings a CPU type `host` or `x86-64-v3` provides them; check the n2disk SystemID before and after "
          "(n2disk --show-system-id): a hardware change can change it and void the licence")
    if handles_old_cpus(src):
        return "warn", f"the CPU lacks {lacks}: Triage builds polars' compat runtime (works, slower)", vm
    return "fail", f"the CPU lacks {lacks}: polars in this Triage release crashes on it (the app would answer 502)", \
        "use a Triage release that builds the compat runtime (SC_POLARS_RUNTIME), or " + vm


def limits_yaml(mb: int) -> str:
    return ("# Written by the recorder installer: Triage's memory cap (= SC_MEMORY_MB), so that it, and not n2disk,\n"
            "# is what runs out of memory first on a shared host.\n"
            f"services:\n  app:\n    mem_limit: {mb}m\n")


def sq(value: str) -> str:
    """A value for a compose .env line, single-quoted so that `$` is not expanded ('...' cannot hold a quote)."""
    if "'" in value or "\n" in value:
        raise ValueError("a single quote or a newline cannot be stored in the Triage .env")
    return f"'{value}'"


def sycope_host(url: str) -> str:
    return re.sub(r"^https?://", "", url).rstrip("/")


def recorder_destination(sycope: dict | None, passthrough: str) -> str:
    """The name of the External Destination that posts to the recorder's Passthrough (Triage's Get PCAP uses it)."""
    want = f"/npm/api/v1/passthrough/{passthrough}/extract"
    for r in (sycope or {}).get("destinations") or []:
        if r.get("type") == "restClient" and r.get("path", "").rstrip("/") == want:
            return r.get("name", "")
    return ""


def managed_env(ctx, sycope_pass: str) -> dict[str, str]:
    a = ctx.a
    host = sycope_host(a["sycope_url"])
    name = a.get("triage_passthrough_name") or DEFAULT_PASSTHROUGH
    env = {
        "SC_SYCOPE_URL": a["sycope_url"].rstrip("/"),
        "SC_SYCOPE_USER": sq(a.get("triage_sycope_user") or a["sycope_user"]),
        "SC_SYCOPE_PASSWORD": sq(sycope_pass),
        "SC_SYCOPE_VERIFY_TLS": "false",
        "SC_PUBLIC_HOST": a["public_host"],
        "SC_PORT": str(a.get("triage_port") or DEFAULT_PORT),
        "SC_BASE_HREF": f"https://{host}/npm/api/v1/passthrough/{name}",
        "SC_SYCOPE_UI_URL": f"https://{host}",
        "SC_RECORDER_PASSTHROUGH": a.get("passthrough_name") or "",
        "SC_MEMORY_MB": str(memory_mb(a)),
        "ALLOWED_IPS": a.get("allowed_ips") or "0.0.0.0/0 ::/0",
        "TZ": ctx.host.timezone(),
    }
    dest = recorder_destination(ctx.sycope, a.get("passthrough_name") or "")
    if dest:
        env["SC_RECORDER_DESTINATION"] = sq(dest)
    return env


def _compose(d: str, *args: str) -> str:
    return (f"cd {shlex.quote(d)} && docker compose --env-file .env -f compose.yaml -f {LIMITS_FILE} "
            + " ".join(shlex.quote(x) for x in args))


def _password(d: str) -> str | None:
    try:
        return re.search(r"password: (\S+)", open(os.path.join(d, "credentials")).read()).group(1)
    except (OSError, AttributeError):
        return None


def step_triage(ctx, apply: bool) -> Result:
    """A zipped release (the one bundled with the recorder) is unpacked into a temporary directory for the
    run; the install directory gets the same copy as from an unpacked release."""
    from . import steps as st

    if not chosen(ctx.a):
        return Result().add("Sycope Triage", "skip", "not chosen (answer triage=yes to install it beside the recorder)")
    src = resolve_src(ctx.a.get("triage_src") or "", ctx.repo)
    if src is None:
        return Result().add("Triage release", "fail", f"no Triage release zip in {os.path.join(ctx.repo, 'bundled')}",
                            "put the sycope_clusters zip into bundled/, or answer triage_src with a release path (TRIAGE_SRC)")
    if not src.endswith(".zip"):
        return _step(ctx, apply, src)
    if not is_release(src):
        return Result().add("Triage release", "fail", f"{src} is not a zipped sycope_clusters release",
                            "answer triage_src with the bundled zip or an unpacked release directory (TRIAGE_SRC)")
    with tempfile.TemporaryDirectory(prefix="sycope-triage-") as t:
        st.say(ctx, f"unpacking {src}")
        try:
            unpacked = unpack(src, t)
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            return Result().add("Triage release", "fail", f"cannot unpack {src}: {exc}")
        return _step(ctx, apply, unpacked, shown=src)


def resolve_src(src: str, repo: str) -> str | None:
    """The release to install: `bundled` (or nothing, or a zip path in bundled/ that an earlier package left in the
    answers) means the zip this package carries now; anything else is used as given. None: no bundled zip."""
    here = os.path.abspath(os.path.join(repo, "bundled"))
    if src in ("", BUNDLED) or (src.endswith(".zip") and os.path.dirname(os.path.abspath(src)) == here):
        return bundled(repo)
    return src


# What the Triage rsync excludes (_step): never chowned by steps.root_own.
KEEP = (".git", ".venv", "tests", "__pycache__", ".pytest_cache", ".ruff_cache", ".env", DEPLOYED, "credentials",
        LIMITS_FILE, "docs")


def _skip(rel: str) -> bool:
    parts = rel.split("/")
    return any(p in KEEP for p in parts) or parts[0] == "config"


def ok_now_cheap(have: dict, drift: list, running: list, current: bool) -> bool:
    """The Triage that runs is the wanted one (then a CPU warning does not stop anything: it already runs)."""
    return bool(have) and not drift and len(running) >= 2 and current


def _step(ctx, apply: bool, src: str, shown: str = "") -> Result:
    from . import steps as st

    res, a = Result(), ctx.a
    d = a.get("triage_dir") or DEFAULT_DIR
    port = str(a.get("triage_port") or DEFAULT_PORT)
    if not is_release_dir(src):
        return res.add("Triage release", "fail", f"{src or '(not given)'} is not a sycope_clusters release directory",
                       "copy the Triage release to this host and answer triage_src with its path (TRIAGE_SRC)")
    if not (a.get("sycope_url") and a.get("sycope_user")):
        return res.add("Sycope Triage", "fail", "it reads Sycope: give the Sycope URL and user")
    sycope_pass = ctx.secrets.get("triage_sycope_pass") or (
        ctx.secrets.get("sycope_pass") if (a.get("triage_sycope_user") or a["sycope_user"]) == a["sycope_user"] else None)
    if not sycope_pass:
        return res.add("Sycope Triage", "fail", "no password for Triage's Sycope account", "TRIAGE_SYCOPE_PASS")
    release, fp = version_of(src), fingerprint(src)
    res.add("Triage release", "ok", f"{release or 'unknown version'} from {shown or src}")
    envp = os.path.join(d, ".env")
    try:
        want = managed_env(ctx, sycope_pass)
    except ValueError as exc:
        return res.add("Triage .env", "fail", str(exc), "use a Sycope password without a single quote for Triage's account")
    have = st.read_env(envp)
    if "SC_TRIAGE_EDIT" not in have:
        # analysts' actions on: written once, so an operator's SC_TRIAGE_EDIT=false stays (a release whose compose
        # defaults to false would otherwise come up read-only)
        want["SC_TRIAGE_EDIT"] = "true"
    drift = [k for k, v in want.items() if have.get(k) != v]
    running = ctx.r.probe(_compose(d, "ps", "--status", "running", "-q"))[1].split() if have else []
    deployed = st.read_deployed(d)
    current = deployed.get("fingerprint") == fp
    # the sync below runs with --delete: only into a new or empty directory, a Triage this installer deployed, or
    # a Triage release (a run that failed before writing .deployed, or a copy made by hand)
    refused = paths.foreign(d, DEPLOYED, recognised=is_release_dir(d))
    if refused:
        return res.add("Triage directory", "fail" if apply else "warn", f"not used: {refused}",
                       "answer a new or empty directory (triage_dir, TRIAGE_DIR); nothing in it was changed")
    cpu, cpu_detail, cpu_hint = cpu_item(src)
    res.add("CPU", cpu, cpu_detail, cpu_hint)
    if cpu == "fail" and apply and not ok_now_cheap(have, drift, running, current):
        return res
    mb = memory_mb(a)
    status, detail = fits(mem_available_mb(), mb, len(running) >= 2)
    res.add("memory", status, detail, "" if status != "fail" else
            "add memory to the host, or leave Triage out (triage=no): the capture must keep its memory")
    ok_now = ok_now_cheap(have, drift, running, current)
    holder = ctx.host.port_holder(port) if not ok_now else None
    if holder and holder != "docker:" + st._project_name(d):
        res.add("port", "fail" if apply else "warn", f"host port {port} is taken by {holder}",
                "answer another triage_port (TRIAGE_PORT), or stop that service")
        if apply:
            return res
    if apply and not ok_now:
        if status == "fail":
            return res
        if ctx.dry:
            return st._would(res, "Sycope Triage",
                             f"copy {shown or src} to {d}, write .env, build and start it on port {port}")
        ctx.r.run(["mkdir", "-p", d])
        ctx.r.run(["rsync", "-a", "--delete", *st.ROOT_OWNED, "--exclude", ".git", "--exclude", ".venv", "--exclude", "tests",
                   "--exclude", "__pycache__", "--exclude", ".pytest_cache", "--exclude", ".ruff_cache",
                   "--exclude", ".env", "--exclude", DEPLOYED, "--exclude", "credentials", "--exclude", "/config",
                   "--exclude", LIMITS_FILE, "--exclude", "docs", f"{src.rstrip('/')}/", f"{d}/"])
        ctx.r.run(["mkdir", "-p", os.path.join(d, "config")])
        hosts = os.path.join(d, "config", "critical_hosts.json")
        if not os.path.exists(hosts):
            ctx.r.write(hosts, '{"critical_hosts": []}\n', 0o644)
        ctx.r.write(os.path.join(d, LIMITS_FILE), limits_yaml(mb), 0o644)
        if not have or not _password(d):
            pw = st.new_password()
            rc, hashed = ctx.r.run(["docker", "run", "-i", "--rm", "caddy:2", "caddy", "hash-password"], input=pw + "\n")
            if rc != 0 or not hashed.strip().startswith("$2"):
                return res.add("Triage login", "fail", "could not make the Basic-auth hash: " + hashed[-120:],
                               "check that Docker can pull caddy:2")
            want = {**want, "BASIC_AUTH_USER": a.get("basic_auth_user") or "sycope",
                    "BASIC_AUTH_HASH": f"'{hashed.strip()}'"}
            ctx.r.write(os.path.join(d, "credentials"),
                        f"user: {want['BASIC_AUTH_USER']}\npassword: {pw}\n", 0o600)
            ctx.extra["triage_password_new"] = True
        st.update_env(ctx, envp, want)
        st.say(ctx, "building Triage's image and starting its containers (a few minutes the first time)")
        rc, out = ctx.r.run_live(_compose(d, "up", "-d", "--build"), timeout=1800)
        if rc != 0:
            return res.add("Triage containers", "fail", "docker compose up failed: " + (out.strip()[-300:] or f"exit {rc}"),
                           f"docker compose logs in {d}")
        st.say(ctx, f"waiting for https://{a['public_host']}:{port}/healthz (up to {HEALTH_TIMEOUT} s)")
        start = time.monotonic()
        code = None
        while time.monotonic() - start < HEALTH_TIMEOUT:
            code = healthz_status(f"{a['public_host']}:{port}")
            if code == 200:
                break
            time.sleep(3)
        res.add("Triage health", "ok" if code == 200 else "fail",
                f"https://{a['public_host']}:{port}/healthz answered " + (str(code) if code else "nothing"),
                "" if code == 200 else f"docker compose logs app in {d}")
        if code != 200:
            return res
        ctx.r.write(os.path.join(d, DEPLOYED), json.dumps(
            {"release": release, "fingerprint": fp, "at": time.strftime("%Y-%m-%d %H:%M:%S")}) + "\n", 0o644)
        have = st.read_env(envp)
        drift = [k for k, v in want.items() if have.get(k) != v]
        running = ctx.r.probe(_compose(d, "ps", "--status", "running", "-q"))[1].split()
        current = True
    if not have:
        return res.add("Sycope Triage", "warn", f"not installed in {d}")
    st.root_owned_item(ctx, res, "Triage code owner", d, src, _skip, apply)  # root builds and runs it
    res.add("Triage .env", "ok" if not drift else "warn", envp + ("" if not drift else "; differs: " + ", ".join(drift)))
    res.add("Triage code", "ok" if current else "warn",
            f"release {deployed.get('release') or release}" if current else "the deployed code differs from triage_src",
            "" if current else "the installer rebuilds it")
    res.add("Triage containers", "ok" if len(running) >= 2 else ("fail" if apply else "warn"),
            f"{len(running)} running (app, caddy)", "" if len(running) >= 2 else f"docker compose logs in {d}")
    if not ctx.dry:
        _passthrough(ctx, res, apply, d, port)
    return res


def _passthrough(ctx, res: Result, apply: bool, d: str, port: str) -> None:
    """Create or correct Triage's Passthrough entry and reach Triage through it (its Basic auth included)."""
    from . import passthrough as pt
    from . import steps as st

    a = ctx.a
    name = a.get("triage_passthrough_name") or DEFAULT_PASSTHROUGH
    pw = _password(d)
    user = st.read_env(os.path.join(d, ".env")).get("BASIC_AUTH_USER") or a.get("basic_auth_user") or "sycope"
    manual = (f"create it in Sycope (Settings > Integrations > Passthrough): URL {pt.upstream(a['public_host'], port)}, "
              f"SSL verify off, Basic auth {user} with the password from {d}/credentials, rules "
              + ", ".join(f"{m} {p}" for m, p in pt.TRIAGE_RULES))
    if not (pw and ctx.secrets.get("sycope_pass")):
        res.add("Triage Passthrough", "warn", "no Sycope login or Triage password known", manual)
        return
    st.say(ctx, f"logging in to {a['sycope_url']} and reading the Passthrough entry '{name}'")
    fresh = bool(ctx.extra.get("triage_password_new")) or bool(ctx.extra.get("update_passthrough"))
    try:
        client = st._sycope_client(ctx)
        cur = pt.find(client, name)
        if cur is None:
            if not apply:
                res.add("Triage Passthrough", "warn", f"'{name}' does not exist in Sycope")
                return
            pt.create(client, pt.desired(name, a["public_host"], user, pw, rules=pt.TRIAGE_RULES, port=port))
            res.add("Triage Passthrough", "ok", f"created '{name}' -> {pt.upstream(a['public_host'], port)}")
        else:
            conf = cur.get("config") or {}
            if not pt.points_here(conf, a["public_host"], port):
                res.add("Triage Passthrough", "warn", f"'{name}' exists and points at {str(conf.get('url')).strip()}: "
                        "left alone", "answer another triage_passthrough_name, or change that entry by hand")
                return
            want = pt.desired(name, a["public_host"], user, pw if fresh else None, conf,
                              rules=pt.TRIAGE_RULES, port=port)
            diff = pt.differences(conf, want, rules=pt.TRIAGE_RULES)
            if diff or fresh:
                if not apply:
                    res.add("Triage Passthrough", "warn", f"'{name}' differs: " + ("; ".join(diff) or "new password"))
                    return
                pt.update(client, cur, want)
                res.add("Triage Passthrough", "ok", f"updated '{name}': " + "; ".join(diff + (["password"] if fresh else [])))
            else:
                res.add("Triage Passthrough", "ok", f"'{name}' -> {pt.upstream(a['public_host'], port)} as wanted")
        if not apply:
            return
        try:
            st.say(ctx, f"checking Triage through Sycope: GET passthrough/{name}/whoami and /healthz")
            pt.get(client, name, "whoami")  # behind Triage's Basic auth (healthz is not): proves the entry's password
            health = pt.get(client, name, "healthz")
            ok, detail = True, (f"Triage {health.get('version', '')} answered through the Passthrough; its Sycope "
                                f"reading: {health.get('sycope', '?')}" if isinstance(health, dict)
                                else "Triage answered through the Passthrough")
        except pt.PassthroughError as exc:
            if cur is not None and not fresh and "401" in str(exc):
                pt.update(client, pt.find(client, name), pt.desired(name, a["public_host"], user, pw, conf,
                                                                    rules=pt.TRIAGE_RULES, port=port))
                try:
                    pt.get(client, name, "whoami")
                    ok, detail = True, "Triage answered through the Passthrough (after setting its password in the entry)"
                except pt.PassthroughError as exc2:
                    ok, detail = False, str(exc2)
            else:
                ok, detail = False, str(exc)
        res.add("Triage Passthrough check", "ok" if ok else "fail", detail,
                "" if ok else f"open https://{sycope_host(a['sycope_url'])}/npm/api/v1/passthrough/{name}/ logged in to Sycope")
    except pt.PassthroughError as exc:
        res.add("Triage Passthrough", "warn", str(exc), manual)
    except BaseException as exc:
        if isinstance(exc, KeyboardInterrupt):
            raise
        res.add("Triage Passthrough", "warn", f"cannot log in to Sycope: {exc}", manual)
