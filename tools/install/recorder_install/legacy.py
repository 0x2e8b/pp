"""What an earlier deployment left on the host, so that an upgrade adopts it instead of fighting it.

The first customer deployment (September 2026, before 0.3) was not made by this installer:

* n2disk runs from its own unit (`n2disk.service` with `/etc/n2disk/n2disk.conf`), not from `n2disk@<nic>`.
  It is licensed and recording. The installer must not start a second n2disk on the same NIC and buffer,
  and must not rewrite, retune or restart the one that runs: it is "external", the installer only checks
  that the recorder agrees with it (NIC, directory, file duration).
* The stack in the install directory has no `.deployed` record: its own `compose.override.yaml` (bind
  mounts by path), a Basic-auth hash that may be unquoted in `.env`, maybe a certificate under
  `caddy/certs`, and no `credentials` file (the password is not known to the installer).

Parsers are pure (unit-tested); the host is only read through `Runner.probe`.
"""

from __future__ import annotations

import os
import re
import shlex

# n2disk options (long and short form) that the recorder depends on.
_OPTS = {
    "iface": ("--interface", "-i"),
    "dump_dir": ("--dump-directory", "-o"),
    "timeline_dir": ("--timeline-dir", "-A"),
    "duration": ("--max-file-duration",),
    "disk_limit": ("--disk-limit",),
    "slicing": ("--packet-slicing",),
    "filter": ("--filter", "-f"),
}
_FLAGS = {"index": ("--index", "-I")}


def _tokens(text: str) -> list[tuple[str, str | None]]:
    """(option, value) pairs of an n2disk configuration or command line.

    n2disk's configuration file has one option per line, as `--opt=value`, `-o=value` or `--opt value`;
    a command line has the same options separated by spaces. Comments (`#`) and empty lines are skipped.
    """
    out: list[tuple[str, str | None]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            parts = shlex.split(line)
        except ValueError:
            parts = line.split()
        i = 0
        while i < len(parts):
            p = parts[i]
            if not p.startswith("-"):
                i += 1
                continue
            if "=" in p:
                k, v = p.split("=", 1)
                out.append((k, v))
                i += 1
            elif i + 1 < len(parts) and not parts[i + 1].startswith("-"):
                out.append((p, parts[i + 1]))
                i += 2
            else:
                out.append((p, None))
                i += 1
    return out


def parse_n2disk_conf(text: str) -> dict:
    """The options the recorder cares about, from an n2disk configuration file or command line.

    Missing options are absent from the result; `index` is True/False. The last occurrence wins (as in n2disk).
    """
    found: dict = {"index": False}
    for k, v in _tokens(text):
        for key, names in _OPTS.items():
            if k in names and v is not None:
                found[key] = v.strip()
        for key, names in _FLAGS.items():
            if k in names:
                found[key] = True
    return found


def parse_execstart(value: str) -> list[str]:
    """argv of `systemctl show -p ExecStart --value <unit>` (`{ path=... ; argv[]=/usr/bin/n2disk /etc/... ; ...}`)."""
    m = re.search(r"argv\[\]=([^;]*)", value)
    raw = m.group(1) if m else value
    try:
        return shlex.split(raw.strip())
    except ValueError:
        return raw.split()


def config_of(argv: list[str]) -> str | None:
    """The configuration file an n2disk command line reads (its one argument that is an existing file)."""
    for arg in argv[1:]:
        if not arg.startswith("-") and os.path.isfile(arg):
            return arg
    return None


def managed_unit(unit: str) -> bool:
    """`n2disk@<nic>.service` is what this installer runs; every other n2disk unit is someone else's."""
    return unit.startswith("n2disk@")


# Unit states of a set-up n2disk that does not record right now: an invalid or expired licence leaves the
# first customer's n2disk.service failed, or restarting forever (activating), and it comes back on its own
# once the licence is valid again. Such a unit is adopted all the same: the installer must not set up a
# second n2disk on the same NIC and buffer that would record beside it after the licence is renewed.
_SET_UP_STATES = ("active", "activating", "reloading", "deactivating", "failed")


def _list_units(out: str) -> list[tuple[str, str, str]]:
    """(unit, load, active) of `systemctl list-units --all --plain --no-legend` lines."""
    rows = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0].endswith(".service"):
            rows.append((parts[0], parts[1], parts[2]))
    return rows


def _enabled_unit_files(out: str) -> list[str]:
    """Enabled, non-template units of `systemctl list-unit-files --plain --no-legend` lines."""
    names = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].endswith(".service") and "@." not in parts[0] and parts[1] == "enabled":
            names.append(parts[0])
    return names


def find_external_n2disk(r) -> dict | None:
    """An n2disk set up on this host outside the installer's `n2disk@<nic>` unit, or None.

    A running one is found first. Without one, and without a running `n2disk@<nic>`, a unit of someone
    else that is failed, restarting or enabled counts as well (an expired licence stops it, a renewed one
    brings it back). Returns {"unit", "config", "options", "argv", "state"}; `unit` is None for an n2disk not
    started by systemd (screen, nohup), `config` is None when the options are on the command line.
    """
    rc, out = r.probe(["systemctl", "list-units", "--all", "--type=service", "--plain", "--no-legend", "n2disk*"])
    rows = [u for u in _list_units(out) if u[1] == "loaded"] if rc == 0 else []
    active = [u for u, _load, state in rows if state == "active"]
    for unit in active:
        if not managed_unit(unit):
            return _describe(unit, _execstart(r, unit), "active")
    if any(managed_unit(u) for u in active):
        return None
    candidates = [(u, state) for u, _load, state in rows if not managed_unit(u) and state in _SET_UP_STATES]
    rc, out = r.probe(["systemctl", "list-unit-files", "--type=service", "--plain", "--no-legend", "n2disk*"])
    for unit in _enabled_unit_files(out) if rc == 0 else []:
        if not managed_unit(unit) and unit not in [c[0] for c in candidates]:
            candidates.append((unit, next((s for u, _l, s in rows if u == unit), "inactive")))
    for unit, state in candidates:
        argv = _execstart(r, unit)
        if argv:
            return _describe(unit, argv, state)
    rc, out = r.probe(["pgrep", "-a", "^n2disk"])
    if rc == 0:
        for line in out.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                try:
                    argv = shlex.split(parts[1])
                except ValueError:
                    argv = parts[1].split()
                if argv and os.path.basename(argv[0]).startswith("n2disk"):
                    return _describe(None, argv, "active")
    return None


def _execstart(r, unit: str) -> list[str]:
    return parse_execstart(r.probe(["systemctl", "show", "-p", "ExecStart", "--value", unit])[1])


def _describe(unit: str | None, argv: list[str], state: str = "active") -> dict:
    conf = config_of(argv)
    text = ""
    if conf:
        try:
            with open(conf) as fh:
                text = fh.read()
        except OSError:
            text = ""
    else:
        text = " ".join(shlex.quote(a) for a in argv[1:])
    return {"unit": unit, "config": conf, "options": parse_n2disk_conf(text), "argv": argv, "state": state}


def describe(ext: dict) -> str:
    who = ext["unit"] or "a process outside systemd"
    return f"{who}" + (f" with {ext['config']}" if ext["config"] else "")


def recording(ext: dict) -> bool:
    """Does the adopted n2disk run now (False: set up, but failed or restarting, e.g. on an expired licence)."""
    return ext.get("state", "active") == "active"


def compatibility(ext: dict, a: dict) -> list[tuple[str, str, str, str]]:
    """(status, name, detail, hint): does the recorder (the answers) agree with the n2disk that runs?"""
    o, out = ext["options"], []
    iface = o.get("iface")
    if iface is None:
        out.append(("warn", "external n2disk NIC", "could not read its interface", f"check {describe(ext)} by hand"))
    elif iface != a["capture_iface"]:
        out.append(("fail", "external n2disk NIC", f"it records {iface}, the answer is {a['capture_iface']}",
                    f"answer capture_iface={iface} (--redo with CAPTURE_IFACE={iface})"))
    else:
        out.append(("ok", "external n2disk NIC", iface, ""))
    rolling = os.path.normpath(a["rolling_dir"])
    for key, label in (("dump_dir", "dump directory"), ("timeline_dir", "timeline directory")):
        have = o.get(key)
        if have is None:
            out.append(("fail" if key == "timeline_dir" else "warn", f"external n2disk {label}", "not set",
                        "the recorder extracts through n2disk's timeline: --timeline-dir must be the rolling directory"
                        if key == "timeline_dir" else ""))
        elif os.path.normpath(have) != rolling:
            out.append(("fail", f"external n2disk {label}", f"{have}, the answer is {a['rolling_dir']}",
                        f"answer rolling_dir={have} (ROLLING_DIR={have})"))
        else:
            out.append(("ok", f"external n2disk {label}", have, ""))
    dur = o.get("duration")
    if dur is None:
        out.append(("warn", "external n2disk file duration", "not set (n2disk's default)",
                    f"set --max-file-duration={a['chunk_seconds']} in {ext['config'] or 'its command line'}: the recorder "
                    "waits that long for a file to close"))
    elif not dur.isdigit() or int(dur) != int(a["chunk_seconds"]):
        out.append(("fail", "external n2disk file duration", f"{dur} s, the recorder waits {a['chunk_seconds']} s",
                    f"answer chunk_seconds={dur} (CHUNK_SECONDS={dur}): they must be equal"))
    else:
        out.append(("ok", "external n2disk file duration", f"{dur} s", ""))
    out.append(("ok" if o.get("index") else "warn", "external n2disk index", "on" if o.get("index") else "off",
                "" if o.get("index") else "add --index: without it every extraction reads whole files"))
    if a.get("packet_slicing") not in (None, "", "off") or (a.get("capture_filter") or "").strip():
        out.append(("warn", "packet slicing / capture filter", "answers not applied: n2disk is not managed by the installer",
                    f"set them in {ext['config'] or 'its command line'} by hand if wanted"))
    return out


# ---- the stack of an earlier deployment ---------------------------------------------------------
LEGACY_COMPOSE_FILES = ("compose.yaml", "compose.override.yaml", "docker-compose.yml", "docker-compose.override.yml")


def legacy_stack(install_dir: str, deployed_name: str = ".deployed") -> list[str] | None:
    """The compose files of a stack this installer did not deploy, or None.

    A directory with a compose file and no `.deployed` record is an earlier deployment (the September 2026
    one, or one made by hand from README_DEPLOY). Its own files are needed to stop it: once the new code is
    synced over them they are gone.
    """
    if os.path.exists(os.path.join(install_dir, deployed_name)):
        return None
    files = [f for f in LEGACY_COMPOSE_FILES if os.path.isfile(os.path.join(install_dir, f))]
    return files or None


def quote_hash_line(line: str) -> str | None:
    """`BASIC_AUTH_HASH=$2a$14$...` unquoted is mangled by compose's interpolation: the quoted line, else None."""
    m = re.fullmatch(r"BASIC_AUTH_HASH=(\$2[aby]?\$\d\d\$[./A-Za-z0-9]{53})\s*", line)
    return f"BASIC_AUTH_HASH='{m.group(1)}'" if m else None


def legacy_cert(install_dir: str) -> tuple[str, str] | None:
    """(crt, key) of an own certificate the older layout kept under caddy/certs, when the new ./certs has none."""
    old = os.path.join(install_dir, "caddy", "certs")
    crt, key = os.path.join(old, "server.crt"), os.path.join(old, "server.key")
    new = os.path.join(install_dir, "certs")
    if os.path.isfile(crt) and os.path.isfile(key) and not os.path.isfile(os.path.join(new, "server.crt")):
        return crt, key
    return None


def caddyfile_uses_own_cert(install_dir: str) -> bool:
    try:
        with open(os.path.join(install_dir, "caddy", "Caddyfile")) as fh:
            text = fh.read()
    except OSError:
        return False
    return bool(re.search(r"^\s*tls\s+/certs/", text, re.M))


# Settings of an older .env worth a word: they are kept (the customer's choice), but they differ from 0.4's defaults.
NOTABLE_ENV = {
    "SR_RETENTION_MAX_AGE_DAYS": ("0", "PCAPs older than {v} days are deleted automatically; 0.4's default is never "
                                       "(PCAPs are evidence). Remove the line from .env to keep them"),
    "SR_MAX_CONCURRENT_EXTRACTIONS": ("4", "{v} extraction(s) at a time; 0.4's default is 4 (a burst of alerts waits "
                                           "longer with fewer). Remove the line from .env for the default"),
}


def notable_env(env: dict[str, str]) -> list[tuple[str, str]]:
    out = []
    for k, (default, text) in NOTABLE_ENV.items():
        v = env.get(k, "").strip().strip("'\"")
        if v and v != default:
            out.append((k, text.format(v=v)))
    return out


def env_defaults(install_dir: str) -> dict[str, str]:
    """Answers an earlier .env already holds (answer key -> value), to offer them as defaults."""
    env: dict[str, str] = {}
    try:
        with open(os.path.join(install_dir, ".env")) as fh:
            for line in fh:
                if "=" in line and not line.lstrip().startswith("#"):
                    k, v = line.rstrip("\n").split("=", 1)
                    env[k.strip()] = v.strip().strip("'\"")
    except OSError:
        return {}
    out = {}
    for key, var in (("public_host", "SR_PUBLIC_HOST"), ("basic_auth_user", "BASIC_AUTH_USER"),
                     ("allowed_ips", "ALLOWED_IPS"), ("chunk_seconds", "SR_CHUNK_SECONDS"),
                     ("rolling_dir", "SR_ROLLING_DIR"), ("alerts_dir", "SR_ALERTS_DIR"),
                     ("https_port", "SR_HTTPS_PORT"), ("http_port", "SR_HTTP_PORT")):
        if env.get(var) and not env[var].startswith("CHANGE_ME"):
            out[key] = env[var]
    return out


_UNITS = {"us": 1e-6, "ms": 1e-3, "s": 1, "min": 60, "h": 3600, "d": 86400}


def systemd_seconds(value: str) -> float | None:
    """`1min 30s`, `100ms`, `30s` -> seconds; `infinity` -> inf; None when unreadable."""
    value = value.strip()
    if value == "infinity":
        return float("inf")
    parts = re.findall(r"(\d+(?:\.\d+)?)\s*(us|ms|min|s|h|d)", value)
    if not parts or re.sub(r"[\d.\s]|us|ms|min|s|h|d", "", value):
        return None
    return sum(float(n) * _UNITS[u] for n, u in parts)


def restarts_forever(props: dict[str, str]) -> bool:
    """Does a unit with these `systemctl show` properties restart a crashing service without ever giving up?

    systemd gives up after StartLimitBurst starts within StartLimitIntervalUSec. With RestartSec so long that
    the burst never fits in the interval (n2disk.service of the first customer: RestartSec=5 against the
    default 5 in 10 s), or with the limit off (burst 0, interval 0), an invalid licence restarts n2disk forever.
    """
    if props.get("Restart", "no").strip() not in ("always", "on-failure", "on-abnormal", "on-abort"):
        return False
    burst = props.get("StartLimitBurst", "").strip()
    interval = systemd_seconds(props.get("StartLimitIntervalUSec", ""))
    restart = systemd_seconds(props.get("RestartUSec", ""))
    if not burst.isdigit() or interval is None or restart is None:
        return False  # cannot tell: no warning on a guess
    if int(burst) == 0 or interval == 0:
        return True
    return restart * (int(burst) - 1) >= interval
