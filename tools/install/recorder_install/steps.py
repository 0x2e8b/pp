"""The installation steps. Each is `fn(ctx, apply) -> Result`: it inspects the host and reports;
with apply=True it first changes what is missing or wrong, then reports what is now true.

A step is idempotent and never touches the PCAP directories' contents. Changes go through
`ctx.r`, so --dry-run prints them and --check cannot make them.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import stat
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

from . import legacy
from . import licence
from . import nprobe as np_
from . import paths
from .report import Result
from .system import Host, Runner, healthz_status, insecure_context as _insecure_context

BASE_PACKAGES = ["ca-certificates", "curl", "wget", "gnupg", "lsb-release", "whiptail", "ethtool",
                 "tcpdump", "jq", "rsync", "python3", "openssl"]
SUPPORTED = {("debian", "12"), ("debian", "13"), ("ubuntu", "22.04"), ("ubuntu", "24.04")}


def apt_based(os_rel: dict) -> bool:
    """Debian, Ubuntu or a release built on them (ID_LIKE): the installer's apt and systemd calls work there."""
    ids = {os_rel.get("ID", "")} | set(os_rel.get("ID_LIKE", "").split())
    return bool(ids & {"debian", "ubuntu"})


def _strip_prefix(text: str, prefix: str) -> str:
    """str.removeprefix, which Python 3.8 (Ubuntu 20.04) lacks."""
    return text[len(prefix):] if text.startswith(prefix) else text
MARKER = "# Managed by the recorder installer."
NPCAPEXTRACT = "/usr/bin/npcapextract"  # module constants, so that tests can point them elsewhere
N2DISK_CONF_DIR = "/etc/n2disk"
SYSTEMD_DIR = "/etc/systemd/system"
OBSOLETE_ENV = ("SR_MODE", "SR_LOG_BUFFER_LINES")  # settings 0.4 no longer has; a 0.3 .env may still carry them
DEPLOYED = ".deployed"  # in the install directory: what the running stack was built from
HEALTH_TIMEOUT = 120  # seconds the stack gets to answer /healthz after `up`
STACK_BACKUP_ROOT = "/var/lib/sycope-recorder-installer/stack-backup"  # an earlier stack's files, before replacing it
PRE_DEPLOY = ("profiles", "certs", ".env", "credentials")  # what a fresh install directory may hold before the first sync

# What the host is for. recorder-only is what every installation before the profiles was (and what an old
# state.json without the answer means); full adds nProbe beside n2disk; probe-only is nProbe alone.
PROFILES = ("recorder-only", "full", "probe-only")
DEFAULT_PROFILE = "recorder-only"
EVERY = frozenset(PROFILES)
RECORDER = frozenset({"recorder-only", "full"})  # n2disk, the stack, the Passthrough
PROBE = frozenset({"full", "probe-only"})  # nProbe


def profile(a: dict) -> str:
    return a.get("profile") or DEFAULT_PROFILE


def records(a: dict) -> bool:
    """This host runs n2disk and the recorder stack."""
    return profile(a) in RECORDER


def probes(a: dict) -> bool:
    """This host runs nProbe."""
    return profile(a) in PROBE


@dataclass
class Ctx:
    a: dict
    secrets: dict
    r: Runner
    host: Host
    repo: str
    sycope: dict | None = None
    dry: bool = False
    extra: dict = field(default_factory=dict)  # facts one step hands to the next


def say(ctx, msg: str) -> None:
    """A progress line under the running step (long waits, calls to Sycope), so the operator sees what happens."""
    log = getattr(ctx.r, "log", None)
    if log:
        log(msg)


def _apt(ctx: Ctx, *args: str) -> tuple[int, str]:
    """apt-get, with --no-remove on every install: -y would otherwise approve removing a conflicting
    package (docker.io, containerd) and, one day, one that n2disk's licence depends on."""
    if args and args[0] == "install":
        args = (args[0], "--no-remove", *args[1:])
    return ctx.r.run(["apt-get", *args], env={"DEBIAN_FRONTEND": "noninteractive"})


# The smallest rolling limit the installer accepts: four capture files (n2disk_conf: --max-file-len=256).
# n2disk keeps the buffer under --disk-limit by deleting the oldest files, at start as well: a limit below
# what the buffer holds deletes that history, and one below a single file deletes the file being written.
MIN_ROLLING_MB = 1024


def limit_mb(value: str, total_mb: float) -> float:
    """A rolling limit answer ("81920" MB or "60%" of the volume) in MB."""
    return total_mb * int(value[:-1]) / 100 if value.endswith("%") else float(value)


def limit_problem(value: str, total_mb: float | None = None) -> str | None:
    """Why `value` cannot be the rolling limit, or None. `total_mb` is the size of the capture volume
    (None when not known yet: then only a plain number is checked against MIN_ROLLING_MB)."""
    m = re.fullmatch(r"(\d+)(%?)", value)
    if not m:
        return "use MB (e.g. 81920) or a percentage of the volume (e.g. 60%)"
    n = int(m.group(1))
    if m.group(2):
        if not 1 <= n <= 100:
            return "a percentage between 1% and 100%"
        if total_mb is not None and limit_mb(value, total_mb) < MIN_ROLLING_MB:
            return (f"{n}% of this volume is {limit_mb(value, total_mb):.0f} MB, less than {MIN_ROLLING_MB} MB "
                    "(four capture files): n2disk would delete the file it is writing")
        return None
    if n < MIN_ROLLING_MB:
        return (f"{n} is in MB and less than {MIN_ROLLING_MB} MB (four capture files): n2disk would delete the "
                "whole buffer to fit" + (f". For {n} percent of the volume answer {n}%" if 1 <= n <= 100 else "")
                + f"; for {n} GB answer {n * 1024}")
    return None


def buffer_cut(a: dict, total_mb: float, used_mb: float | None, current_limit: str | None) -> tuple[float, float] | None:
    """(MB the buffer holds, MB of the limit) when starting n2disk with the answered limit would delete
    capture history, else None.

    A buffer that already runs under this limit or a smaller one sits at the limit by design and is left
    alone; so is one whose size cannot be told. The margin is two capture files (the one being written
    and the rounding of the sizes): anything more that would go is said."""
    if used_mb is None:
        return None
    new = limit_mb(a["rolling_limit"], total_mb)
    if current_limit and limit_problem(current_limit) is None and limit_mb(current_limit, total_mb) <= new:
        return None
    return (used_mb, new) if used_mb > new + MIN_ROLLING_MB / 2 else None


def current_rolling_limit(iface: str) -> str | None:
    """--disk-limit of the n2disk configuration the installer wrote for `iface`, if there is one."""
    try:
        with open(f"{N2DISK_CONF_DIR}/n2disk-{iface}.conf") as fh:
            return legacy.parse_n2disk_conf(fh.read()).get("disk_limit")
    except OSError:
        return None


def _pkg(ctx: Ctx, name: str) -> bool:
    """Installed, also when the operator holds it (`hold ok installed`): a held package is not installed again."""
    rc, out = ctx.r.probe(["dpkg-query", "-W", "-f=${Status}", name])
    return rc == 0 and out.strip().endswith("ok installed")


# ntop's packages are tied to each other by exact versions (n2disk depends on pfring (= x) and
# ntop-license (= y)), so installing one that is missing can pull every installed one to the newest build.
# A licence is checked by the product it was issued for: the installer never moves an installed one.
GUARDED_PACKAGES = ("n2disk", "nprobe", "pfring", "pfring-dkms", "ntop-license", "ndpi", "ntopng", "cento")
_SIM_UPGRADE = re.compile(r"^Inst (\S+) \[([^\]]+)\] \((\S+)", re.MULTILINE)


def _apt_moves(ctx: Ctx, *pkgs: str) -> list[str]:
    """Installed ntop packages that `apt-get install <pkgs>` would upgrade as well, as "name old -> new".

    A simulation (`apt-get -s`): nothing is changed. Empty when apt would leave them alone, and when the
    simulation itself fails (the install then fails the same way and says why)."""
    rc, out = ctx.r.probe(["apt-get", "-s", "install", "--no-remove", *pkgs], timeout=120,
                          env={"DEBIAN_FRONTEND": "noninteractive"})
    if rc != 0:
        return []
    return [f"{n} {old} -> {new}" for n, old, new in _SIM_UPGRADE.findall(out)
            if n in GUARDED_PACKAGES and n not in pkgs]


def _moves_text(moves: list[str]) -> tuple[str, str]:
    """(detail, hint) for an install that was not made because it would upgrade licensed packages."""
    return ("not installed: apt would also upgrade " + ", ".join(moves) + "; the installer does not upgrade "
            "installed ntop packages (a licence is checked by the build it runs with)",
            "decide with the licence owner; to upgrade by hand: note `n2disk --show-system-id` and "
            "`n2disk --check-license`, apt-get install the package, check both again")


def _read(path: str, mode: str = "r", **kw):
    """The whole content of `path`, the file closed again before it returns."""
    with open(path, mode, **kw) as fh:
        return fh.read()


def _would(res: Result, name: str, what: str) -> Result:
    return res.add(name, "skip", f"would {what} (dry run)")


def external_n2disk(ctx: Ctx) -> dict | None:
    """The n2disk that records on this host outside the installer's n2disk@<nic> (legacy.py), cached per run.

    When there is one (the first customer's n2disk.service), the installer adopts it: it never writes its
    configuration, never starts a second n2disk and never restarts, retunes or moves it to PF_RING.
    """
    if "external_n2disk" not in ctx.extra:
        ctx.extra["external_n2disk"] = legacy.find_external_n2disk(ctx.r) if records(ctx.a) else None
    return ctx.extra["external_n2disk"]


# ---- 1. Sycope --------------------------------------------------------------------------------
def step_sycope(ctx: Ctx, apply: bool) -> Result:
    from . import sycope as sy

    res, s = Result(), ctx.sycope
    if s is None:
        return res.add("Sycope access", "skip", "no Sycope credentials given",
                       "give the URL, user and password (profiles and the checks below need them)")
    if not s["ok"]:
        return res.add("Sycope login", "fail", s["error"] or "login failed",
                       "check the URL (https://host[:port]), the user and the password")
    res.add("Sycope login", "ok", ctx.a["sycope_url"])
    if s["error"]:
        res.add("alert definitions", "fail", s["error"], "the user needs permission to read alert definitions")
    else:
        status = "ok" if s["defs_active"] else "warn"
        res.add("alert definitions", status, f"{s['defs_active']} active of {s['defs_total']}",
                "" if s["defs_active"] else "no active alert definition: nothing will ever call the recorder")
    macros = s["macros"]
    if macros:
        bad = [n for n, m in macros.items() if not m["nql"]]
        res.add("macros", "ok" if not bad else "warn", f"{len(macros) - len(bad)} of {len(macros)} readable",
                "" if not bad else "unreadable: " + ", ".join(f"{n} ({macros[n]['status']})" for n in bad)
                + ". Their conditions are not part of the BPF filter (a broader filter, never a wrong one)")
        for name, m in macros.items():
            for lk in m["lookups"]:
                res.add(f"macro {name} -> lookup '{lk['lookup']}'", "ok" if lk["networks"] else "warn",
                        f"{len(lk['networks'])} network(s) with {lk['field']} in {lk['values']}",
                        "" if lk["networks"] else lk["status"])
    skew = s["skew"]
    if skew is not None:
        res.add("clock vs Sycope", "ok" if abs(skew) <= 5 else "warn", f"Sycope is {skew:+.0f} s from this host",
                "" if abs(skew) <= 5 else "synchronise both with NTP: the extraction window is host time")
    if "destinations_error" in s:
        res.add("External Destinations", "warn", f"could not list them: {s['destinations_error']}")
    for status, name, detail, hint in sy.analyze_destinations(
            s["destinations"], s["expected_destination_path"], s.get("passthroughs")):
        if status == "warn" and name == "External Destination":  # none yet: the destination step creates it
            status, detail, hint = "ok", detail + "; the External Destination step creates it", ""
        if sy.DEAD in hint:  # said again in the next steps: alerts that use it record nothing
            ctx.extra.setdefault("dead_destinations", []).append(_strip_prefix(name, "External Destination "))
        res.add(name, status, detail, hint)
    return res


# ---- 2. Preflight -----------------------------------------------------------------------------
def step_preflight(ctx: Ctx, apply: bool) -> Result:
    h, a, res = ctx.host, ctx.a, Result()
    os_rel = h.os_release()
    key = (os_rel.get("ID", ""), os_rel.get("VERSION_ID", ""))
    if key in SUPPORTED:
        res.add("operating system", "ok", os_rel.get("PRETTY_NAME", "unknown"))
    elif apt_based(os_rel):
        # Another Debian or Ubuntu release (an older host that already runs n2disk and Docker): the installer
        # works there, it only cannot add the ntop repository or Docker for a release they do not publish.
        res.add("operating system", "warn", os_rel.get("PRETTY_NAME", "unknown") + ": not a tested release",
                "tested: Debian 12/13, Ubuntu 22.04/24.04; elsewhere n2disk and Docker should already be installed")
    else:
        res.add("operating system", "fail", os_rel.get("PRETTY_NAME", "unknown"),
                "supported: Debian 12/13, Ubuntu 22.04/24.04 (ntop publishes packages for these)")
    res.add("architecture", "ok" if h.arch() == "x86_64" else "fail", h.arch(), "ntop packages are x86_64 only")
    res.add("root", "ok" if h.is_root() else "fail", "" if h.is_root() else "not root", "run with sudo")
    res.add("CPU cores", "ok" if h.cpu_count() >= 2 else "warn", str(h.cpu_count()), "2 or more recommended")
    res.add("memory", "ok" if h.mem_mb() >= 4096 else "warn", f"{h.mem_mb()} MB",
            "n2disk buffers 1 GB (--buffer-len=1024); 4 GB or more recommended")
    res.add("install profile", "ok", profile(a))
    if records(a):
        _preflight_recorder(ctx, res)
    elif not h.reachable("https://packages.ntop.org/"):
        res.add("reach https://packages.ntop.org/", "fail", "no answer",
                "the packages cannot be installed from here (proxy or firewall?)")
    _preflight_capture_nic(ctx, res)
    left = np_.managed_confs()
    if left and not probes(a):
        # A profile switch never undoes another profile's steps: say what still runs.
        res.add("nProbe", "warn", f"configured by an earlier run ({', '.join(left)}), not part of the profile {profile(a)}",
                "stop it if it is not wanted: " + " ; ".join(f"systemctl disable --now nprobe@{n}" for n in left))
    return res


def _preflight_recorder(ctx: Ctx, res: Result) -> None:
    """Disk, time and port checks of a host that records."""
    h, a = ctx.host, ctx.a
    rolling, alerts = a["rolling_dir"], a["alerts_dir"]
    # What the rolling buffer may use is the free space plus what the buffer itself already holds: on a
    # host that has been recording, the volume is full of the buffer by design.
    free, total = h.disk_free_gb(rolling), h.disk_total_gb(rolling)
    held = (h.dir_used_mb(rolling) or 0) / 1024
    room = min(total, free + held)
    res.add("space for the capture", "ok" if room >= 20 else "warn",
            f"{room:.0f} GB on {rolling} (volume {total:.0f} GB: {free:.0f} GB free"
            + (f", {held:.0f} GB held by the rolling buffer" if held >= 1 else "") + ")",
            "" if room >= 20 else "20 GB or more is recommended for the rolling buffer; give it a larger volume")
    why = limit_problem(a.get("rolling_limit") or "", total * 1024) if not external_n2disk(ctx) else None
    if why:
        res.add("rolling limit", "fail", f"{a.get('rolling_limit')}: {why}", "run the installer and answer the limit again")
    if h.same_filesystem(rolling, "/"):
        res.add("capture volume", "warn", f"{rolling} is on the root filesystem",
                "put /storage on its own disk: a full capture must not stop the system")
    else:
        res.add("capture volume", "ok", "separate filesystem")
    if not h.same_filesystem(rolling, alerts):
        res.add("alerts volume", "warn", "alerts and rolling are on different filesystems",
                "works, but the free-space guard looks at the alerts filesystem only")
    tz = h.timezone()
    res.add("time zone", "ok", f"{tz} (the recorder's TZ must equal this: n2disk names its directories in it)")
    res.add("clock", "ok" if h.ntp_synced() else "warn", "NTP synchronised" if h.ntp_synced() else "not synchronised",
            "" if h.ntp_synced() else "enable NTP (timedatectl set-ntp true): extraction windows use the host clock")
    ours = ctx.r.probe("docker ps --format '{{.Names}}' 2>/dev/null | grep -c sycope-recorder")[1].strip() not in ("", "0")
    for port in (443, 80):
        busy = h.port_listening(port)
        res.add(f"port {port}", "ok" if (not busy or ours) else "warn",
                "free" if not busy else ("held by this recorder" if ours else "in use by another service"),
                "" if (not busy or ours) else "the recorder's Caddy publishes this port: stop the other service or change the mapping")
    if not ours:
        for url in ("https://packages.ntop.org/", "https://download.docker.com/"):
            ok = h.reachable(url)
            res.add(f"reach {url}", "ok" if ok else "fail", "" if ok else "no answer",
                    "" if ok else "the packages cannot be installed from here (proxy or firewall?)")


def _preflight_capture_nic(ctx: Ctx, res: Result) -> None:
    h, a = ctx.host, ctx.a
    if a["capture_iface"] in h.default_route_ifaces():
        # The SystemID (so the licence) comes from the management NIC, and the host must stay reachable.
        ctx.extra["capture_nic_is_management"] = True
        res.add("capture NIC", "fail", "the capture NIC is the management NIC",
                f"{a['capture_iface']} carries a default route (IPv4 or IPv6): capture on another interface; the SystemID "
                "of the n2disk licence is derived from the management NIC and must not change")
    nic = next((n for n in h.nics() if n["name"] == a["capture_iface"]), None)
    if nic is None:
        res.add("capture NIC", "fail", f"{a['capture_iface']} does not exist", "check the name with: ip -br link")
    else:
        if nic["ipv4"]:
            res.add("capture NIC", "fail", f"{nic['name']} has an IPv4 address {nic['ipv4']}",
                    "the capture NIC must be a bare interface (no address): use another NIC for management")
        else:
            res.add("capture NIC", "ok", f"{nic['name']} {nic['mac']}, no IPv4 address, mtu {nic['mtu']}")
        if not nic["carrier"]:
            res.add("capture NIC link", "warn", f"state {nic['state']}, no carrier",
                    "the installer brings the interface up; then check the SPAN/mirror port and cabling")


# ---- 3. Packages and ntop ---------------------------------------------------------------------
def step_base_packages(ctx: Ctx, apply: bool) -> Result:
    res = Result()
    missing = [p for p in BASE_PACKAGES if not _pkg(ctx, p)]
    if missing and apply:
        if ctx.dry:
            _apt(ctx, "install", "-y", *missing)
            return _would(res, "base packages", "install " + ", ".join(missing))
        _apt(ctx, "update", "-qq")
        _apt(ctx, "install", "-y", "-qq", *missing)
        missing = [p for p in BASE_PACKAGES if not _pkg(ctx, p)]
    if missing:
        return res.add("base packages", "fail" if apply else "warn", "missing: " + ", ".join(missing),
                       "apt-get install " + " ".join(missing))
    return res.add("base packages", "ok", f"{len(BASE_PACKAGES)} present")


def _contrib_present() -> bool:
    paths = ["/etc/apt/sources.list"] + [os.path.join("/etc/apt/sources.list.d", f)
                                          for f in (os.listdir("/etc/apt/sources.list.d") if os.path.isdir("/etc/apt/sources.list.d") else [])]
    for p in paths:
        try:
            with open(p) as fh:
                text = fh.read()
        except OSError:
            continue
        if re.search(r"^(deb(-src)?\s.*\bcontrib\b|Components:.*\bcontrib\b)", text, re.M):
            return True
    return False


def step_ntop_repo(ctx: Ctx, apply: bool) -> Result:
    res = Result()
    os_rel = ctx.host.os_release()
    is_debian = os_rel.get("ID") == "debian"
    path = os_rel.get("VERSION_CODENAME") if is_debian else os_rel.get("VERSION_ID")
    key = (os_rel.get("ID", ""), os_rel.get("VERSION_ID", ""))
    if (key not in SUPPORTED and _pkg(ctx, "n2disk") and not probes(ctx.a)
            and not _pkg(ctx, "apt-ntop-stable") and not _pkg(ctx, "apt-ntop")):
        # An older release with n2disk already installed (the adopted host): nothing has to come from ntop, and
        # ntop may not publish this release any more; the APT sources are not touched either. Upgrading n2disk
        # is the owner's call, not the installer's.
        return res.add("ntop repository", "ok", "not added: n2disk is installed already and "
                       f"{os_rel.get('PRETTY_NAME', 'this release')} is not a tested release")
    if is_debian and not _contrib_present():
        if not apply:
            res.add("contrib component", "warn", "missing from the APT sources", "the ntop packages need it")
        elif ctx.dry:
            _would(res, "contrib component", "add it to the APT sources")
        else:
            if os.path.exists("/etc/apt/sources.list.d/debian.sources"):
                ctx.r.run(["sed", "-i", "s/^Components: main$/Components: main contrib/",
                           "/etc/apt/sources.list.d/debian.sources"])
            else:
                ctx.r.run(["sed", "-i", "-E", r"/^deb(-src)? /{/ contrib( |$)/! s/ main( |$)/ main contrib\1/}",
                           "/etc/apt/sources.list"])
            res.add("contrib component", "ok" if _contrib_present() else "fail", "added")
    elif is_debian:
        res.add("contrib component", "ok", "present")
    if _pkg(ctx, "apt-ntop-stable"):
        return res.add("ntop repository", "ok", "present")
    if _pkg(ctx, "apt-ntop"):
        # An earlier set-up used ntop's development repository: adding the stable one beside it gives two
        # sources for the same packages, so it is kept as it is.
        return res.add("ntop repository", "ok", "present (apt-ntop, ntop's development repository: kept)")
    if not apply:
        return res.add("ntop repository", "warn", "not installed")
    if ctx.dry:
        return _would(res, "ntop repository", "install apt-ntop-stable")
    url = f"https://packages.ntop.org/apt-stable/{path}/all/apt-ntop-stable.deb"
    # A fresh root-only directory, never a fixed name in /tmp: a local user could plant a file or symlink there
    # and have apt install it as root. No checksum pin: ntop rebuilds this package (2.10-75 was rebuilt in
    # November 2026) and it differs per release path, so a pin would break installs. What is trusted is TLS to
    # packages.ntop.org (wget verifies it), plus the check below that the file is the apt-ntop-stable package.
    tmp = tempfile.mkdtemp(prefix="sycope-ntop-repo-")
    try:
        deb = os.path.join(tmp, "apt-ntop-stable.deb")
        rc, out = ctx.r.run(["wget", "-q", url, "-O", deb])
        if rc != 0:
            return res.add("ntop repository", "fail", f"download failed (wget rc {rc}){': ' + out[-200:] if out else ''}",
                           f"check that {url} can be reached from this host and exists for this release")
        rc, name = ctx.r.probe(["dpkg-deb", "-f", deb, "Package"])
        if rc != 0 or name.strip() != "apt-ntop-stable":
            return res.add("ntop repository", "fail", "the download is not the apt-ntop-stable package"
                           + (f" (package {name.strip()!r})" if rc == 0 else " (not a Debian package)") + ": not installed",
                           f"fetch {url} by hand and check what it returns")
        _apt(ctx, "install", "-y", "-qq", deb)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    _apt(ctx, "update", "-qq")
    ok = _pkg(ctx, "apt-ntop-stable")
    return res.add("ntop repository", "ok" if ok else "fail", "added" if ok else "could not be added",
                   "" if ok else f"check that https://packages.ntop.org/apt-stable/{path}/ exists for this release")


def _n2disk_info(ctx: Ctx) -> dict:
    """SystemID and licence validity (one parser, in licence.py)."""
    return licence.n2disk_info(ctx.r)


def _restore_licence(ctx: Ctx, target: str, previous: bytes | None, owner: tuple[int, int, int] | None) -> str:
    """Put the licence file back as it was before this run: content, owner, group and mode.

    `owner` is (uid, gid, mode) recorded before anything was written. Returns "" or the reason it failed.
    """
    try:
        if previous is None:
            if os.path.lexists(target):
                os.unlink(target)  # our own new file, which n2disk rejected
            return ""
        if not os.path.exists(target) or _read(target, "rb") != previous:
            ctx.r.write(target, previous, owner[2] if owner else None)
        if owner:
            os.chown(target, owner[0], owner[1])
            os.chmod(target, owner[2])
        return ""
    except OSError as exc:
        return f"{type(exc).__name__}: {exc}"


def _install_licence(ctx: Ctx, res: Result, apply: bool) -> None:
    """Install the licence file the operator gave, but never over a valid one and never unverified.

    The only code that touches the n2disk licence file. A valid installed licence is kept (unless
    --replace-licence); so is one whose validity cannot be determined (n2disk -V gave no answer): a
    licence that may be valid is never overwritten on a guess. A new one is checked with n2disk -V and
    rolled back (content, owner, group, mode) if it is not valid. When anything is unclear (symlink,
    unreadable file) the licence is left alone and reported.
    """
    given, target = ctx.a.get("license_file") or "", licence.N2DISK_LICENCE
    if not given or not os.path.isfile(given):
        return
    name = "licence file"
    try:
        with open(given, "rb") as fh:
            new = fh.read()
        if os.path.islink(target):
            res.add(name, "warn", f"{target} is a symlink: left untouched", "replace it by hand if that is intended")
            return
        current = _read(target, "rb") if os.path.exists(target) else None
        old = os.stat(target) if current is not None else None
        owner = (old.st_uid, old.st_gid, stat.S_IMODE(old.st_mode)) if old else None
    except OSError as exc:
        res.add(name, "warn", f"cannot read {exc.filename or given} ({exc.strerror}): the licence is left untouched")
        return
    if current == new:
        res.add(name, "ok", f"{given} is already installed as {target}")
        return
    before = licence.n2disk_info(ctx.r)
    replace = bool(ctx.extra.get("replace_licence"))
    if current is not None and not replace:
        if before["state"] == "valid":
            res.add(name, "warn", "a valid licence is installed; the given file was not installed",
                    "use --replace-licence to replace it")
            return
        if before["state"] == "unknown":
            res.add(name, "warn", "could not determine whether the installed licence is valid; not replaced",
                    "run n2disk -V by hand to see why, or use --replace-licence to replace it anyway")
            return
    if not apply:
        res.add(name, "warn", f"{given} is not installed yet", "run the installer to install it")
        return
    if ctx.dry:
        _would(res, name, f"install {given} as {target}")
        return
    backup = ctx.extra.get("licence_backup_dir")
    by_hand = f"restore it: {licence.restore_command(backup)}" if backup else "restore it by hand"
    try:
        ctx.r.write(target, new, 0o644)
    except Exception as exc:  # the write is atomic: the previous file is normally untouched
        failed = _restore_licence(ctx, target, current, owner)  # only acts if it is not
        detail = f"could not write {target}: {type(exc).__name__}: {exc}"
        if failed:
            res.add(name, "fail", f"{detail}; the previous licence could not be put back ({failed})", by_hand)
        else:
            res.add(name, "fail", f"{detail}; the previous licence is untouched", "free disk space or fix the permissions, then run again")
        return
    after = licence.n2disk_info(ctx.r)
    if after["state"] == "valid":
        ctx.extra.setdefault("licence_written", {})[target] = licence.sha256_file(target)
        res.add(name, "ok", f"installed {given} as {target}")
        return
    failed = _restore_licence(ctx, target, current, owner)
    sysid = after["system_id"] or before["system_id"] or "unknown"
    verdict = (f"the given licence is not valid for SystemID {sysid}" if after["state"] == "invalid"
               else "the given licence could not be verified (n2disk -V gave no answer)")
    if failed:
        res.add(name, "fail", f"{verdict} and the previous one could not be restored ({failed})", by_hand)
        return
    kept = "the previous licence was restored" if current is not None else "it was not kept"
    res.add(name, "fail", f"{verdict}; {kept}", f"ask for a licence issued for SystemID {sysid}")


def step_n2disk(ctx: Ctx, apply: bool) -> Result:
    res = Result()
    if not _pkg(ctx, "n2disk"):
        if not apply:
            return res.add("n2disk", "warn", "not installed")
        if ctx.dry:
            _apt(ctx, "install", "-y", "n2disk")
            return _would(res, "n2disk", "install n2disk (it contains npcapextract)")
        moves = _apt_moves(ctx, "n2disk")
        if moves:
            return res.add("n2disk", "fail", *_moves_text(moves))
        _apt(ctx, "install", "-y", "-qq", "n2disk")
    if not _pkg(ctx, "n2disk"):
        return res.add("n2disk", "fail", "could not be installed", "check the ntop repository above")
    ver = ctx.r.probe(["dpkg-query", "-W", "-f=${Version}", "n2disk"])[1]
    res.add("n2disk", "ok", ver)
    res.add("npcapextract", "ok" if os.path.exists(NPCAPEXTRACT) else "fail",
            NPCAPEXTRACT, "" if os.path.exists(NPCAPEXTRACT) else "it ships with the n2disk package")
    _install_licence(ctx, res, apply)
    info = _n2disk_info(ctx)
    ctx.extra["system_id"], ctx.extra["licensed"] = info["system_id"], info["licensed"]
    ctx.extra["licence_state"] = info["state"]
    res.add("SystemID", "ok", info["system_id"] or "unknown", "licences are issued on this value")
    if info["state"] == "unknown":
        res.add("n2disk licence", "warn", "could not be determined (n2disk -V gave no answer)",
                "run n2disk -V by hand; the licence file was not touched")
    else:
        res.add("n2disk licence", "ok" if info["licensed"] else "warn",
                (f"valid for {info['binary']}" + (f" (edition {info['edition']})" if info["edition"] else ""))
                if info["licensed"] else "missing or invalid",
                "" if info["licensed"] else f"install {licence.N2DISK_LICENCE} for SystemID {info['system_id']}; recording stays off until then, then re-run")
        if info["licensed"] and info["binary"] != "n2disk" and not external_n2disk(ctx):
            # A smaller edition: ntop's unit must start that binary (its ExecStartPre checks the licence).
            unit = ctx.r.probe(["systemctl", "cat", "n2disk@.service"])[1]
            if info["binary"] in unit:
                res.add("n2disk binary", "ok", f"n2disk@.service starts {info['binary']} for this licence")
            else:
                res.add("n2disk binary", "warn", f"the licence is for {info['binary']}, but n2disk@.service does "
                        "not select it", "update the n2disk package (its unit picks the binary by licence)")
    return res


# ---- 4. Capture NIC and n2disk ----------------------------------------------------------------
NIC_UNIT = """[Unit]
Description=Capture NIC %i: link up, no address, no IPv6
After=network-pre.target
Before=n2disk@%i.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/ip link set dev %i up
ExecStart=/usr/sbin/sysctl -qw net.ipv6.conf.%i.disable_ipv6=1 net.ipv6.conf.%i.accept_ra=0

[Install]
WantedBy=multi-user.target
"""
N2DISK_DROPIN = """# Bounded restarts: an invalid licence makes n2disk exit at once; unbounded retries flooded the
# journal with >1.5M restarts at the first customer. After 5 failures in 10 min the unit stays
# failed (visible); fix the cause, then `systemctl reset-failed n2disk@<nic>`.
[Unit]
StartLimitIntervalSec=600
StartLimitBurst=5
After=recorder-capture-nic@%i.service
Wants=recorder-capture-nic@%i.service

[Service]
RestartSec=30
"""


def _unit_state(ctx: Ctx, unit: str) -> str:
    return ctx.r.probe(["systemctl", "is-active", unit])[1].strip()


def _unit_age(ctx: Ctx, unit: str) -> float | None:
    """Seconds since `unit` became active, or None when it is not active or systemd does not say."""
    if _unit_state(ctx, unit) != "active":
        return None
    rc, out = ctx.r.probe(["systemctl", "show", "-p", "ActiveEnterTimestampMonotonic", "--value", unit])
    try:
        started = int(out.strip()) / 1e6  # microseconds on CLOCK_MONOTONIC, the clock of time.monotonic()
    except ValueError:
        return None
    age = time.monotonic() - started
    return age if rc == 0 and started > 0 and age >= 0 else None


def _owned_by(path: str, uid: str) -> bool:
    """True when the top-level owner of `path` is the numeric user id `uid`."""
    try:
        return os.stat(path).st_uid == int(uid)
    except (OSError, ValueError):
        return False


def step_capture_nic(ctx: Ctx, apply: bool) -> Result:
    res, a = Result(), ctx.a
    iface = a["capture_iface"]
    if apply and ctx.extra.get("capture_nic_is_management"):
        return res.add("capture NIC", "fail", f"not set up: {iface} is the management NIC",
                       "the host must stay reachable and the SystemID must not change: use another interface")
    rec = records(a)  # probe-only: the NIC unit, no n2disk drop-in, no PCAP directories
    unit_path = f"{SYSTEMD_DIR}/recorder-capture-nic@.service"
    dropin = f"{SYSTEMD_DIR}/n2disk@.service.d/10-recorder.conf"

    def have_dirs() -> bool:
        return not rec or (os.path.isdir(a["rolling_dir"]) and os.path.isdir(a["alerts_dir"]))
    current = (os.path.exists(unit_path) and _read(unit_path) == NIC_UNIT
               and (not rec or (os.path.exists(dropin) and _read(dropin) == N2DISK_DROPIN)))
    active = _unit_state(ctx, f"recorder-capture-nic@{iface}.service") == "active"
    dirs = have_dirs()
    if apply and not (current and active and dirs):
        rolling_existed = rec and os.path.isdir(a["rolling_dir"])
        ctx.r.write(unit_path, NIC_UNIT)
        if rec:
            ctx.r.write(dropin, N2DISK_DROPIN)
        ctx.r.run(["systemctl", "daemon-reload"])
        ctx.r.run(["systemctl", "enable", "--now", f"recorder-capture-nic@{iface}.service"])
        if rec:
            ctx.r.run(["mkdir", "-p", a["rolling_dir"], a["alerts_dir"]])
            rc, uid = ctx.r.probe(["id", "-u", "n2disk"])
            if rc == 0 and not (rolling_existed and (_owned_by(a["rolling_dir"], uid) or external_n2disk(ctx))):
                # Recursive over a rolling buffer of terabytes: only for a new directory or one that is not
                # n2disk's yet, never on every re-run. The alerts directory's contents are never touched.
                ctx.r.run(["chown", "-R", "n2disk:ntop", a["rolling_dir"]])
            ctx.r.run(["chmod", "0755", os.path.dirname(a["rolling_dir"]), a["rolling_dir"], a["alerts_dir"]])
        if ctx.dry:
            return _would(res, "capture NIC", f"set up {iface} (unit, no IPv6" + (", directories)" if rec else ")"))
        active = _unit_state(ctx, f"recorder-capture-nic@{iface}.service") == "active"
        dirs = have_dirs()
        current = os.path.exists(unit_path)
    res.add("capture NIC unit", "ok" if (current and active) else "warn" if not apply else "fail",
            f"recorder-capture-nic@{iface}: {'active' if active else 'not active'}",
            "" if active else "systemctl status recorder-capture-nic@" + iface)
    if rec:
        res.add("capture directories", "ok" if dirs else "warn" if not apply else "fail",
                f"{a['rolling_dir']}, {a['alerts_dir']}")
    return res


def _slicing_conf(a: dict) -> str:
    """The --packet-slicing line, or nothing when whole packets are recorded.

    Absent or "off" means whole packets: an installation from before this answer existed, and the
    default, keep writing full payload. Only 2, 3 and 4 are levels n2disk knows.
    """
    level = str(a.get("packet_slicing") or "off")
    if level not in ("2", "3", "4"):
        return ""
    return f"""# Only the headers up to L{level} are written; the payload is dropped at capture time and is not in
# the extracted PCAP either. Extraction and the index need L3/L4, so a level below 4 narrows what
# the recorder can filter on.
--packet-slicing={level}
"""


def _filter_conf(a: dict) -> str:
    """The --filter line, or nothing when every packet is recorded.

    An empty answer (and an installation from before this answer existed) records everything.
    The wizard has already checked that the value compiles and holds no character that could
    add or comment out a line of the configuration.
    """
    expr = str(a.get("capture_filter") or "").strip()
    if not expr:
        return ""
    return f"""# Only traffic matching this filter is recorded at all; the rest never reaches the buffer and
# cannot be extracted later. The alert's own filter is applied at extraction, on top of this one.
--filter={expr}
"""


def n2disk_conf(a: dict) -> str:
    return f"""{MARKER}
--interface={a['capture_iface']}
# Write in 4 MB chunks: the default 0.1 MB made 64 KB writes and the disk, not the CPU, dropped packets
# above ~4 Gbit/s in the lab (27-83% loss); with 4 MB the same VM kept 12.5 Gbit/s at under 1%.
--chunk-len=4096
--buffer-len=1024
--max-file-len=256
# Must equal SR_CHUNK_SECONDS: a file is closed (and indexed) this often. npcapextract only sees
# closed files, so the api waits chunk + margin before extracting.
--max-file-duration={a['chunk_seconds']}
--dump-directory={a['rolling_dir']}
--timeline-dir={a['rolling_dir']}
# Hard cap for the rolling buffer (MB or % of the volume).
--disk-limit={a['rolling_limit']}
--index
{_slicing_conf(a)}{_filter_conf(a)}"""


def _bak_name(path: str, content: str) -> str:
    """Where to copy a config before rewriting it: .bak, or .bak.<time> when a different .bak exists.

    An old backup is the operator's only copy of an earlier hand-made config: never overwritten.
    """
    bak = path + ".bak"
    if not os.path.lexists(bak):
        return bak
    try:
        if not os.path.islink(bak) and _read(bak) == content:
            return bak  # the same content: nothing is lost by copying over it
    except OSError:
        pass
    stamp, n = time.strftime("%Y%m%d-%H%M%S"), 0
    while True:
        cand = f"{bak}.{stamp}" + (f"-{n}" if n else "")
        if not os.path.lexists(cand):
            return cand
        n += 1


PF_RING_PROC = "/proc/net/pf_ring"
PF_RING_CONF = "/etc/pf_ring/pf_ring.conf"
PF_RING_SLOTS = "min_num_slots=65536"


def _pf_ring_loaded() -> bool:
    return os.path.exists(os.path.join(PF_RING_PROC, "info"))


def _n2disk_on_pf_ring(iface: str) -> bool:
    """n2disk opened a PF_RING socket on `iface` (in its libpcap fallback it has no entry in stats/)."""
    d = os.path.join(PF_RING_PROC, "stats")
    try:
        return any(re.match(rf"\d+-{re.escape(iface)}\.\d+$", f) for f in os.listdir(d))
    except OSError:
        return False


def step_pf_ring(ctx: Ctx, apply: bool) -> Result:
    """The PF_RING kernel module, so that n2disk does not fall back to libpcap.

    Without the module n2disk still records, through libpcap, and only says so in its log. The module
    comes from pfring-dkms (built for the running kernel, so it needs that kernel's headers). In the
    lab loading it did not change the SystemID; the licence is still checked before and after, and the
    module is taken out again if the SystemID moved. A module that does not load (Secure Boot without
    an enrolled key, missing headers) is a warning: n2disk keeps recording with libpcap.
    """
    res, a = Result(), ctx.a
    iface = a["capture_iface"]
    headers = f"linux-headers-{os.uname().release}"
    unit = f"n2disk@{iface}.service"
    ext = external_n2disk(ctx)
    if ext:
        # A new kernel module and a restart of a licensed capture that the installer did not set up: not here.
        loaded = _pf_ring_loaded()
        return res.add("PF_RING module", "ok" if loaded else "warn",
                       ("loaded" if loaded else "not loaded: n2disk may capture with libpcap")
                       + f"; not changed: n2disk runs as {legacy.describe(ext)}, outside the installer",
                       "" if loaded else "fine up to ~1-2 Gbit/s; for more, plan PF_RING with the owner of that n2disk")
    if not _pf_ring_loaded():
        if not apply:
            return res.add("PF_RING module", "warn", "not loaded: n2disk captures with libpcap",
                           "run the installer to add it (pfring-dkms)")
        if ctx.dry:
            _apt(ctx, "install", "-y", headers, "pfring-dkms")
            return _would(res, "PF_RING module", f"install {headers} and pfring-dkms and load pf_ring")
        before = ctx.extra.get("system_id") or _n2disk_info(ctx)["system_id"]
        # Only what is missing is installed: an installed pfring-dkms whose module is merely not loaded
        # (after the uninstaller, or a stopped pf_ring.service) is started below, never installed again.
        missing = [p for p in (headers, "pfring-dkms") if not _pkg(ctx, p)]
        if missing:
            _apt(ctx, "update", "-qq")
            moves = _apt_moves(ctx, *missing)
            if moves:
                detail, hint = _moves_text(moves)
                return res.add("PF_RING module", "warn", detail,
                               hint + "; until then n2disk records with libpcap")
            rc, out = _apt(ctx, "install", "-y", "-qq", *missing)
            if rc != 0:
                return res.add("PF_RING module", "warn", f"not installed ({out.strip()[-160:] or 'apt-get failed'})",
                               f"apt-get install {' '.join(missing)}; until then n2disk records with libpcap")
        ctx.r.run(["mkdir", "-p", os.path.dirname(PF_RING_CONF)])
        if not os.path.exists(PF_RING_CONF) or not _read(PF_RING_CONF).strip():
            ctx.r.write(PF_RING_CONF, PF_RING_SLOTS + "\n")
        ctx.r.write(os.path.join(os.path.dirname(PF_RING_CONF), "pf_ring.start"), "")
        ctx.r.run(["systemctl", "enable", "--now", "pf_ring.service"])
        after = _n2disk_info(ctx)["system_id"]
        if before and after and after != before:
            ctx.r.run(["systemctl", "disable", "--now", "pf_ring.service"])
            ctx.r.run(["rmmod", "pf_ring"])
            return res.add("PF_RING module", "fail", f"the SystemID changed from {before} to {after} after loading it: "
                           "the module was taken out again", "check n2disk -V; do not reboot with pf_ring enabled")
        if not _pf_ring_loaded():
            return res.add("PF_RING module", "warn", "installed but not loaded: n2disk captures with libpcap",
                           "Secure Boot? (mokutil --sb-state) enrol the DKMS key or load it by hand: modprobe pf_ring")
        res.add("PF_RING module", "ok", "installed and loaded")
    else:
        res.add("PF_RING module", "ok", "loaded")
    if _unit_state(ctx, unit) != "active":
        return res  # n2disk_config starts it, and then it opens PF_RING
    if _n2disk_on_pf_ring(iface):
        return res.add("n2disk capture", "ok", f"PF_RING on {iface}")
    path = f"{N2DISK_CONF_DIR}/n2disk-{iface}.conf"
    have = _read(path) if os.path.exists(path) else None
    if have is not None and have.startswith(MARKER) and have != n2disk_conf(a):
        return res.add("n2disk capture", "ok", "libpcap now; the configuration step restarts n2disk onto PF_RING")
    licensed = ctx.extra.get("licensed")
    if licensed is None:
        licensed = _n2disk_info(ctx)["licensed"]
    if not (apply and licensed):
        return res.add("n2disk capture", "warn", f"libpcap on {iface}", f"systemctl restart {unit}")
    ctx.r.run(["systemctl", "restart", unit])
    if not ctx.dry:
        time.sleep(4)
    on = _n2disk_on_pf_ring(iface)
    return res.add("n2disk capture", "ok" if on else "warn",
                   f"restarted onto PF_RING on {iface}" if on else f"still libpcap on {iface} after a restart",
                   "" if on else f"journalctl -u {unit} | grep -i pf_ring")


def _external_n2disk_report(ctx: Ctx, ext: dict) -> Result:
    """The adopted n2disk: nothing is written or restarted, only checked against the answers."""
    res, a = Result(), ctx.a
    res.add("n2disk config", "ok", f"adopted: {legacy.describe(ext)} records outside the installer; "
            "its configuration is kept as it is")
    for status, name, detail, hint in legacy.compatibility(ext, a):
        res.add(name, status, detail, hint)
    ours = f"n2disk@{a['capture_iface']}.service"
    if _unit_state(ctx, ours) == "active":
        res.add("second n2disk", "fail", f"{ours} runs as well: two n2disk on one NIC and buffer",
                f"stop the one that should not record (systemctl disable --now {ours}, if {ext['unit'] or 'the other'} "
                "is the licensed one)")
    if ext["unit"]:
        state = _unit_state(ctx, ext["unit"])
        if state == "active":
            res.add("n2disk service", "ok", f"{ext['unit']}: {state}")
        else:
            # Not started here: the installer never starts or restarts an n2disk it did not set up.
            licensed = ctx.extra.get("licensed")
            if licensed is None:
                licensed = _n2disk_info(ctx)["licensed"]
            start = f"systemctl reset-failed {ext['unit']} && systemctl restart {ext['unit']}"
            if licensed:
                res.add("n2disk service", "fail", f"{ext['unit']}: {state}, not recording; the licence is valid",
                        f"start it: {start}; then journalctl -u {ext['unit']} -n 50")
            else:
                res.add("n2disk service", "fail", f"{ext['unit']}: {state}, not recording: no valid n2disk licence",
                        f"install the licence for SystemID {ctx.extra.get('system_id') or '(n2disk --show-system-id)'} "
                        f"(sudo sycope-licence, or install.sh --licence n2disk.license), then {start}")
        show = ctx.r.probe(["systemctl", "show", "-p", "Restart", "-p", "RestartUSec", "-p", "StartLimitBurst",
                            "-p", "StartLimitIntervalUSec", ext["unit"]])[1]
        props = dict(line.split("=", 1) for line in show.splitlines() if "=" in line)
        if legacy.restarts_forever(props):
            res.add("n2disk restarts", "warn", f"{ext['unit']} restarts every {props.get('RestartUSec')} and its "
                    "start limit never trips", "an invalid licence then floods the journal (1.5M restarts at the first "
                    "customer): StartLimitIntervalSec=600, StartLimitBurst=5, RestartSec=30 in a drop-in")
        else:
            res.add("n2disk restarts", "ok", f"bounded (Restart={props.get('Restart')}, RestartSec="
                    f"{props.get('RestartUSec')}, {props.get('StartLimitBurst')} in {props.get('StartLimitIntervalUSec')})")
    return res


def step_n2disk_config(ctx: Ctx, apply: bool) -> Result:
    res, a = Result(), ctx.a
    iface = a["capture_iface"]
    ext = external_n2disk(ctx)
    if ext:
        return _external_n2disk_report(ctx, ext)
    path = f"{N2DISK_CONF_DIR}/n2disk-{iface}.conf"
    want = n2disk_conf(a)
    changed = False  # the config file content was rewritten in this run
    have = _read(path) if os.path.exists(path) else None
    managed = have is not None and have.startswith(MARKER)
    if have is None or (managed and have != want):
        if not apply:
            return res.add("n2disk config", "warn", f"{path} " + ("missing" if have is None else "differs from the answers"))
        if ctx.extra.get("capture_nic_is_management"):
            return res.add("n2disk config", "fail", f"not written: {iface} is the management NIC",
                           "use another interface for capture")
        if have is not None and not ctx.dry:
            ctx.r.run(["cp", "-a", path, _bak_name(path, have)])
        ctx.r.write(path, want)
        changed = not ctx.dry
        res.add("n2disk config", "skip" if ctx.dry else "ok", f"{'would write' if ctx.dry else 'wrote'} {path}")
        have, managed = want, True
    elif not managed:
        res.add("n2disk config", "warn", f"{path} was edited by hand: kept",
                f"make sure it has --max-file-duration={a['chunk_seconds']} (= SR_CHUNK_SECONDS), --index and "
                "--chunk-len=4096 (small chunks lose packets at a few Gbit/s)")
    else:
        res.add("n2disk config", "ok", path)
    m = re.search(r"--packet-slicing=(\d)", have or "")
    if m:
        res.add("packet slicing", "ok" if m.group(1) == "4" else "warn",
                f"only the headers up to L{m.group(1)} are recorded: the PCAPs have no payload",
                "" if m.group(1) == "4" else "below L4 the recorder cannot filter by port (L3) or by IP (L2)")
    m = re.search(r"--filter=(.+)", have or "")
    if m:
        res.add("capture filter", "warn", f"only matching traffic is recorded: {m.group(1).strip()}",
                "everything else never reaches the rolling buffer and can never be extracted")
    m = re.search(r"--max-file-duration=(\d+)", have or "")
    if m and int(m.group(1)) != int(a["chunk_seconds"]):
        res.add("chunk length", "fail", f"n2disk rotates every {m.group(1)} s, the recorder waits {a['chunk_seconds']} s",
                "they must be equal: jobs would run before the file is closed")
    licensed = ctx.extra.get("licensed")
    if licensed is None:
        licensed = _n2disk_info(ctx)["licensed"]
    unit = f"n2disk@{iface}.service"
    if licensed and apply:
        if _unit_state(ctx, unit) != "active":
            ctx.r.run(["systemctl", "enable", "--now", unit])  # starts with the config as it is now
            if not ctx.dry:
                time.sleep(4)
        elif changed:
            # n2disk reads its config at start: without this it would keep running the old one.
            ctx.r.run(["systemctl", "restart", unit])
            time.sleep(4)
            res.add("n2disk restart", "ok", "n2disk restarted to apply the new configuration; the rolling buffer files are kept")
    state = _unit_state(ctx, unit)
    if licensed:
        res.add("n2disk service", "ok" if state == "active" else ("skip" if ctx.dry else "fail"),
                state, "" if state == "active" else f"journalctl -u n2disk@{iface}")
    else:
        res.add("n2disk service", "warn", "not started: no valid licence", "install the licence, then run this installer again")
    return res


# ---- 4a. Tuning -------------------------------------------------------------------------------
def step_tuning(ctx: Ctx, apply: bool) -> Result:
    """NIC offloads and ring, sysctl, and the limits/priority drop-ins (recorder_install/tuning.py)."""
    from . import tuning as tu

    res, a = Result(), ctx.a
    iface = a["capture_iface"]
    if apply and ctx.extra.get("capture_nic_is_management"):
        return res.add("tuning", "fail", f"not applied: {iface} is the management NIC", "use another interface for capture")
    ext = external_n2disk(ctx)
    if ext:
        # The NIC settings (ring size, offloads) reset the link on many drivers: a gap in a capture that is not ours.
        apply = False
        res.add("tuning", "ok", f"not applied: n2disk runs as {legacy.describe(ext)}, outside the installer; "
                "the checks below are information only")
    files = {f"{SYSTEMD_DIR}/{tu.TUNE_UNIT_NAME}": tu.TUNE_UNIT, tu.SYSCTL_PATH: tu.SYSCTL,
             tu.IRQ_SPREAD_PATH: tu.IRQ_SPREAD}
    if records(a):
        files[f"{SYSTEMD_DIR}/n2disk@.service.d/20-tuning.conf"] = tu.DROPIN_N2DISK
    if probes(a):
        files[f"{SYSTEMD_DIR}/nprobe@.service.d/20-tuning.conf"] = tu.DROPIN_NPROBE
    stale = [p for p, text in files.items() if not os.path.exists(p) or _read(p) != text]
    unit = f"recorder-capture-tune@{iface}.service"
    if apply and stale:
        for p in stale:
            ctx.r.write(p, files[p], 0o755 if p == tu.IRQ_SPREAD_PATH else None)
        ctx.r.run(["systemctl", "daemon-reload"])
        ctx.r.run(["sysctl", "-q", "-p", tu.SYSCTL_PATH])
        # The drop-ins take effect at the next start of n2disk/nProbe: they are not restarted for it here.
    if apply and (stale or _unit_state(ctx, unit) != "active"):
        ctx.r.run(["systemctl", "enable", f"{unit}"])
        ctx.r.run(["systemctl", "restart", f"{unit}"])  # oneshot: run the ethtool lines now
        if ctx.dry:
            return _would(res, "tuning", f"write {len(stale)} file(s) and apply the NIC settings to {iface}")
        stale = [p for p, text in files.items() if not os.path.exists(p) or _read(p) != text]
    res.add("tuning files", "ok" if not stale else "warn",
            f"{len(files)} in place" if not stale else "missing or different: " + ", ".join(stale),
            "" if not stale else "run the installer to write them")
    on = tu.offloads_on(ctx.r.probe(["ethtool", "-k", iface])[1])
    res.add("NIC offloads", "ok" if not on else "warn", "packet merging off" if not on else "still on: " + ", ".join(on),
            "" if not on else f"systemctl status {unit}; the NIC or its driver may not allow switching them off")
    mx, cur = tu.rx_ring(ctx.r.probe(["ethtool", "-g", iface])[1])
    if cur is not None:
        want = min(4096, mx or 4096)
        res.add("NIC RX ring", "ok" if cur >= want else "warn", f"{cur} (maximum {mx})",
                "" if cur >= want else f"ethtool -G {iface} rx {want}")
    cpus = ctx.r.probe(["nproc"])[1].strip()
    irqs = ctx.r.probe(["sh", "-c", tu.IRQ_PROBE, "sh", iface])[1]
    if cpus.isdigit() and irqs.strip():
        crowded = tu.irq_crowding(irqs, int(cpus))
        res.add("NIC interrupts", "ok" if not crowded else "warn",
                f"spread over the CPUs ({len(irqs.strip().splitlines())} interrupts, {cpus} CPUs)" if not crowded
                else "more than one on CPU " + ", ".join(crowded) + " while another CPU has none",
                "" if not crowded else f"systemctl restart {unit}")
    if _unit_state(ctx, "irqbalance.service") == "active":
        res.add("irqbalance", "warn", "running: it moves the capture NIC's interrupts back together",
                "systemctl disable --now irqbalance")
    return res


# ---- 4c. Licence inbox ------------------------------------------------------------------------
TUI_PATH = "/usr/local/sbin/sycope-licence"
# The copy of tools/install/ that the inbox unit and the menu run as root. Never the directory the release was
# unpacked in: an ordinary user owns that one (a home directory, /tmp) and could replace install.sh there.
INSTALLER_HOME = "/usr/local/lib/sycope-recorder-installer"
INSTALLER_SH = f"{INSTALLER_HOME}/tools/install/install.sh"
# rsync options for code that root runs later: root's alone (no group/other write; no setuid/setgid a user planted)
ROOT_OWNED = ("--chown=root:root", "--chmod=go-w,ug-s")


def _changeable(s: os.stat_result) -> bool:
    """Someone other than root can change this entry (or run it as its owner): not root's, group/other-writable,
    or a setuid/setgid file. A symlink's own mode means nothing: only its owner counts."""
    if stat.S_ISLNK(s.st_mode):
        return s.st_uid != 0
    return s.st_uid != 0 or bool(s.st_mode & 0o022) or (stat.S_ISREG(s.st_mode) and bool(s.st_mode & 0o6000))


def root_own(top: str, src: str, skip: Callable[[str], bool], fix: bool) -> tuple[list[str], list[str]]:
    """The entries of `top` (itself included) that are also in the release `src`, minus `skip(rel)`, that someone
    other than root can change. Returns (those, the ones `fix` could not repair).

    With `fix`, each becomes root:root without group/other write and setuid/setgid, top-down through directory
    descriptors and O_NOFOLLOW: a directory is root's before anything in it is touched, so nothing can be swapped
    in between, and a symlink only gets its own owner changed. Whatever is not in the release (.env, credentials,
    profiles, an own certificate, data, PCAP directories) is never walked into or changed.
    """
    bad: list[str] = []
    failed: list[str] = []
    top = os.path.realpath(top)

    def one(rel: str, s: os.stat_result, opener) -> None:
        if not _changeable(s):
            return
        bad.append(rel)
        if not fix:
            return
        try:
            if stat.S_ISLNK(s.st_mode):
                opener(None)
                return
            if stat.S_ISREG(s.st_mode) and s.st_nlink > 1:
                raise OSError("a hard link: change it by hand")
            fd = opener(os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_DIRECTORY if stat.S_ISDIR(s.st_mode) else 0))
            try:
                now = os.fstat(fd)
                if (now.st_dev, now.st_ino) != (s.st_dev, s.st_ino):
                    raise OSError("replaced while it was looked at")
                os.fchown(fd, 0, 0)
                os.fchmod(fd, stat.S_IMODE(now.st_mode) & ~0o6022)
            finally:
                if fd is not None:
                    os.close(fd)
        except OSError as exc:
            failed.append(f"{rel} ({exc.strerror or exc})")

    for dirpath, dirnames, filenames, dfd in os.fwalk(top, follow_symlinks=False):
        here = os.path.relpath(dirpath, top)
        if here == ".":
            one(".", os.fstat(dfd), lambda flags, d=dfd: os.dup(d))
        walk = []
        for name in dirnames + filenames:
            rel = os.path.normpath(os.path.join(here, name))
            if skip(rel) or not os.path.lexists(os.path.join(src, rel)):
                continue
            try:
                s = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            except OSError:
                continue
            one(rel, s, lambda flags, n=name, d=dfd: (os.chown(n, 0, 0, dir_fd=d, follow_symlinks=False) if flags is None
                                                      else os.open(n, flags, dir_fd=d)))
            if stat.S_ISDIR(s.st_mode):
                walk.append(name)
        dirnames[:] = [n for n in dirnames if n in walk]
    return bad, failed


def unsafe_parents(path: str) -> list[str]:
    """The directories above `path` (up to /) that a user other than root can change: not root's, or writable
    by a group other than root or by others without the sticky bit. Only reported: they are the host's."""
    out = []
    p = os.path.realpath(path)
    while p != "/":
        p = os.path.dirname(p)
        try:
            s = os.stat(p)
        except OSError:
            continue
        open_ = (s.st_mode & 0o020 and s.st_gid != 0) or (s.st_mode & 0o002 and not s.st_mode & stat.S_ISVTX)
        if s.st_uid != 0 or open_:
            out.append(f"{p} (uid {s.st_uid}, gid {s.st_gid}, mode {stat.S_IMODE(s.st_mode):o})")
    return out


def root_owned_item(ctx: Ctx, res: Result, name: str, top: str, src: str, skip: Callable[[str], bool],
                    apply: bool) -> None:
    """Report (and with apply repair) that what root runs from `top` is root's alone: an install made before
    the copy set the owner still has the files of the user who unpacked the release."""
    if not os.path.isdir(top):
        return
    bad, failed = root_own(top, src, skip, False)
    if bad and apply and not ctx.dry and not getattr(ctx.r, "read_only", False):
        say(ctx, f"making the code in {top} root's (root:root, no group/other write): {len(bad)} entries")
        failed = root_own(top, src, skip, True)[1]
        bad = root_own(top, src, skip, False)[0]
    shown = ", ".join(bad[:3]) + (f" and {len(bad) - 3} more" if len(bad) > 3 else "")
    if bad and apply and ctx.dry:
        _would(res, name, f"make {len(bad)} entries in {top} root:root without group/other write ({shown})")
    elif bad:
        res.add(name, "fail" if apply else "warn",
                f"{len(bad)} entries in {top} can be changed by a user other than root: {shown}"
                + (f"; not repaired: {', '.join(failed[:3])}" if failed else ""),
                "the installer makes them root:root without group/other write when it runs" if not apply
                else f"chown -R root:root {top}/ and chmod -R go-w,ug-s it (leave .env and credentials at 0600)")
    else:
        res.add(name, "ok", f"the code in {top} is root's alone")
    parents = unsafe_parents(top)
    if parents:
        res.add(f"{name} (directories above)", "warn", "a user other than root can change " + "; ".join(parents),
                "chown root and chmod go-w these directories, or choose a directory under one that is root's")


def _installer_copy_stale(ctx: Ctx, src: str) -> bool:
    """INSTALLER_HOME does not hold exactly `src` (tools/install of this release), root's alone."""
    rc, out = ctx.r.probe(["rsync", "-a", "--dry-run", "--itemize-changes", "--delete", *ROOT_OWNED,
                           "--exclude", "__pycache__", f"{src}/", f"{INSTALLER_HOME}/tools/install/"])
    if rc != 0 or out.strip():
        return True
    for d in (INSTALLER_HOME, os.path.join(INSTALLER_HOME, "tools")):
        try:
            if _changeable(os.lstat(d)) or not os.path.isdir(d) or os.path.islink(d):
                return True
        except OSError:
            return True
    return False


def step_licence_inbox(ctx: Ctx, apply: bool) -> Result:
    """The ways to bring a licence in later: the inbox with its path unit, and the console menu (licence_inbox.py).

    Both run the root-owned copy of the installer in INSTALLER_HOME, refreshed here from this release; units of
    an earlier release that ran install.sh from the unpacked release are rewritten (their text differs)."""
    from . import licence_inbox as li

    res = Result()
    src = os.path.join(ctx.repo, "tools", "install")
    install_sh = INSTALLER_SH
    with open(os.path.join(src, "sycope-licence")) as fh:
        tui = fh.read().replace(
            "@INSTALL_SH@", install_sh)
    files = {f"{SYSTEMD_DIR}/{li.PATH_UNIT_NAME}": li.PATH_UNIT,
             f"{SYSTEMD_DIR}/{li.SERVICE_UNIT_NAME}": li.service_unit(install_sh), TUI_PATH: tui}
    stale = [p for p, text in files.items() if not os.path.exists(p) or _read(p) != text]
    copy_stale = _installer_copy_stale(ctx, src)
    group = ctx.r.probe(["getent", "group", li.INBOX_GROUP])[0] == 0
    active = _unit_state(ctx, li.PATH_UNIT_NAME) == "active"
    if apply and (stale or copy_stale or not group or not active):
        if not group:
            ctx.r.run(["groupadd", "--system", li.INBOX_GROUP])
        if copy_stale:  # before the units and the menu that run it
            ctx.r.run(["install", "-d", "-m", "0755", "-o", "root", "-g", "root", INSTALLER_HOME,
                       os.path.join(INSTALLER_HOME, "tools")])
            ctx.r.run(["rsync", "-a", "--delete", *ROOT_OWNED, "--exclude", "__pycache__",
                       f"{src}/", f"{INSTALLER_HOME}/tools/install/"])
        for p in stale:
            ctx.r.write(p, files[p], 0o755 if p == TUI_PATH else None)
        ctx.r.run(["install", "-d", "-m", "2770", "-o", "root", "-g", li.INBOX_GROUP, li.INBOX])
        ctx.r.run(["systemctl", "daemon-reload"])
        ctx.r.run(["systemctl", "enable", "--now", li.PATH_UNIT_NAME])
        if ctx.dry:
            return _would(res, "licence inbox", f"set up {li.INBOX}, the path unit and {TUI_PATH}")
        stale = [p for p, text in files.items() if not os.path.exists(p) or _read(p) != text]
        copy_stale = _installer_copy_stale(ctx, src)
        group = ctx.r.probe(["getent", "group", li.INBOX_GROUP])[0] == 0
        active = _unit_state(ctx, li.PATH_UNIT_NAME) == "active"
    good = not stale and not copy_stale and group and active
    res.add("licence inbox", "ok" if good else ("fail" if apply else "warn"),
            f"{li.INBOX} (group {li.INBOX_GROUP}), {li.PATH_UNIT_NAME} {'active' if active else 'not active'}",
            "" if good else f"systemctl status {li.PATH_UNIT_NAME}")
    res.add("licence menu", "ok" if TUI_PATH not in stale else "warn", f"sudo {os.path.basename(TUI_PATH)}")
    res.add("installer copy", "ok" if not copy_stale else ("fail" if apply else "warn"),
            f"{INSTALLER_HOME}/tools/install (root's; what the inbox unit and the menu run)"
            if not copy_stale else f"{INSTALLER_HOME}/tools/install is missing, out of date or not root's alone",
            "" if not copy_stale else "the installer copies tools/install there when it runs")
    parents = unsafe_parents(INSTALLER_HOME)
    if parents:
        res.add("installer copy (directories above)", "warn", "a user other than root can change " + "; ".join(parents),
                "chown root and chmod go-w these directories")
    return res


# ---- 4b. nProbe -------------------------------------------------------------------------------
def step_nprobe(ctx: Ctx, apply: bool) -> Result:
    res = Result()
    if not _pkg(ctx, "nprobe"):
        if not apply:
            return res.add("nProbe", "warn", "not installed")
        if ctx.dry:
            _apt(ctx, "install", "-y", "nprobe")
            return _would(res, "nProbe", "install nprobe")
        moves = _apt_moves(ctx, "nprobe")
        if moves:
            return res.add("nProbe", "fail", *_moves_text(moves))
        _apt(ctx, "install", "-y", "-qq", "nprobe")
    if not _pkg(ctx, "nprobe"):
        return res.add("nProbe", "fail", "could not be installed", "check the ntop repository above")
    res.add("nProbe", "ok", ctx.r.probe(["dpkg-query", "-W", "-f=${Version}", "nprobe"])[1])
    np_.install_licence(ctx, res, apply)
    info = np_.nprobe_info(ctx.r)
    ctx.extra["nprobe_licensed"], ctx.extra["nprobe_system_id"] = info["licensed"], info["system_id"]
    res.add("nProbe SystemID", "ok", info["system_id"] or "unknown",
            "nProbe licences are issued on this value (it is not n2disk's SystemID)")
    if info["state"] == "unknown":
        res.add("nProbe licence", "warn", "could not be determined (nprobe --version gave no answer)",
                "run nprobe --version by hand; the licence file was not touched")
    else:
        res.add("nProbe licence", "ok" if info["licensed"] else "warn", "valid" if info["licensed"] else "missing or invalid",
                "" if info["licensed"] else f"install {np_.NPROBE_LICENCE} for SystemID {info['system_id']}; "
                "nProbe stays off until then (without a licence it runs only as a time-limited demo)")
    return res


def step_nprobe_config(ctx: Ctx, apply: bool) -> Result:
    res, a = Result(), ctx.a
    if apply and ctx.extra.get("capture_nic_is_management"):
        return res.add("nProbe config", "fail", f"not written: {a['capture_iface']} is the management NIC",
                       "use another interface for capture")
    names = np_.instance_names(a)
    dropin = f"{SYSTEMD_DIR}/nprobe@.service.d/10-recorder.conf"
    if not os.path.exists(dropin) or _read(dropin) != np_.DROPIN:
        if apply:
            ctx.r.write(dropin, np_.DROPIN)
            ctx.r.run(["systemctl", "daemon-reload"])
        else:
            res.add("nProbe unit drop-in", "warn", f"{dropin} missing or different")
    changed: set[str] = set()
    for i, name in enumerate(names, 1):
        path, want = f"{np_.NPROBE_CONF_DIR}/nprobe-{name}.conf", np_.conf(a, i)
        have = _read(path) if os.path.exists(path) else None
        if have is not None and not have.startswith(np_.MARKER):
            res.add(f"nProbe config {name}", "warn", f"{path} was edited by hand: kept",
                    f"make sure it exports IPFIX (-V 10) with %L7_PROTO to {np_.collector(a)}")
            continue
        if have == want:
            res.add(f"nProbe config {name}", "ok", path)
            continue
        if not apply:
            res.add(f"nProbe config {name}", "warn", f"{path} " + ("missing" if have is None else "differs from the answers"))
            continue
        if have is not None and not ctx.dry:
            ctx.r.run(["cp", "-a", path, _bak_name(path, have)])
        ctx.r.write(path, want)
        changed.add(name)
        res.add(f"nProbe config {name}", "skip" if ctx.dry else "ok", f"{'would write' if ctx.dry else 'wrote'} {path}")
    # Instances of an earlier, larger count: ours (the marker), so stop them; the file stays as a record.
    extra = [n for n in np_.managed_confs() if n not in names and re.fullmatch(rf"{re.escape(a['capture_iface'])}(-\d+)?", n)]
    for name in extra:
        if apply:
            ctx.r.run(["systemctl", "disable", "--now", f"nprobe@{name}.service"])
        res.add(f"nProbe {name}", "ok" if apply else "warn",
                "stopped: not part of the instance count any more" if apply else "runs but is not part of the instance count")
    licensed = ctx.extra.get("nprobe_licensed")
    if licensed is None:
        licensed = np_.nprobe_info(ctx.r)["licensed"]
    for name in names:
        unit = f"nprobe@{name}.service"
        if licensed and apply:
            if _unit_state(ctx, unit) != "active":
                ctx.r.run(["systemctl", "enable", "--now", unit])
            elif name in changed:
                ctx.r.run(["systemctl", "restart", unit])  # nProbe reads its config at start
        if not licensed:
            res.add(f"nProbe service {name}", "warn", "not started: no valid nProbe licence",
                    "install the licence, then run this installer again")
            continue
        if apply and not ctx.dry:
            time.sleep(3)
        state = _unit_state(ctx, unit)
        res.add(f"nProbe service {name}", "ok" if state == "active" else ("skip" if ctx.dry else "fail" if apply else "warn"),
                f"{state}, IPFIX to {np_.collector(a)}", "" if state == "active" else f"journalctl -u {unit}")
    return res


# ---- 5. Docker --------------------------------------------------------------------------------
def step_docker(ctx: Ctx, apply: bool) -> Result:
    res = Result()
    have = ctx.r.probe(["docker", "compose", "version"])[0] == 0
    if not have and apply:
        os_rel = ctx.host.os_release()
        distro, codename = os_rel.get("ID", ""), os_rel.get("VERSION_CODENAME", "")
        if ctx.dry:
            return _would(res, "Docker", "add the Docker apt repository and install docker-ce + compose plugin")
        ctx.r.run(["install", "-m", "0755", "-d", "/etc/apt/keyrings"])
        ctx.r.run(["curl", "-fsSL", f"https://download.docker.com/linux/{distro}/gpg", "-o", "/etc/apt/keyrings/docker.asc"])
        ctx.r.write("/etc/apt/sources.list.d/docker.list",
                    f"deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/{distro} {codename} stable\n")
        _apt(ctx, "update", "-qq")
        _apt(ctx, "install", "-y", "-qq", "docker-ce", "docker-ce-cli", "containerd.io",
             "docker-buildx-plugin", "docker-compose-plugin")
        have = ctx.r.probe(["docker", "compose", "version"])[0] == 0
    if have:
        return res.add("Docker", "ok", ctx.r.probe(["docker", "--version"])[1])
    return res.add("Docker", "fail" if apply else "warn", "not installed", "install docker-ce and the compose plugin")


# ---- 6. Profiles ------------------------------------------------------------------------------
def step_profiles(ctx: Ctx, apply: bool) -> Result:
    res, a = Result(), ctx.a
    out = os.path.join(a["install_dir"], "profiles", "profiles.json")
    macros = os.path.join(a["install_dir"], "profiles", "macros.yaml")
    have = os.path.exists(out) and os.path.getsize(out) > 2
    if not ctx.secrets.get("sycope_pass") or not a.get("sycope_url"):
        return res.add("profiles", "skip" if not have else "ok",
                       "no Sycope credentials: " + ("keeping the existing profiles" if have else "alerts use the default window/filter"),
                       "" if have else "give the Sycope URL, user and password and run again")
    if apply and not ctx.dry:
        ctx.r.run(["mkdir", "-p", os.path.dirname(out)])
        rc, text = ctx.r.run(
            ["python3", os.path.join(ctx.repo, "tools", "profiles", "gen_profiles.py"), "--macros",
             "-o", out, "--macros-out", macros],
            env={"SYCOPE_URL": a["sycope_url"], "SYCOPE_USER": a["sycope_user"], "SYCOPE_PASS": ctx.secrets["sycope_pass"]})
        have = rc == 0 and os.path.exists(out)
        if rc != 0:
            res.add("profile generation", "fail", text.strip().splitlines()[-1] if text.strip() else "failed",
                    "alerts use the default window/filter until this works")
    elif apply and ctx.dry:
        return _would(res, "profiles", "generate them from Sycope")
    if have:
        try:
            with open(out) as fh:
                data = json.load(fh)  # {"profiles": [...]}, or the older bare list
            n = len(data["profiles"] if isinstance(data, dict) else data)
        except (OSError, ValueError, KeyError, TypeError):
            n = 0
        res.add("profiles", "ok" if n else "warn", f"{n} extraction profiles in {out}")
    elif not res.items:
        res.add("profiles", "warn", "not generated yet")
    return res


# ---- 7. The stack -----------------------------------------------------------------------------
def read_env(path: str) -> dict[str, str]:
    env: dict[str, str] = {}
    try:
        with open(path) as fh:
            for line in fh:
                if "=" in line and not line.lstrip().startswith("#"):
                    k, v = line.rstrip("\n").split("=", 1)
                    env[k] = v
    except OSError:
        pass
    return env


def update_env(ctx: Ctx, path: str, updates: dict[str, str], remove: tuple[str, ...] = ()) -> bool:
    """Set keys in an .env file and drop the keys in `remove`, keeping every other byte. True if anything changed.

    Lines are handled with their own line endings, so comments, blank lines, secrets and keys the operator
    added come back exactly as they were; a commented-out `#KEY=` is not the key. A removed key is removed
    wherever it appears.
    """
    text = _read(path, newline="") if os.path.exists(path) else ""
    lines = text.splitlines(keepends=True)
    changed, seen, out = False, set(), []
    for line in lines:
        body = line.rstrip("\r\n")
        ending = line[len(body):]
        k = body.split("=", 1)[0]
        if k in remove and "=" in body:
            changed = True
            continue
        if k in updates and "=" in body:
            seen.add(k)
            if body != f"{k}={updates[k]}":
                line, changed = f"{k}={updates[k]}{ending or chr(10)}", True
        out.append(line)
    for k, v in updates.items():
        if k not in seen:
            if out and not out[-1].endswith(("\n", "\r")):
                out[-1] += "\n"
            out.append(f"{k}={v}\n")
            changed = True
    if changed:
        if out and not out[-1].endswith(("\n", "\r")):
            out[-1] += "\n"
        ctx.r.write(path, "".join(out), 0o600)
    return changed


COMPOSE_FILES = "compose.yaml:compose.ntop.yaml"  # COMPOSE_FILE in .env: the files _compose passes with -f


def _compose(ctx: Ctx, *args: str) -> str:
    d = ctx.a["install_dir"]
    return (f"cd {shlex.quote(d)} && docker compose --env-file .env -f compose.yaml -f compose.ntop.yaml "
            + " ".join(shlex.quote(x) for x in args))


def https_port(a: dict) -> str:
    return str(a.get("https_port") or "443")


def http_port(a: dict) -> str:
    return str(a.get("http_port") or "80")


def base(a: dict) -> str:
    """host[:port] the recorder is reached at directly (links, the installer's own checks, the Passthrough)."""
    return a["public_host"] + ("" if https_port(a) == "443" else f":{https_port(a)}")


def managed_env(ctx: Ctx) -> dict[str, str]:
    a = ctx.a
    env = {"SR_PUBLIC_HOST": a["public_host"], "TZ": ctx.host.timezone(),
           "SR_CHUNK_SECONDS": str(a["chunk_seconds"]), "SR_ROLLING_DIR": a["rolling_dir"],
           "SR_ALERTS_DIR": a["alerts_dir"], "ALLOWED_IPS": a["allowed_ips"]}
    # SR_LOG_FORMAT is not managed: text is the default, and an operator's json (log collector) must survive a rerun.
    if a.get("passthrough_name") and a.get("sycope_url"):
        host = re.sub(r"^https?://", "", a["sycope_url"]).rstrip("/")
        env["SR_DOWNLOAD_URL_BASE"] = f"{host}/npm/api/v1/passthrough/{a['passthrough_name']}"
    elif https_port(a) != "443":
        env["SR_DOWNLOAD_URL_BASE"] = base(a)  # links carry the port; SR_PUBLIC_HOST stays the bare TLS name
    env["SR_HTTPS_PORT"], env["SR_HTTP_PORT"] = https_port(a), http_port(a)
    if os.path.exists(os.path.join(a["install_dir"], "profiles", "profiles.json")):
        env["SR_PROFILES_FILE"] = "/profiles/profiles.json"
    # The allowed networks guard all of the recorder, not only /downloads/*: this replaces ALLOWED_IPS above and
    # adds ALLOWED_UI_IPS and ALLOWED_EXTRACT_IPS (except one set by hand). What it found goes to the stack step.
    access, ctx.extra["access_items"] = access_env(ctx, read_env(os.path.join(a["install_dir"], ".env")))
    env.update(access)
    # A plain `docker compose ...` in the install directory then uses the same files as _compose (an explicit
    # -f overrides it). compose reads it from .env; it is not passed into the containers.
    env["COMPOSE_FILE"] = COMPOSE_FILES
    return env


# ---- who may reach the recorder ----------------------------------------------------------------
# The Caddyfile has three allowlists: ALLOWED_IPS for the legacy /downloads/* files, ALLOWED_UI_IPS for the pages,
# the API and ?download=1, ALLOWED_EXTRACT_IPS for the webhook (any other POST). The installer's one answer
# (allowed_ips) goes into all three, with what must always get in added: Sycope's address (it posts the webhook,
# and through the Passthrough it is the client of every page and download) and this host's own address (the
# installer's checks call https://<public_host> from here). ALLOWED_UI_IPS and ALLOWED_EXTRACT_IPS are newer than
# the installer's .env: a value the operator set by hand (one this installer did not write) is kept.
ACCESS_KEYS = ("ALLOWED_IPS", "ALLOWED_UI_IPS", "ALLOWED_EXTRACT_IPS")
ACCESS_HAND_SET = ("ALLOWED_UI_IPS", "ALLOWED_EXTRACT_IPS")


def resolve(name: str, lookup: Callable = socket.getaddrinfo) -> list[str]:
    """The IPv4 and IPv6 addresses of a host name or IP literal, sorted (IPv4 first); [] when it does not resolve."""
    try:
        infos = lookup(name.strip("[]"), None, 0, socket.SOCK_STREAM)
    except (OSError, UnicodeError, ValueError):
        return []
    found = set()
    for info in infos:
        try:
            found.add(ipaddress.ip_address(str(info[4][0]).split("%", 1)[0]))
        except (ValueError, IndexError):
            continue
    return [str(x) for x in sorted(found, key=lambda x: (x.version, x))]


def uncovered(networks: str, addresses: list[str]) -> list[str]:
    """The addresses that none of `networks` (CIDRs or addresses, separated by spaces) contains, in order, once."""
    nets = []
    for part in networks.split():
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            continue
    out = []
    for addr in addresses:
        ip = ipaddress.ip_address(addr)
        if addr not in out and not any(ip.version == n.version and ip in n for n in nets):
            out.append(addr)
    return out


def access_list(networks: str, addresses: list[str]) -> str:
    """The operator's networks, then each of `addresses` that they do not already cover."""
    return " ".join(networks.split() + uncovered(networks, addresses))


def sycope_hostname(a: dict) -> str:
    """The host name or address of the Sycope URL answer ("" without one)."""
    try:
        return urllib.parse.urlsplit(a.get("sycope_url") or "").hostname or ""
    except ValueError:
        return ""


def access_env(ctx: Ctx, have: dict[str, str]) -> tuple[dict[str, str], list[tuple[str, str, str, str]]]:
    """The allowlist keys for .env, and (status, name, detail, hint) items saying what went into them.

    Sycope's address is resolved now; when its name does not resolve, the addresses resolved for the same name on
    an earlier run are used (and a warning says so), so a DNS hiccup never takes Sycope out of the allowlists.
    """
    a, items, extra = ctx.a, [], []

    def note(status: str, name: str, detail: str, hint: str = "") -> None:
        items.append((status, name, detail, hint))

    shost = sycope_hostname(a)
    if shost:
        addrs, known = resolve(shost), a.get("sycope_addresses") or {}
        if addrs:
            a["sycope_addresses"] = {"host": shost, "addresses": addrs}
            shown = shost if addrs == [shost] else f"{shost} = {' '.join(addrs)}"
            note("ok", "Sycope's address", f"{shown}: allowed for the webhook, the pages and the "
                 "downloads (the Passthrough connects from it)")
        elif known.get("host") == shost and known.get("addresses"):
            addrs = list(known["addresses"])
            note("warn", "Sycope's address", f"{shost} does not resolve on this host now; the address found on an "
                 f"earlier run stays allowed: {' '.join(addrs)}",
                 "check DNS on this host; if Sycope's address changed, run the installer again once it resolves")
        else:
            note("warn", "Sycope's address", f"{shost} does not resolve on this host: its address is not added to the "
                 "allowed networks",
                 "Sycope's webhook and Passthrough are refused (403) unless an answered network contains its address: "
                 "fix DNS and run again, or add Sycope's address to the allowed networks (allowed_ips)")
        extra += addrs
    else:
        note("ok", "Sycope's address", "no Sycope URL given: only the allowed networks get in (they must contain "
             "Sycope's address, or its alerts are refused)")
    mine = ctx.host.addresses()
    own = [ip for ip in resolve(a["public_host"]) if ip in mine and not ipaddress.ip_address(ip).is_loopback]
    if not own:
        note("warn", "this host's address", f"{a['public_host']} is not an address of this host: the installer's own "
             "checks of the recorder (webhook self-test, worker stats) may be refused (403)",
             "answer a public_host that resolves to this host's management address, or add the address these checks "
             "come from to the allowed networks")
    extra += own
    value = access_list(a["allowed_ips"], extra)
    env = {k: value for k in ACCESS_KEYS}
    written = a.setdefault("access_written", {})
    for k in ACCESS_HAND_SET:
        cur = have.get(k)
        if cur is None or cur == value or cur == written.get(k):
            if cur == value:
                written[k] = value
            continue
        del env[k]  # set by hand: the operator's choice stands
        missing = uncovered(cur.strip("'\""), extra)
        note("warn" if missing else "ok", f".env {k}",
             f"kept as set by hand: {cur}" + (f" (it does not contain {' '.join(missing)})" if missing else ""),
             f"remove the line from .env and run the installer again to have it set to: {value}")
    return env, items


# What the stack's rsync excludes (step_stack): the operator's and the stack's own files, never chowned by root_own.
STACK_KEEP = (".git", "old", ".venv", "tests", "__pycache__", ".env", DEPLOYED, "data", "credentials")


def _stack_skip(rel: str) -> bool:
    parts = rel.split("/")
    # an own certificate (the rsync's "P /certs/**"): with the release unpacked in the install directory itself
    # it would otherwise count as part of the release
    in_certs = (parts[0] == "certs" and len(parts) > 1) or (parts[:2] == ["caddy", "certs"] and len(parts) > 2)
    return (any(p in STACK_KEEP for p in parts) or parts[0] == "bundled"
            or (in_certs and parts[-1] not in ("README.md", ".gitkeep"))
            or (len(parts) >= 2 and parts[-2] == "profiles" and parts[-1].endswith((".json", ".yaml"))))


# Files whose content decides what the image and the containers are: a change to any of them is a
# redeploy. Tests, docs and bytecode are not part of the image.
FINGERPRINT_TREES = (("src", ".py"), ("docker", ""), ("caddy", ""))
FINGERPRINT_FILES = ("Dockerfile", "compose.yaml", "compose.ntop.yaml", "gunicorn.conf.py", "pyproject.toml", "uv.lock")


def release_of(repo: str) -> str:
    """The release string of the code in `repo` (`__version__`), "" when it cannot be read."""
    try:
        with open(os.path.join(repo, "src", "sycope_recorder", "__init__.py")) as fh:
            text = fh.read()
    except OSError:
        return ""
    m = re.search(r'^__version__\s*=\s*"([^"]*)"', text, re.M)
    return m.group(1) if m else ""


def code_fingerprint(repo: str) -> str:
    """sha256 over the sorted relative paths and contents of everything the deployed stack is built from.

    The release is part of it, so a release bump is a new fingerprint even if the files were copied
    unchanged. Files that are not inputs of the image (tests, docs, __pycache__) do not count.
    """
    paths: list[str] = []
    for tree, suffix in FINGERPRINT_TREES:
        root = os.path.join(repo, tree)
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(x for x in dirnames if x != "__pycache__")
            paths += [os.path.relpath(os.path.join(dirpath, f), repo) for f in filenames if f.endswith(suffix)]
    paths += [f for f in FINGERPRINT_FILES if os.path.isfile(os.path.join(repo, f))]
    h = hashlib.sha256()
    h.update(f"release\0{release_of(repo)}\0".encode())
    for rel in sorted(set(paths)):
        with open(os.path.join(repo, rel), "rb") as fh:
            data = fh.read()
        h.update(f"{rel}\0{len(data)}\0".encode())
        h.update(data)
    return h.hexdigest()


def read_deployed(install_dir: str) -> dict:
    """The `.deployed` record of the install directory ({} when missing or unreadable)."""
    try:
        with open(os.path.join(install_dir, DEPLOYED)) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


# What the running (previous) release still has in its queue. Read-only on purpose: the old database is
# opened with mode=ro and nothing in this script writes; any failure is "unknown", never an abort.
QUEUE_SCRIPT = (
    "import json,sqlite3\n"
    "c=sqlite3.connect('file:/var/lib/sycope-recorder/jobs.db?mode=ro',uri=True)\n"
    "w=\"FROM jobs WHERE state IN ('queued','running')\"\n"
    "n=c.execute('SELECT COUNT(*) '+w).fetchone()[0]\n"
    "r=c.execute('SELECT id,alert_id,state,window_begin,window_end '+w+' ORDER BY created LIMIT 50').fetchall()\n"
    "print(json.dumps({'total':n,'jobs':r}))\n"
)
ABANDONED = "abandoned jobs of the previous release"


def parse_abandoned_jobs(rc: int, out: str) -> dict | None:
    """{"total": n, "jobs": [[id, alert_id, state, begin, end], ...]} from the queue query, None when unknown."""
    if rc != 0:
        return None
    for line in reversed(out.strip().splitlines()):
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except ValueError:
            return None
        if isinstance(data, dict) and isinstance(data.get("total"), int) and isinstance(data.get("jobs"), list):
            return data
        return None
    return None


def abandoned_jobs_item(ctx: Ctx, res: Result) -> None:
    """Tell what the previous release leaves in its queue, before the stack is replaced (read-only)."""
    rc, out = ctx.r.probe(_compose(ctx, "exec", "-T", "api", "python", "-c", QUEUE_SCRIPT), timeout=60)
    found = parse_abandoned_jobs(rc, out)
    if found is None:
        res.add(ABANDONED, "warn", "the queue of the previous release could not be read (no container or no database)",
                "jobs of the previous release are not continued by 0.4; extracted PCAPs are kept and the old database is "
                "moved aside on the first start (jobs.db.0.3-<time> in the state volume)")
    elif found["total"] == 0:
        res.add(ABANDONED, "ok", "queue of the previous release was empty")
    else:
        shown = found["jobs"][:50]
        listing = "; ".join(f"{j[0]} ({j[2]}, {j[3]} to {j[4]})" for j in shown)
        more = f"; and {found['total'] - len(shown)} more" if found["total"] > len(shown) else ""
        res.add(ABANDONED, "warn", f"{found['total']} job(s) still queued or running will not be continued: {listing}{more}",
                "PCAPs already extracted are kept; the old database is moved aside by 0.4 on first start "
                "(jobs.db.0.3-<time> in the state volume); trigger the alerts again if those PCAPs are still needed")


def wait_healthy(ctx: Ctx, timeout: float = HEALTH_TIMEOUT, interval: float = 2.0) -> tuple[bool, str]:
    """Poll /healthz until it answers 200 or `timeout` seconds have passed (replaces a fixed sleep)."""
    host, start, tries, last = base(ctx.a), time.monotonic(), 0, None
    while True:
        tries += 1
        last = healthz_status(host)
        waited = time.monotonic() - start
        if last == 200:
            return True, f"https://{host}/healthz answered 200 after {waited:.0f} s ({tries} tries)"
        if waited + interval > timeout:
            return False, (f"https://{host}/healthz did not answer 200 within {timeout:.0f} s "
                           f"(last: {'no answer' if last is None else last})")
        time.sleep(interval)


def _project_name(d: str) -> str:
    """compose's default project name for a directory (its base name, lower case, [a-z0-9_-])."""
    return re.sub(r"[^a-z0-9_-]", "", os.path.basename(os.path.normpath(d)).lower())


def _stop_legacy_stack(ctx: Ctx, res: Result, d: str, files: list[str]) -> bool:
    """Back up and stop a stack this installer did not deploy, with its own compose files (before they are replaced).

    Nothing of it is deleted here: its configuration goes to STACK_BACKUP_ROOT first, the containers are stopped
    with `down` (never -v: volumes and the PCAP directories stay). False when it could not be stopped.
    """
    backup = os.path.join(STACK_BACKUP_ROOT, time.strftime("%Y%m%d-%H%M%S"))
    keep = [f for f in (".env", *files, "caddy", "certs", "profiles", "credentials")
            if os.path.lexists(os.path.join(d, f))]
    ctx.r.run(["mkdir", "-p", "-m", "0700", backup])
    for f in keep:
        ctx.r.run(["cp", "-a", os.path.join(d, f), backup + "/"])
    res.add("earlier stack", "ok", f"not deployed by this installer ({', '.join(files)}); "
            f"{', '.join(keep)} copied to {backup}")
    env = "--env-file .env " if os.path.exists(os.path.join(d, ".env")) else ""
    rc, out = ctx.r.run(f"cd {shlex.quote(d)} && docker compose {env}"
                        + " ".join(f"-f {shlex.quote(f)}" for f in files) + " down", timeout=300)
    if rc != 0:  # its own files no longer parse (a missing variable): stop it by its project name instead
        rc, out = ctx.r.run(["docker", "compose", "-p", _project_name(d), "down"], timeout=300)
    if rc != 0:
        res.add("earlier stack stopped", "fail", "docker compose down failed: " + (out.strip()[-200:] or f"exit {rc}"),
                f"stop it by hand in {d} (docker compose ... down, without -v), then run the installer again")
        return False
    res.add("earlier stack stopped", "ok", "containers removed; volumes, PCAPs and the backup kept")
    if legacy.caddyfile_uses_own_cert(d):
        cert = legacy.legacy_cert(d)
        if cert:
            ctx.r.run(["mkdir", "-p", os.path.join(d, "certs")])
            ctx.r.run(["cp", "-a", cert[0], os.path.join(d, "certs", "server.crt")])
            ctx.r.run(["cp", "-a", cert[1], os.path.join(d, "certs", "server.key")])
            ctx.extra["legacy_tls"] = True
            res.add("own certificate", "ok", "the earlier stack's certificate (caddy/certs) is used from certs/")
    return True


def _check_volumes(ctx: Ctx, res: Result) -> bool:
    """The `rolling` and `alerts` volumes must be bound to the answered directories (compose.ntop.yaml).

    A volume of the same name made earlier without that binding (an older compose.yaml) is not re-created by
    `docker compose up`: it says so on a prompt nobody answers and keeps the old one, so the api would read an
    empty buffer and write the PCAPs into Docker's own directory. Such a volume is removed only when no container
    uses it and it is empty; otherwise this is a failure to resolve by hand. False when `up` must not run.
    """
    a = ctx.a
    rc, out = ctx.r.probe(_compose(ctx, "config", "--format", "json"), timeout=60)
    try:
        project = json.loads(out[out.index("{"):])["name"] if rc == 0 else _project_name(a["install_dir"])
    except (ValueError, KeyError):
        project = _project_name(a["install_dir"])
    good = True
    for vol, want in (("rolling", a["rolling_dir"]), ("alerts", a["alerts_dir"])):
        name = f"{project}_{vol}"
        rc, out = ctx.r.probe(["docker", "volume", "inspect", name])
        if rc != 0:
            continue
        try:
            info = json.loads(out)[0]
        except (ValueError, IndexError, KeyError):
            continue
        device = (info.get("Options") or {}).get("device")
        if device and os.path.normpath(device) == os.path.normpath(want):
            continue
        users = ctx.r.probe(["docker", "ps", "-aq", "--filter", f"volume={name}"])[1].split()
        mount = info.get("Mountpoint") or ""
        try:
            empty = not device and os.path.isdir(mount) and not os.listdir(mount)
        except OSError:
            empty = False
        if not users and empty:
            ctx.r.run(["docker", "volume", "rm", name])
            res.add(f"volume {vol}", "ok", f"removed the empty {name} of an earlier stack (not bound to {want})")
            continue
        good = False
        res.add(f"volume {vol}", "fail", f"{name} exists but is bound to {device or 'no directory (Docker storage)'}, "
                f"not {want}" + (f"; used by {len(users)} container(s)" if users else "")
                + ("" if empty or device else "; it holds files"),
                f"docker compose down in {a['install_dir']}; if it holds PCAPs, copy them from {mount} into {want} "
                f"first; then docker volume rm {name} and run the installer again")
    return good


def _adopt_password(ctx: Ctx, res: Result, envp: str) -> None:
    """A stack whose password the installer does not know (no `credentials`): check the one given, or make a new one.

    The earlier deployment kept the password outside the installer. Given (BASIC_AUTH_PASS or the question), it
    is checked against the running recorder and kept in `credentials`; not given, a new one replaces the hash
    in .env, and the Passthrough gets it. The earlier password then stops working everywhere else.
    """
    d = ctx.a["install_dir"]
    pw = ctx.secrets.get("basic_auth_pass")
    if pw:
        code, _ = _fetch_stats(ctx)
        if code == 200:
            ctx.r.write(os.path.join(d, "credentials"), f"user: {ctx.a['basic_auth_user']}\npassword: {pw}\n", 0o600)
            res.add("recorder login", "ok", "the earlier password matches; kept in credentials")
            return
        ctx.secrets.pop("basic_auth_pass", None)  # not remembered: the next run asks again or makes a new one
        if code == 403:  # Caddy checks the address before the login: the password was not looked at
            res.add("recorder login", "fail", "could not check the password given: the recorder refused this "
                    "host's address (HTTP 403: the running recorder's ALLOWED_UI_IPS does not contain it)",
                    "run the installer again with the password (BASIC_AUTH_PASS) once this host's address is in the "
                    "allowed networks, or with none to make a new one")
            return
        res.add("recorder login", "fail", f"the password given does not match the hash in .env (HTTP {code})",
                "run the installer again with the right password (BASIC_AUTH_PASS), or with none to make a new one")
        return
    pw = new_password()
    rc, hashed = ctx.r.run(["docker", "run", "-i", "--rm", "caddy:2", "caddy", "hash-password"], input=pw + "\n")
    if rc != 0 or not hashed.strip().startswith("$2"):
        res.add("recorder login", "fail", "could not make a new Basic-auth hash: " + hashed[-120:],
                "check that Docker can pull caddy:2")
        return
    update_env(ctx, envp, {"BASIC_AUTH_HASH": f"'{hashed.strip()}'"})
    ctx.r.write(os.path.join(d, "credentials"), f"user: {ctx.a['basic_auth_user']}\npassword: {pw}\n", 0o600)
    ctx.secrets["basic_auth_pass"] = pw
    ctx.extra["basic_auth_new"] = True
    ctx.extra["restart_caddy"] = True
    res.add("recorder login", "warn", f"the earlier password was not given: a new one is in {d}/credentials",
            "the Passthrough gets it below; anything that called the recorder directly with the old password "
            "(an External Destination to https://<recorder>/extract) must now go through the Passthrough")


def foreign_ports(ctx: Ctx) -> list[str]:
    """The recorder's host ports (HTTPS, HTTP) held by something other than its own compose project, as
    `443 (apache2)`. compose would start the api and then fail on Caddy's port with half a stack up."""
    own = "docker:" + _project_name(ctx.a["install_dir"])
    out = []
    for port in (https_port(ctx.a), http_port(ctx.a)):
        holder = ctx.host.port_holder(port)
        if holder and holder != own:
            out.append(f"{port} ({holder})")
    return out


def foreign_install_dir(ctx: Ctx, d: str, earlier: list[str] | None, have: dict) -> str | None:
    """Why the release must not be synced (rsync --delete) into the install directory `d`, or None (paths.foreign).

    Accepted: no directory, an empty one or one holding only PRE_DEPLOY entries, this installer's deployment
    (`.deployed`), and an earlier recorder stack that _stop_legacy_stack backs up first: compose files without
    `.deployed` and something of the recorder (its .env keys, its sources or Caddyfile), not just any compose project.
    """
    if os.path.realpath(ctx.repo) == os.path.realpath(d):
        return None  # deployed in place: nothing is synced
    recorder = (any(k.startswith(("SR_", "BASIC_AUTH_")) for k in have)
                or os.path.isdir(os.path.join(d, "src", "sycope_recorder"))
                or os.path.isfile(os.path.join(d, "caddy", "Caddyfile")))
    return paths.foreign(d, DEPLOYED, PRE_DEPLOY, recognised=bool(earlier) and recorder)


def step_stack(ctx: Ctx, apply: bool) -> Result:
    """Deploy the stack when anything is off: .env drift, an obsolete key, stopped containers or other code.

    A stack that is up on the same code and .env is left alone. Otherwise (apply) the code is synced,
    the image built, the stack started and /healthz awaited; `.deployed` is written only after that worked.
    """
    res, a = Result(), ctx.a
    d = a["install_dir"]
    envp = os.path.join(d, ".env")
    want = managed_env(ctx)
    have = read_env(envp)
    drift = [k for k, v in want.items() if have.get(k) != v]
    obsolete = [k for k in OBSOLETE_ENV if k in have]
    earlier = legacy.legacy_stack(d, DEPLOYED) if os.path.realpath(ctx.repo) != os.path.realpath(d) else None
    refused = foreign_install_dir(ctx, d, earlier, have)
    if refused:  # the sync below runs with --delete: never over a directory that is not the installer's
        return res.add("install directory", "fail" if apply else "warn", f"not used: {refused}",
                       "answer a new or empty directory (install_dir, INSTALL_DIR); nothing in it was changed")
    running = ctx.r.probe(_compose(ctx, "ps", "--status", "running", "-q"))[1].split() if have and not earlier else []
    fingerprint, release = code_fingerprint(ctx.repo), release_of(ctx.repo)
    deployed = read_deployed(d)
    current = deployed.get("fingerprint") == fingerprint
    # COMPOSE_FILE only tells a plain `docker compose` which files to read; the containers do not see it, so a
    # running stack whose .env lacks only that line (installed before it was managed) gets it without a redeploy.
    files_only = drift == ["COMPOSE_FILE"]
    ok_now = bool(have) and (not drift or files_only) and not obsolete and len(running) >= 2 and current
    if running and not ok_now and (not deployed or deployed.get("release") != release):
        abandoned_jobs_item(ctx, res)  # before anything replaces the running release
    for key, text in legacy.notable_env(have):
        res.add(f".env {key}", "warn", f"kept from the earlier deployment: {text}")
    for status, name, detail, hint in ctx.extra.get("access_items", []):
        res.add(name, status, detail, hint)
    busy = foreign_ports(ctx) if not ok_now else []
    if busy:
        res.add("ports", "fail" if apply else "warn", "host port " + ", ".join(busy) + " is taken by another service",
                "answer other ports (https_port, http_port; SR_HTTPS_PORT/SR_HTTP_PORT), or stop that service")
        if apply:
            return res
    if earlier and not apply:
        res.add("earlier stack", "warn", f"{d} holds a stack this installer did not deploy ({', '.join(earlier)})",
                "the installer backs it up, stops it (keeping volumes and PCAPs) and deploys this release in its place")
    if apply and ok_now and files_only:
        if ctx.dry:
            _would(res, ".env COMPOSE_FILE", f"add COMPOSE_FILE={COMPOSE_FILES} to {envp}")
        else:
            update_env(ctx, envp, {"COMPOSE_FILE": want["COMPOSE_FILE"]})
            drift = []
            res.add(".env COMPOSE_FILE", "ok", f"added: a plain `docker compose` in {d} now uses {COMPOSE_FILES}")
    if apply and not ok_now:
        if ctx.dry:
            if earlier:
                _would(res, "earlier stack", f"back up {', '.join(earlier)} and .env to {STACK_BACKUP_ROOT}, stop it")
            ctx.r.run(f"rsync -a {' '.join(ROOT_OWNED)} {shlex.quote(ctx.repo)}/ {shlex.quote(d)}/")
            return _would(res, "recorder stack", f"sync the code to {d}, write .env, build and start it")
        if earlier and not _stop_legacy_stack(ctx, res, d, earlier):
            return res
        if os.path.realpath(ctx.repo) != os.path.realpath(d):
            ctx.r.run(["mkdir", "-p", d])
            ctx.r.run(["rsync", "-a", "--delete", *ROOT_OWNED, "--exclude", ".git", "--exclude", "old", "--exclude", ".venv",
                       "--exclude", "tests", "--exclude", "__pycache__", "--exclude", ".env", "--exclude", DEPLOYED,
                       "--exclude", "data", "--exclude", "profiles/*.json", "--exclude", "profiles/*.yaml",
                       "--exclude", "credentials", "--exclude", "/bundled",
                       # an own certificate (README_DEPLOY "Own certificate") is the operator's, never the repository's
                       "--filter", "P /certs/**", "--filter", "P /caddy/certs/**",
                       f"{ctx.repo}/", f"{d}/"])
        if not have:
            pw = ctx.secrets.get("basic_auth_pass") or new_password()
            ctx.secrets["basic_auth_pass"] = pw
            ctx.extra["basic_auth_new"] = True  # the Passthrough step then sets it in Sycope
            # The password goes in through stdin: as an argument it would show in `ps` and /proc/<pid>/cmdline.
            rc, hashed = ctx.r.run(["docker", "run", "-i", "--rm", "caddy:2", "caddy", "hash-password"],
                                   input=pw + "\n")
            if rc != 0 or not hashed.strip().startswith("$2"):
                return res.add("recorder stack", "fail", "could not make the Basic-auth hash: " + hashed[-120:],
                               "check that Docker can pull caddy:2")
            ctx.r.write(envp, "\n".join([f"BASIC_AUTH_USER={a['basic_auth_user']}",
                                         f"BASIC_AUTH_HASH='{hashed.strip()}'"]) + "\n", 0o600)
            ctx.r.write(os.path.join(d, "credentials"), f"user: {a['basic_auth_user']}\npassword: {pw}\n", 0o600)
        extra = {}
        if ctx.extra.get("legacy_tls") and "SR_TLS" not in have:
            extra = {"SR_SITE_ADDRESS": ":443", "SR_TLS": "/certs/server.crt /certs/server.key"}
        raw_hash = have.get("BASIC_AUTH_HASH", "")
        if legacy.quote_hash_line(f"BASIC_AUTH_HASH={raw_hash}"):
            extra["BASIC_AUTH_HASH"] = f"'{raw_hash.strip()}'"
            res.add(".env BASIC_AUTH_HASH", "ok", "quoted (compose would otherwise expand the $ in the bcrypt hash)")
        update_env(ctx, envp, {**want, **extra}, remove=OBSOLETE_ENV)
        # what the installer wrote: a later different value in .env was set by hand and is kept (access_env)
        a.setdefault("access_written", {}).update({k: want[k] for k in ACCESS_HAND_SET if k in want})
        for k in obsolete:
            res.add(".env", "ok", f"removed obsolete {k} from .env")
        if earlier and not os.path.exists(os.path.join(d, "credentials")) and not ctx.secrets.get("basic_auth_pass"):
            _adopt_password(ctx, res, envp)  # unknown password: a new one, before the stack starts with it
        if not _check_volumes(ctx, res):
            return res
        say(ctx, "building the image and starting the containers (a few minutes the first time)")
        rc, out = ctx.r.run_live(_compose(ctx, "up", "-d", "--build"), timeout=1800)
        if rc != 0:
            res.add("containers", "fail", "docker compose up failed: " + (out.strip()[-300:] or f"exit code {rc}"),
                    f"docker compose logs in {d}; the previous containers, if any, were not replaced")
            return res
        say(ctx, f"waiting for https://{base(a)}/healthz (up to {HEALTH_TIMEOUT} s)")
        healthy, health = wait_healthy(ctx)
        have = read_env(envp)
        drift = [k for k, v in want.items() if have.get(k) != v]
        running = ctx.r.probe(_compose(ctx, "ps", "--status", "running", "-q"))[1].split()
        res.add("health check", "ok" if healthy else "fail", health,
                "" if healthy else f"docker compose logs api in {d}")
        if healthy and earlier and not os.path.exists(os.path.join(d, "credentials")) and ctx.secrets.get("basic_auth_pass"):
            _adopt_password(ctx, res, envp)  # the earlier password, checked against the stack that now runs
        if healthy and len(running) >= 2 and not drift:
            ctx.r.write(os.path.join(d, DEPLOYED), json.dumps(
                {"release": release, "fingerprint": fingerprint, "at": time.strftime("%Y-%m-%d %H:%M:%S")}) + "\n", 0o644)
            deployed, current = {"release": release, "fingerprint": fingerprint}, True
            ctx.extra["stack_deployed"] = True  # the end-to-end test runs again on the new code
    elif obsolete:
        for k in obsolete:
            res.add(".env", "warn", f"obsolete {k} is still in .env", "the installer removes it when it runs")
    if not have:
        return res.add("recorder stack", "warn", f"not installed in {d}")
    root_owned_item(ctx, res, "code owner", d, ctx.repo, _stack_skip, apply)  # root builds and runs it
    res.add(".env", "ok" if not drift else "warn", f"{envp}" + ("" if not drift else "; differs: " + ", ".join(drift)))
    res.add("deployed code", "ok" if current else "warn",
            f"release {deployed.get('release')}, fingerprint {fingerprint[:12]}" if current
            else ("no .deployed record: the stack was not deployed by this installer (or is from 0.3)" if not deployed
                  else f"the deployed code ({deployed.get('release')}) differs from this repository ({release})"),
            "" if current else "the installer builds and starts the current code")
    res.add("containers", "ok" if len(running) >= 2 else "fail" if apply else "warn", f"{len(running)} running (api, caddy)",
            "" if len(running) >= 2 else f"docker compose logs in {d}")
    return res


def new_password() -> str:
    """The recorder's Basic-auth password, made once per install: 48 letters and digits (about 285 bits). Nobody
    types it: the installer puts it into Caddy and into the Sycope Passthrough, and keeps it in `credentials`."""
    import string

    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(48))


def _recorder_password(ctx: Ctx) -> str | None:
    """The recorder's Basic-auth password: from this run, else from `credentials` (mode 600); None if unknown."""
    pw = ctx.secrets.get("basic_auth_pass") or ""
    if not pw:
        try:
            with open(os.path.join(ctx.a["install_dir"], "credentials")) as fh:
                pw = re.search(r"password: (\S+)", fh.read()).group(1)
        except (OSError, AttributeError):
            return None
    return pw


# ---- 8. Sycope Passthrough --------------------------------------------------------------------
def _sycope_client(ctx: Ctx):
    """A logged-in Sycope session with the installer's account (the same client the profile generator uses)."""
    from . import sycope as sy

    return sy.load_client_module(ctx.repo).Sycope(ctx.a["sycope_url"], ctx.a["sycope_user"],
                                                  ctx.secrets["sycope_pass"], False)


def step_passthrough(ctx: Ctx, apply: bool) -> Result:
    """Create or fix the Sycope Passthrough entry that points at this recorder (the one write to Sycope).

    Only the entry named PASSTHROUGH_NAME is touched, and only when it is missing or points at this recorder
    (upstream https://<public_host>); one that points elsewhere is left alone and reported. Nothing is ever
    deleted. An entry that differs is corrected, and it gets the recorder's password when that password was
    made in this run or when the check through the Passthrough fails. At the end the recorder's /stats (behind
    its Basic auth) is fetched through the entry.
    """
    from . import passthrough as pt

    res, a = Result(), ctx.a
    name, host, port = a.get("passthrough_name") or "", a["public_host"], https_port(a)
    manual = "create it by hand in Sycope (Settings > Integrations > Passthrough); the values are in the next steps"
    if not (a.get("sycope_url") and a.get("sycope_user") and ctx.secrets.get("sycope_pass") and name):
        return res.add("Passthrough", "skip", "no Sycope credentials or Passthrough name", manual)
    pw = _recorder_password(ctx)
    if not pw:
        return res.add("Passthrough", "warn", "the recorder's login is not known yet", "run again after the stack step")
    try:
        say(ctx, f"logging in to {a['sycope_url']} and reading the Passthrough entry '{name}'")
        client = _sycope_client(ctx)
        cur = pt.find(client, name)
    except pt.PassthroughError as exc:
        return res.add("Passthrough", "warn", str(exc), manual)
    except BaseException as exc:  # login refused (SystemExit from the client), network, TLS
        if isinstance(exc, KeyboardInterrupt):
            raise
        return res.add("Passthrough", "warn", f"cannot log in to Sycope: {exc}", manual)
    fresh = bool(ctx.extra.get("basic_auth_new")) or bool(ctx.extra.get("update_passthrough"))
    want = None
    try:
        if cur is None:
            if not apply:
                return res.add("Passthrough", "warn", f"'{name}' does not exist in Sycope")
            if ctx.dry:
                return _would(res, "Passthrough", f"create '{name}' -> {pt.upstream(host, port)}")
            want = pt.desired(name, host, a["basic_auth_user"], pw, port=port)
            pt.create(client, want)
            cur = pt.find(client, name)
            a["passthrough_written"] = pt.upstream(host, port)
            res.add("Passthrough", "ok", f"created '{name}' -> {pt.upstream(host, port)} (Basic auth, the access rules of "
                    "README_DEPLOY section 10)")
        else:
            conf = cur.get("config") or {}
            url = str(conf.get("url") or "").strip().rstrip("/")
            # Ours: it points here, or at what this installer wrote into it earlier (the recorder moved to another
            # port), or at this host on another port and the operator said so (--update-passthrough).
            ours = (pt.points_here(conf, host, port) or (url and url == a.get("passthrough_written"))
                    or (ctx.extra.get("update_passthrough") and pt.same_host(conf, host)))
            if not ours:
                hint = ("if that is this recorder on its old port, run again with --update-passthrough"
                        if pt.same_host(conf, host) else "choose another Passthrough name, or change that entry by hand")
                return res.add("Passthrough", "warn", f"'{name}' exists and points at {url}: left alone", hint)
            want = pt.desired(name, host, a["basic_auth_user"], pw if fresh else None, conf, port=port)
            diff = pt.differences(conf, want)
            if diff or fresh:
                if not apply:
                    return res.add("Passthrough", "warn", f"'{name}' differs: " + ("; ".join(diff) or "new password"))
                if ctx.dry:
                    return _would(res, "Passthrough", f"update '{name}'")
                pt.update(client, cur, want)
                a["passthrough_written"] = pt.upstream(host, port)
                res.add("Passthrough", "ok", f"updated '{name}': " + "; ".join(diff + (["password"] if fresh else [])))
            else:
                res.add("Passthrough", "ok", f"'{name}' -> {pt.upstream(host, port)} as wanted")
        if not apply or ctx.dry:
            return res
        say(ctx, f"checking the recorder through Sycope: GET passthrough/{name}/stats")
        ok, detail = pt.probe(client, name)
        if not ok and want is not None and want.get("password") is None and cur is not None:
            # The entry is ours but the check fails: the likely cause is an old password in it. Set it once.
            want["password"] = pw
            pt.update(client, cur, want)
            ok, detail = pt.probe(client, name)
            detail += " (after setting the recorder's password in the entry)"
    except pt.PassthroughError as exc:
        return res.add("Passthrough", "warn", str(exc), manual)
    res.add("Passthrough check", "ok" if ok else "fail", detail,
            "" if ok else f"open https://{a['sycope_url'].split('://')[-1]}/npm/api/v1/passthrough/{name}/stats "
            "logged in to Sycope; check the entry's URL and that Sycope's address is in ALLOWED_UI_IPS (.env)")
    if ok:
        say(ctx, f"checking the webhook path through Sycope: POST passthrough/{name}/extract")
        ok, detail = pt.probe_webhook(client, name)
        res.add("Passthrough webhook", "ok" if ok else "fail", detail,
                "" if ok else "the POST rule ^/.* must be in the entry, and Caddy's ALLOWED_EXTRACT_IPS must allow Sycope")
    ctx.extra["passthrough_ok"] = ok
    return res


# ---- 8. External Destination ------------------------------------------------------------------
def step_destination(ctx: Ctx, apply: bool) -> Result:
    """Create or fix the Sycope External Destination (REST) that posts alerts to the recorder's Passthrough.

    Only the destination named `destination_name` is touched, and only when it is missing or posts to this
    Passthrough; one of that name posting elsewhere is left alone. When another destination already posts to
    the Passthrough, none is created beside it. The Sycope account of the installer is its Basic auth; the
    password is set when the destination is created or corrected, or with --update-passthrough.
    """
    from . import destination as ds
    from . import passthrough as pt

    res, a = Result(), ctx.a
    name, pt_name = a.get("destination_name") or ds.DEFAULT_NAME, a.get("passthrough_name") or ""
    path = ds.path_of(pt_name or "<passthrough>")
    manual = (f"create it by hand in Sycope (Settings > Integrations > External Destinations): REST client, POST "
              f"{a.get('sycope_url', '').rstrip('/')}{path}, Basic auth with a Sycope account, verify TLS off")
    if not (a.get("sycope_url") and a.get("sycope_user") and ctx.secrets.get("sycope_pass") and pt_name):
        return res.add("External Destination", "skip", "no Sycope credentials or Passthrough name", manual)
    user, pw = a["sycope_user"], ctx.secrets["sycope_pass"]
    try:
        say(ctx, f"reading the External Destinations of {a['sycope_url']}")
        client = _sycope_client(ctx)
        cur, others = ds.find(client, name, a["sycope_url"], pt_name)
        if cur is None:
            if others:
                return res.add("External Destination", "ok", "posts to the Passthrough already as "
                               + ", ".join(repr((o.get("config") or {}).get("name")) for o in others)
                               + f": '{name}' not created beside it")
            if not apply:
                return res.add("External Destination", "warn", f"'{name}' does not exist in Sycope")
            if ctx.dry:
                return _would(res, "External Destination", f"create '{name}' -> POST {path}")
            ds.create(client, ds.desired(name, a["sycope_url"], pt_name, user, pw))
            cur, _ = ds.find(client, name, a["sycope_url"], pt_name)
            res.add("External Destination", "ok" if cur else "fail",
                    f"created '{name}': POST {path} as {user}" if cur else f"'{name}' is not in Sycope after creating it",
                    "" if cur else manual)
        else:
            conf = cur.get("config") or {}
            if not ds.posts_to(conf, a["sycope_url"], pt_name):
                return res.add("External Destination", "warn", f"'{name}' exists and posts to "
                               f"{conf.get('host')}:{conf.get('port')}{conf.get('path')}: left alone",
                               "answer another destination_name (DESTINATION_NAME), or change that destination by hand")
            fresh = bool(ctx.extra.get("update_passthrough"))
            want = ds.desired(name, a["sycope_url"], pt_name, user, None, conf)
            diff = ds.differences(conf, want)
            if diff or fresh:
                if not apply:
                    return res.add("External Destination", "warn", f"'{name}' differs: " + ("; ".join(diff) or "new password"))
                if ctx.dry:
                    return _would(res, "External Destination", f"update '{name}'")
                want["password"] = pw  # the user may have changed with it: the password goes with every correction
                want["params"] = {}
                want["customPayloadEnabled"] = False
                ds.update(client, cur, want)
                res.add("External Destination", "ok", f"updated '{name}': " + "; ".join(diff + (["password"] if fresh else [])))
            else:
                res.add("External Destination", "ok", f"'{name}': POST {path} as {conf.get('username')}")
    except pt.PassthroughError as exc:
        return res.add("External Destination", "warn", str(exc), manual)
    except BaseException as exc:  # login refused (SystemExit from the client), network, TLS
        if isinstance(exc, KeyboardInterrupt):
            raise
        return res.add("External Destination", "warn", f"cannot log in to Sycope: {exc}", manual)
    if ctx.sycope is not None and cur is not None:  # Triage's Get PCAP names it (SC_RECORDER_DESTINATION)
        rows = [r for r in ctx.sycope.get("destinations") or [] if r.get("name") != name]
        c = cur.get("config") or {}
        rows.append({"name": name, "type": "restClient", "host": str(c.get("host")), "port": str(c.get("port")),
                     "path": str(c.get("path") or ""), "method": "POST"})
        ctx.sycope["destinations"] = rows
    if cur is not None:
        ctx.extra["destination"] = name
    res.add("alert action", "ok", f"pick '{name}' as the action of the alert definitions that should record")
    return res


# ---- 8a. End-to-end test ----------------------------------------------------------------------
E2E_POLL = 240  # seconds the test job gets to finish
PCAP_MAGIC = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a")


def _job_state(ctx: Ctx, key: str) -> tuple[str | None, dict]:
    """State of the alert link `key`, asked of the recorder itself (any HTTP status carries the JSON)."""
    auth = _basic_auth(ctx)
    req = urllib.request.Request(f"https://{base(ctx.a)}/{key}?format=json",
                                 headers={"Authorization": auth or "", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15, context=_insecure_context()) as r:
            body = r.read().decode()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
    except Exception:
        return None, {}
    try:
        data = json.loads(body)
    except ValueError:
        return None, {}
    return data.get("state"), data


def step_e2e(ctx: Ctx, apply: bool) -> Result:
    """A real alert through Sycope: webhook through the Passthrough, extraction from the buffer, download through it.

    The alert names the address seen most on the capture NIC, a little in the past, so that its window is already
    closed and the job runs at once. `done` with a PCAP proves the whole path; `miss` (that address had no packets
    in that window) still proves everything but the packets, and is a warning. It leaves one job and one PCAP named
    installer-e2e-<time> on the recorder.
    """
    from . import passthrough as pt

    res, a = Result(), ctx.a
    name = a.get("passthrough_name") or ""
    if not apply:
        return res.add("end-to-end test", "ok", "runs after the stack and the Passthrough are set up "
                       "(again with --redo e2e)")
    if ctx.dry:
        return _would(res, "end-to-end test", "send a test alert through the Passthrough and download its PCAP")
    if not (a.get("sycope_url") and ctx.secrets.get("sycope_pass") and name):
        return res.add("end-to-end test", "skip", "no Sycope credentials or Passthrough name")
    if ctx.extra.get("passthrough_ok") is False:
        return res.add("end-to-end test", "skip", "the Passthrough check failed above", "fix it, then --redo e2e")
    if ctx.extra.get("licensed") is False:
        return res.add("end-to-end test", "skip", "n2disk has no valid licence: nothing is recorded")
    say(ctx, f"looking for a busy host on {a['capture_iface']} (5 s of tcpdump)")
    ip = ctx.host.busy_ip(a["capture_iface"], 5)
    if not ip:
        return res.add("end-to-end test", "warn", f"no IPv4 traffic seen on {a['capture_iface']}",
                       "check the mirror port, then --redo e2e")
    when = int(time.time()) - 360 - int(a["chunk_seconds"]) - 60  # its window [T-360, T+360] is closed by now
    key = f"installer-e2e-{int(time.time())}"
    try:
        say(ctx, f"sending a test alert for {ip} through Sycope: POST passthrough/{name}/extract")
        client = _sycope_client(ctx)
        ans = pt.post(client, name, "extract", {"id": key, "clientIp": ip, "unixTimestamp": when,
                                                "name": "Recorder installer end-to-end test"})
    except pt.PassthroughError as exc:
        return res.add("end-to-end test", "fail", f"webhook through the Passthrough: {exc}")
    except BaseException as exc:
        if isinstance(exc, KeyboardInterrupt):
            raise
        return res.add("end-to-end test", "fail", f"cannot log in to Sycope: {exc}")
    res.add("test alert", "ok", f"host {ip} at {time.strftime('%H:%M:%S', time.localtime(when))}, "
            f"answer {str(ans).strip()[:80]!r}")
    start, state, data, said = time.monotonic(), None, {}, None
    say(ctx, f"waiting for the extraction of {key} (up to {E2E_POLL} s)")
    while time.monotonic() - start < E2E_POLL:
        state, data = _job_state(ctx, key)
        if state != said:
            say(ctx, f"job {key}: {state or 'no answer yet'} after {time.monotonic() - start:.0f} s")
            said = state
        if state in ("done", "miss", "failed", "cancelled"):
            break
        time.sleep(5)
    waited = time.monotonic() - start
    if state == "done":
        say(ctx, "downloading the PCAP through Sycope")
        code, head = pt.fetch_raw(client, name, f"{key}?download=1")
        good = code == 200 and head[:4] in PCAP_MAGIC
        return res.add("test PCAP", "ok" if good else "fail",
                       f"extracted in {waited:.0f} s and downloaded through the Passthrough" if good
                       else f"extracted, but the download through the Passthrough gave HTTP {code}",
                       "" if good else "the Passthrough's GET rule must allow ^/([A-Za-z0-9_-]+)?/?$ (the query is not part of it)")
    detail = (data.get("jobs") or [{}])[0].get("detail") if isinstance(data.get("jobs"), list) and data.get("jobs") else ""
    # A miss is tried again (SR_JOB_MAX_ATTEMPTS, minutes apart), so the poll can end while the job is
    # queued for its next attempt: its detail then already says miss. The path worked either way.
    if state == "miss" or (state in ("queued", "running") and str(detail or "").startswith("miss")):
        return res.add("test PCAP", "warn", f"the job ran (in {waited:.0f} s) but {ip} had no packets in its window"
                       + ("" if state == "miss" else " (the recorder is still retrying it)"),
                       "the path works; the address was busy now but not in that window, or the buffer is new or "
                       "quiet. --redo e2e to try another address")
    return res.add("test PCAP", "fail", f"state {state or 'unknown'} after {waited:.0f} s" + (f": {detail}" if detail else ""),
                   f"the job's page: https://{base(a)}/{key}; docker compose logs api in {a['install_dir']}")


# ---- 8b. Sycope Triage (optional) -------------------------------------------------------------
def step_triage(ctx: Ctx, apply: bool) -> Result:
    from . import triage

    return triage.step_triage(ctx, apply)


# ---- 9. Verify --------------------------------------------------------------------------------
def _basic_auth(ctx: Ctx) -> str | None:
    """The `Authorization` header value of the recorder's Basic-auth login, None when no login is known."""
    pw = _recorder_password(ctx)
    if not pw:
        return None
    import base64

    return "Basic " + base64.b64encode(f"{ctx.a['basic_auth_user']}:{pw}".encode()).decode()


def _selftest(ctx: Ctx) -> tuple[bool, str]:
    """A webhook with nothing to filter on: the recorder answers NO BPF FILTER and queues nothing."""
    auth = _basic_auth(ctx)
    if auth is None:
        return False, "no Basic-auth login known"
    req = urllib.request.Request(f"https://{base(ctx.a)}/extract", data=json.dumps({"id": "installer-selftest"}).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    req.add_header("Authorization", auth)
    try:
        with urllib.request.urlopen(req, timeout=15, context=_insecure_context()) as r:
            body, outcome = r.read().decode(), r.headers.get("X-Outcome")
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    return body == "NO BPF FILTER" and outcome == "no_bpf", f"answered {body!r} (X-Outcome {outcome})"


def _fetch_stats(ctx: Ctx) -> tuple[int | None, str]:
    """GET /stats with the Basic-auth login: (HTTP status, body), or (None, reason) when it cannot be asked."""
    auth = _basic_auth(ctx)
    if auth is None:
        return None, "no Basic-auth login known"
    req = urllib.request.Request(f"https://{base(ctx.a)}/stats", headers={"Authorization": auth})
    try:
        with urllib.request.urlopen(req, timeout=15, context=_insecure_context()) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


# The 0.4 processes inside the api container. Pure parsers and judges (unit-tested with fake output); the
# docker calls go through ctx.r.probe in step_verify.
WEB_UID, WORKER_UID = 10001, 0
STATE_DIRS = {"/var/lib/sycope-recorder": ("root", "sr", "2775"), "/var/log/sycope-recorder": ("root", "sr", "2750")}
HEARTBEAT_MAX = 60
SUPERVISOR_WAIT = 60  # seconds supervisord gets to move web and worker from STARTING (startsecs=5) to RUNNING
UIDS_SCRIPT = (  # the same logic as `uids` in tests/smoke/compose_smoke.sh, but run with -c
    # `python -c` puts this very text in its own command line: the names are split and the own pid is
    # skipped, or the check would find itself and report a "web process" running as root.
    "import os\n"
    "me = str(os.getpid())\n"
    "for pid in filter(str.isdigit, os.listdir('/proc')):\n"
    "    try:\n"
    "        cmd = open(f'/proc/{pid}/cmdline', 'rb').read().replace(b'\\0', b' ').decode()\n"
    "        uid = [l.split()[1] for l in open(f'/proc/{pid}/status') if l.startswith('Uid:')][0]\n"
    "    except OSError:\n"
    "        continue\n"
    "    if pid == me:\n"
    "        continue\n"
    "    if 'gunico' + 'rn' in cmd:\n"
    "        print('web', uid, pid)\n"
    "    if 'sycope_recorder ' + 'worker' in cmd:\n"
    "        print('worker', uid, pid)\n"
)
PCAP_SCRIPT = (  # run as the web user: can it read what the worker (root) wrote?
    "import os\n"
    "d = os.environ.get('SR_OUTPUT_DIR', '/storage/pcaps/alerts')\n"
    "try:\n"
    "    names = [n for n in os.listdir(d) if n.endswith('.pcap') and '.part' not in n]\n"
    "except PermissionError:\n"
    "    print('DENIED_DIR', d, oct(os.stat(d).st_mode & 0o7777))\n"
    "    raise SystemExit(0)\n"
    "paths = []\n"
    "for n in names:\n"
    "    try:\n"
    "        paths.append((os.path.getmtime(os.path.join(d, n)), os.path.join(d, n)))\n"
    "    except OSError:\n"
    "        pass\n"
    "if not paths:\n"
    "    print('NONE')\n"
    "    raise SystemExit(0)\n"
    "p = max(paths)[1]\n"
    "try:\n"
    "    open(p, 'rb').read(1)\n"
    "    print('OK', p)\n"
    "except PermissionError:\n"
    "    print('DENIED', p, oct(os.stat(p).st_mode & 0o7777))\n"
    "except OSError as exc:\n"
    "    print('ERROR', p, exc)\n"
)


def parse_supervisor_status(text: str) -> dict[str, str]:
    """name -> state from `supervisorctl status` lines (`web   RUNNING   pid 7, uptime 0:01:12`)."""
    out = {}
    for line in text.splitlines():
        m = re.match(r"^(\S+)\s+([A-Z]+)\b", line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def judge_supervisor(states: dict[str, str]) -> tuple[str, str]:
    """ok when both programs are RUNNING, else fail naming what each is."""
    seen = ", ".join(f"{n} {states.get(n, 'missing')}" for n in ("web", "worker"))
    bad = [n for n in ("web", "worker") if states.get(n) != "RUNNING"]
    return ("fail", seen) if bad else ("ok", seen)


def parse_uid_lines(text: str) -> list[tuple[str, int, int]]:
    """(role, uid, pid) from the lines `UIDS_SCRIPT` prints; anything else is ignored."""
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] in ("web", "worker") and parts[1].isdigit() and parts[2].isdigit():
            rows.append((parts[0], int(parts[1]), int(parts[2])))
    return rows


def judge_uids(rows: list[tuple[str, int, int]]) -> tuple[str, str]:
    """ok when every gunicorn process runs as UID 10001 (sr) and the worker as UID 0 (root)."""
    web = [r for r in rows if r[0] == "web"]
    worker = [r for r in rows if r[0] == "worker"]
    problems = []
    if not web:
        problems.append("no gunicorn process found")
    problems += [f"web process pid {pid} runs as UID {uid}, want {WEB_UID}" for _, uid, pid in web if uid != WEB_UID]
    if not worker:
        problems.append("no worker process found")
    problems += [f"worker process pid {pid} runs as UID {uid}, want {WORKER_UID}" for _, uid, pid in worker if uid != WORKER_UID]
    if problems:
        return "fail", "; ".join(problems)
    return "ok", f"{len(web)} web process(es) as UID {WEB_UID}, worker as UID {WORKER_UID}"


def parse_stat_lines(text: str) -> dict[str, tuple[str, str, str]]:
    """path -> (owner, group, octal mode) from `stat -c '%U %G %a %n'` lines."""
    out = {}
    for line in text.splitlines():
        m = re.match(r"^(\S+) (\S+) ([0-7]{3,4}) (/.+)$", line)
        if m:
            out[m.group(4)] = (m.group(1), m.group(2), m.group(3))
    return out


def judge_dirs(found: dict[str, tuple[str, str, str]]) -> tuple[str, str]:
    """ok when the state and the worker-log directories have the owner, group and mode 0.4 sets up."""
    problems = []
    for path, want in STATE_DIRS.items():
        have = found.get(path)
        if have is None:
            problems.append(f"{path} could not be read")
        elif have != want:
            problems.append(f"{path} is {have[0]}:{have[1]} {have[2]}, want {want[0]}:{want[1]} {want[2]}")
    if problems:
        return "fail", "; ".join(problems)
    return "ok", ", ".join(f"{p} {o}:{g} {m}" for p, (o, g, m) in STATE_DIRS.items())


def judge_worker_stats(code: int | None, body: str) -> tuple[str, str]:
    """ok when /stats says the worker is alive with a heartbeat of at most 60 s."""
    if code != 200:
        return "fail", f"/stats gave {code if code is not None else 'no answer'}: {body[:120]}"
    try:
        w = json.loads(body)["worker"]
        alive, age, state = bool(w["alive"]), w.get("heartbeat_age"), w.get("state")
    except (ValueError, KeyError, TypeError):
        return "fail", "/stats has no worker section (an older release, or not JSON)"
    if not alive:
        return "fail", f"worker is not alive (state {state}, heartbeat {age} s ago)"
    if not isinstance(age, (int, float)) or age > HEARTBEAT_MAX:
        return "fail", f"worker heartbeat is {age} s old (limit {HEARTBEAT_MAX} s)"
    return "ok", f"alive, state {state}, heartbeat {age} s ago"


def judge_pcap_read(rc: int, out: str) -> tuple[str, str, str]:
    """(status, detail, hint) of the PCAP read as the web user, from what `PCAP_SCRIPT` printed."""
    line = next((ln for ln in reversed(out.strip().splitlines()) if ln.split(" ")[0] in
                 ("OK", "NONE", "DENIED", "DENIED_DIR", "ERROR")), "") if rc == 0 else ""
    parts = line.split(" ", 2)
    if parts[0] == "OK":
        return "ok", f"the web user can read {parts[1]}", ""
    if parts[0] == "NONE":
        return "skip", "no PCAPs yet: nothing to read", ""
    if parts[0] in ("DENIED", "DENIED_DIR"):
        what = "the PCAP" if parts[0] == "DENIED" else "the alerts directory"
        return ("fail", f"the web user (sr) cannot read {what} {parts[1]} (mode {parts[2] if len(parts) > 2 else '?'})",
                "downloads would fail: the worker must write files the web can read (0644); chmod the file, "
                "check docker compose logs api")
    if parts[0] == "ERROR":
        return "warn", f"could not check: {line}", ""
    return "warn", f"could not run the check: {out.strip()[-200:] or 'no output'}", "is the api container running? docker compose ps"


def wait_supervisor(ctx: Ctx, timeout: float = SUPERVISOR_WAIT, interval: float = 2.0) -> tuple[dict[str, str], float]:
    """`supervisorctl status` until neither program is STARTING (they stay so for startsecs), at most `timeout` s.

    Only STARTING is waited for, and only while the other program is RUNNING or STARTING too: if either is FATAL,
    BACKOFF, EXITED, STOPPED, missing or gives no answer, waiting will not help and the states are judged at once.
    Returns the last states and the seconds waited.
    """
    start = time.monotonic()
    while True:
        _, out = ctx.r.probe(_compose(ctx, "exec", "-T", "api", "supervisorctl", "status"), timeout=30)
        states = parse_supervisor_status(out)
        waited = time.monotonic() - start
        pair = (states.get("web"), states.get("worker"))
        if "STARTING" not in pair or any(x not in ("RUNNING", "STARTING") for x in pair) or waited + interval > timeout:
            return states, waited
        time.sleep(interval)


def step_verify(ctx: Ctx, apply: bool) -> Result:
    res, a = Result(), ctx.a
    if not records(a):
        return _verify_traffic(ctx, res)
    if not os.path.exists(os.path.join(a["install_dir"], ".env")):
        return res.add("verification", "skip", "the stack is not installed")
    licensed = ctx.extra.get("licensed")
    if licensed is None:
        licensed = _n2disk_info(ctx)["licensed"]
    rc, out = ctx.r.probe(_compose(ctx, "exec", "-T", "api", "python", "-m", "sycope_recorder", "doctor"), timeout=120)
    for line in out.splitlines():
        m = re.match(r"\[(OK|WARN|FAIL)\s*\]\s+(\S+?):\s*(.*)", line)
        if not m:
            continue
        status = {"OK": "ok", "WARN": "warn", "FAIL": "fail"}[m.group(1)]
        hint = ""
        if m.group(2) == "rolling_fresh" and status == "fail" and not licensed:
            status, hint = "warn", "expected: n2disk is not recording without a licence"
        elif m.group(2) == "rolling_fresh" and status == "fail" and "no files under" in m.group(3):
            # n2disk fills a file in memory before it appears: an empty buffer right after its start is not
            # a failure yet. Later than one file duration (plus a margin) it is.
            age = None if external_n2disk(ctx) else _unit_age(ctx, f"n2disk@{a['capture_iface']}.service")
            grace = int(a.get("chunk_seconds") or 300) + 120
            if age is not None and age < grace:
                status, hint = "warn", (f"expected: n2disk started {age:.0f} s ago and has not written its first "
                                        f"file yet (it appears within {grace} s); check again with --check")
        res.add(f"doctor: {m.group(2)}", status, m.group(3), hint)
    if not res.items:
        res.add("doctor", "fail", out[-200:] or "no output", f"docker compose logs api in {a['install_dir']}")
    ok, detail = _selftest(ctx)
    res.add("webhook self-test", "ok" if ok else "fail", detail,
            "" if ok else "POST https://<host>/extract with the Basic-auth login should answer NO BPF FILTER "
            "(HTTP 403: this host's address is not in ALLOWED_EXTRACT_IPS, .env)")
    logs = f"docker compose logs api in {a['install_dir']}"
    # 0.4 runs the web (user sr) and the worker (root) as two programs of one container.
    states, waited = wait_supervisor(ctx)
    status, detail = judge_supervisor(states)
    res.add("supervisord processes", status, detail + (f" (after {waited:.0f} s)" if waited >= 1 and status == "ok" else ""),
            "" if status == "ok" else logs)
    _, out = ctx.r.probe(_compose(ctx, "exec", "-T", "api", "python", "-c", UIDS_SCRIPT), timeout=30)
    status, detail = judge_uids(parse_uid_lines(out))
    res.add("process users", status, detail, "" if status == "ok" else "the web must run as sr (10001) and the worker as root: " + logs)
    _, out = ctx.r.probe(_compose(ctx, "exec", "-T", "api", "stat", "-c", "%U %G %a %n", *STATE_DIRS), timeout=30)
    status, detail = judge_dirs(parse_stat_lines(out))
    res.add("state and log directories", status, detail,
            "" if status == "ok" else "the container entrypoint sets these on every start: " + logs)
    status, detail = judge_worker_stats(*_fetch_stats(ctx))
    res.add("worker alive", status, detail, "" if status == "ok" else logs)
    rc, out = ctx.r.probe(_compose(ctx, "exec", "-T", "-u", "sr", "api", "python", "-c", PCAP_SCRIPT), timeout=30)
    status, detail, hint = judge_pcap_read(rc, out)
    res.add("web reads PCAPs", status, detail, hint)
    return _verify_traffic(ctx, res)


def _verify_traffic(ctx: Ctx, res: Result) -> Result:
    a = ctx.a
    n = ctx.host.packet_sample(a["capture_iface"], 15)
    if n is None:
        res.add("traffic on the capture NIC", "skip", "tcpdump not available")
    elif n > 0:
        res.add("traffic on the capture NIC", "ok", f"{n} packets in 15 s on {a['capture_iface']}")
    else:
        res.add("traffic on the capture NIC", "warn", f"no packets in 15 s on {a['capture_iface']}",
                "is the mirror/SPAN port connected and the NIC cabled? On a very quiet link this can also be normal")
    return res


@dataclass
class Step:
    id: str
    title: str
    fn: Callable[[Ctx, bool], Result]
    version: int
    keys: tuple[str, ...]
    always: bool = False  # run (inspect) every time, never reused
    needs: tuple[str, ...] = ()  # steps that must not have crashed before this one is applied
    profiles: frozenset[str] = EVERY  # the install profiles that run this step


STEPS: list[Step] = [
    Step("sycope", "Sycope access", step_sycope, 1, ("sycope_url", "sycope_user", "passthrough_name"), always=True,
         profiles=RECORDER),
    Step("preflight", "Host checks", step_preflight, 2, ("capture_iface", "rolling_dir", "alerts_dir"), always=True),
    Step("base_packages", "Base packages", step_base_packages, 2, ()),
    Step("ntop_repo", "ntop repository", step_ntop_repo, 3, ()),
    Step("n2disk", "n2disk and npcapextract", step_n2disk, 4, ("license_file",),
         needs=("base_packages", "ntop_repo"), profiles=RECORDER),
    Step("capture_nic", "Capture NIC and directories", step_capture_nic, 3,
         ("capture_iface", "rolling_dir", "alerts_dir", "profile")),
    Step("tuning", "Capture tuning", step_tuning, 2, ("capture_iface", "profile"), needs=("capture_nic",)),
    Step("licence_inbox", "Licence inbox", step_licence_inbox, 1, ()),
    Step("pf_ring", "PF_RING kernel module", step_pf_ring, 1, ("capture_iface",), needs=("n2disk",)),
    Step("n2disk_config", "n2disk configuration", step_n2disk_config, 6,
         ("capture_iface", "rolling_dir", "rolling_limit", "chunk_seconds", "packet_slicing", "capture_filter"),
         needs=("n2disk", "capture_nic"),
         profiles=RECORDER),
    Step("nprobe", "nProbe", step_nprobe, 1, ("nprobe_license_file",), needs=("base_packages", "ntop_repo"),
         profiles=PROBE),
    Step("nprobe_config", "nProbe configuration", step_nprobe_config, 1,
         ("capture_iface", "collector", "nprobe_instances", "nprobe_template", "nprobe_active_timeout",
          "nprobe_idle_timeout", "nprobe_max_flows"), needs=("nprobe", "capture_nic"), profiles=PROBE),
    Step("docker", "Docker", step_docker, 2, (), needs=("base_packages",), profiles=RECORDER),
    Step("profiles", "Extraction profiles", step_profiles, 2, ("sycope_url", "sycope_user", "install_dir"),
         profiles=RECORDER),
    Step("stack", "Recorder stack", step_stack, 4, ("install_dir", "public_host", "rolling_dir", "alerts_dir",
                                                    "chunk_seconds", "allowed_ips", "basic_auth_user",
                                                    "passthrough_name", "sycope_url", "https_port", "http_port"), needs=("docker",),
         profiles=RECORDER),
    Step("passthrough", "Sycope Passthrough", step_passthrough, 2,
         ("sycope_url", "sycope_user", "passthrough_name", "public_host", "basic_auth_user", "https_port"), needs=("stack",),
         profiles=RECORDER),
    Step("destination", "Sycope External Destination", step_destination, 1,
         ("sycope_url", "sycope_user", "passthrough_name", "destination_name"), needs=("passthrough",),
         profiles=RECORDER),
    Step("triage", "Sycope Triage", step_triage, 3,
         ("triage", "triage_src", "triage_dir", "triage_port", "triage_passthrough_name", "triage_sycope_user",
          "triage_memory_mb", "public_host", "sycope_url", "sycope_user", "passthrough_name", "allowed_ips"),
         needs=("docker",), profiles=RECORDER),
    Step("e2e", "End-to-end test", step_e2e, 1, ("public_host", "passthrough_name", "capture_iface"),
         needs=("passthrough",), profiles=RECORDER),
    Step("verify", "Verification", step_verify, 2, (), always=True),
]
