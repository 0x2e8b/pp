"""Remove what the installer set up, except the licences (and the PCAPs).

Each part is `fn(ctx, apply) -> Result`, like the installation steps: with apply=False it only looks and
says what it would remove (status "skip"); with apply=True it removes it, through `ctx.r` so --dry-run
prints the commands. Kept on purpose, never removed by any part:

- the licences: /etc/*.license, the licence backups (licence.BACKUP_ROOT) and every licence file still in
  the inbox, licence-done or licence-rejected. They can be replaced by hand later;
- the PCAPs: the rolling buffer and the alerts directory, with their contents (they are evidence). The
  Docker volumes bound to them are removed only when nothing mounts them (Docker never deletes the
  directory a bind volume points at; the entry count is compared before and after anyway);
- an n2disk that runs outside `n2disk@<nic>` (legacy.py): its unit, configuration, package and PF_RING;
- configuration files that were edited by hand (no installer marker), the `.bak` copies of earlier
  configurations, the operator's own TLS certificate (`certs/`), base packages and Docker (unless asked).

The one write to Sycope: the Passthrough entries named `passthrough_name` and `triage_passthrough_name`
are deleted when they point at this recorder (or this Triage); an entry that points elsewhere is left.
"""

from __future__ import annotations

import glob
import os
import re
import shlex
import stat
import urllib.parse

from . import legacy
from . import licence
from . import licence_inbox as li
from . import nprobe as np_
from . import paths
from . import steps as st
from . import triage as tg
from . import tuning as tu
from .report import Result

STATE_DIR = "/var/lib/sycope-recorder-installer"
DEFAULT_INSTALL_DIR = "/opt/sycope-recorder"
DOCKER_VOLUMES = "/var/lib/docker/volumes"
# Under the state directory: what is removed, and what is kept while it holds a licence file.
STATE_REMOVE = ("state.json", "secrets.json", "reports", "stack-backup", "licence-request.txt", "installer.lock")
LICENCE_HOLDERS = (li.INBOX, li.DONE, li.REJECTED)
NTOP_PACKAGES = ("n2disk", "nprobe", "pfring-dkms", "pfring")  # removed (not purged) when they are ours
NTOP_REPO_PACKAGE = "apt-ntop-stable"  # purged: removing it leaves its sources file behind
OTHER_NTOP = ("ntopng", "cento", "nscrub", "n2n", "apt-ntop")  # installed by someone else: the repository stays
DOCKER_PACKAGES = ("docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin")
DOCKER_LIST = "/etc/apt/sources.list.d/docker.list"
DOCKER_KEY = "/etc/apt/keyrings/docker.asc"


# ---- what must never be removed ----------------------------------------------------------------
def _within(path: str, root: str) -> bool:
    p, r = os.path.realpath(path), os.path.realpath(root)
    return p == r or p.startswith(r.rstrip("/") + "/")


def _holds_files(d: str) -> bool:
    for _root, _dirs, files in os.walk(d):
        if files:
            return True
    return False


def protected(ctx, path: str) -> str | None:
    """Why `path` must not be removed (it is or holds a licence or a PCAP directory), or None."""
    a = ctx.a
    if os.path.realpath(path) in ("/", "/etc", "/opt", "/usr", "/var", "/var/lib", "/home", "/root", "/srv"):
        return "a system directory"
    if os.path.isdir(path) and not os.path.islink(path):  # a symlink is removed as a link: its target stays
        why = paths.system_reason(os.path.realpath(path))
        if why:
            return why
    for lic in glob.glob(licence.LICENCE_GLOB):
        if _within(lic, path):
            return f"it holds the licence {lic}"
    if os.path.exists(licence.BACKUP_ROOT) and _within(licence.BACKUP_ROOT, path):
        return f"it holds the licence backups ({licence.BACKUP_ROOT})"
    for d in LICENCE_HOLDERS:
        if os.path.isdir(d) and _within(d, path) and _holds_files(d):
            return f"it holds licence files ({d})"
    for key in ("rolling_dir", "alerts_dir"):
        d = a.get(key)
        if d and (_within(d, path) or _within(path, d)):
            return f"it is or holds the PCAP directory {d}"
    if path.endswith(".license"):
        return "a licence file"
    return None


def remove(ctx, res: Result, name: str, path: str, apply: bool, recursive: bool = False) -> bool:
    """Remove one file or directory, unless `protected` says no. True when it is gone (or would be)."""
    if not os.path.lexists(path):
        return True
    why = protected(ctx, path)
    if why:
        res.add(name, "warn", f"{path} kept: {why}")
        return False
    if not apply:
        res.add(name, "skip", f"would remove {path}")
        return True
    ctx.r.run(["rm", "-rf" if recursive else "-f", "--", path])
    gone = ctx.dry or not os.path.lexists(path)
    res.add(name, "ok" if gone else "fail", ("would remove " if ctx.dry else "removed ") + path if gone
            else f"{path} could not be removed")
    return gone


def _left_by_installer(path: str) -> bool:
    """A regular file owned by root at `path`: what earlier installers left in /tmp. A symlink or another user's
    file at that name in a world-writable directory is not ours to remove."""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and info.st_uid == 0


def _read(path: str) -> str | None:
    try:
        return open(path).read()
    except OSError:
        return None


def _state(ctx, unit: str) -> tuple[str, str]:
    active = ctx.r.probe(["systemctl", "is-active", unit])[1].strip()
    enabled = ctx.r.probe(["systemctl", "is-enabled", unit])[1].strip()
    return active, enabled


def stop_unit(ctx, res: Result, unit: str, apply: bool) -> None:
    """disable --now a unit that is active or enabled; nothing when it is neither."""
    active, enabled = _state(ctx, unit)
    if active not in ("active", "activating", "failed") and enabled not in ("enabled", "enabled-runtime"):
        return
    if not apply:
        res.add(unit, "skip", f"would stop and disable it ({active}, {enabled})")
        return
    ctx.r.run(["systemctl", "disable", "--now", unit])
    ctx.r.run(["systemctl", "reset-failed", unit])
    active = "inactive" if ctx.dry else _state(ctx, unit)[0]
    res.add(unit, "ok" if active != "active" else "fail", "stopped and disabled" if active != "active" else "still active",
            "" if active != "active" else f"systemctl status {unit}")


def _daemon_reload(ctx, apply: bool) -> None:
    if apply:
        ctx.r.run(["systemctl", "daemon-reload"])


# ---- what is on this host ----------------------------------------------------------------------
_INSTANCE = re.compile(r"(?:recorder-capture-nic|recorder-capture-tune|n2disk)@([^.\s]+)\.service")


def interfaces(ctx) -> list[str]:
    """The capture NICs the installer set up: the answer, the instances systemd knows, our n2disk configs."""
    found = {ctx.a["capture_iface"]} if ctx.a.get("capture_iface") else set()
    out = ctx.r.probe(["systemctl", "list-units", "--all", "--plain", "--no-legend",
                       "recorder-capture-nic@*", "recorder-capture-tune@*"])[1]
    found.update(_INSTANCE.findall(out))
    for p in glob.glob(os.path.join(st.SYSTEMD_DIR, "*.wants", "recorder-capture-*@*.service")):
        found.update(_INSTANCE.findall(os.path.basename(p)))
    for p in glob.glob(os.path.join(st.N2DISK_CONF_DIR, "n2disk-*.conf")):
        if (_read(p) or "").startswith(st.MARKER):
            found.add(os.path.basename(p)[len("n2disk-"):-len(".conf")])
    return sorted(f for f in found if re.fullmatch(r"[A-Za-z0-9_.:-]+", f))


def _pkg(ctx, name: str) -> bool:
    rc, out = ctx.r.probe(["dpkg-query", "-W", "-f=${Status}", name])
    return rc == 0 and "install ok installed" in out


# ---- 1. Sycope ---------------------------------------------------------------------------------
def delete_entry(client, entry: dict) -> None:
    """DELETE one configuration element: a Passthrough entry or the External Destination (the uninstaller's
    only deletes in Sycope)."""
    from . import passthrough as pt

    pt._send(client, "DELETE", f"config-element/{urllib.parse.quote(str(entry['id']))}")


def part_sycope(ctx, apply: bool) -> Result:
    from . import passthrough as pt

    res, a = Result(), ctx.a
    if ctx.extra.get("keep_sycope"):
        return res.add("Passthrough", "ok", "not touched (--keep-sycope)")
    host = a.get("public_host") or ""
    wanted = []
    if a.get("passthrough_name"):
        wanted.append((a["passthrough_name"], "recorder", st.https_port(a), a.get("passthrough_written")))
    if tg.chosen(a) or os.path.isdir(a.get("triage_dir") or tg.DEFAULT_DIR):
        wanted.append((a.get("triage_passthrough_name") or tg.DEFAULT_PASSTHROUGH, "Triage",
                       str(a.get("triage_port") or tg.DEFAULT_PORT), None))
    if not wanted:
        return res.add("Passthrough", "ok", "no Passthrough entry was configured")
    names = ", ".join(f"'{n}'" for n, *_ in wanted)
    manual = f"delete {names} by hand in Sycope (Settings > Integrations > Passthrough) if they point at {host}"
    if not (a.get("sycope_url") and a.get("sycope_user") and ctx.secrets.get("sycope_pass") and host):
        return res.add("Passthrough", "warn", "no Sycope login remembered: the entries are not removed", manual)
    try:
        client = st._sycope_client(ctx)
    except BaseException as exc:  # login refused (SystemExit from the client), network, TLS
        if isinstance(exc, KeyboardInterrupt):
            raise
        return res.add("Passthrough", "warn", f"cannot log in to Sycope: {exc}", manual)
    for name, what, port, written in wanted:
        label = f"Passthrough {name}"
        try:
            cur = pt.find(client, name)
            if cur is None:
                res.add(label, "ok", "not in Sycope")
                continue
            conf = cur.get("config") or {}
            url = str(conf.get("url") or "").strip().rstrip("/")
            if not (pt.points_here(conf, host, port) or (written and url == written)):
                res.add(label, "warn", f"points at {url}, not at this {what}: left alone")
                continue
            if not apply:
                res.add(label, "skip", f"would delete it from Sycope ({url})")
                continue
            if ctx.dry:
                res.add(label, "skip", f"would delete it from Sycope ({url}) (dry run)")
                continue
            delete_entry(client, cur)
            gone = pt.find(client, name) is None
            res.add(label, "ok" if gone else "fail", f"deleted from Sycope ({url})" if gone else "still in Sycope",
                    "" if gone else manual)
        except pt.PassthroughError as exc:
            res.add(label, "fail" if apply else "warn", str(exc), manual)
    if a.get("passthrough_name"):
        _destination(ctx, res, client, apply, manual)
    return res


def _destination(ctx, res: Result, client, apply: bool, manual: str) -> None:
    """The External Destination the installer made (destination_name), when it posts to this Passthrough.
    Others that post there (made by hand) are only reported: their alert actions fail once it is gone."""
    from . import destination as ds
    from . import passthrough as pt

    a = ctx.a
    name = a.get("destination_name") or ds.DEFAULT_NAME
    label = f"External Destination {name}"
    try:
        cur, others = ds.find(client, name, a["sycope_url"], a["passthrough_name"])
        if cur is None:
            res.add(label, "ok", "not in Sycope")
        elif not ds.posts_to(cur.get("config") or {}, a["sycope_url"], a["passthrough_name"]):
            res.add(label, "warn", "posts somewhere else: left alone")
        elif not apply or ctx.dry:
            res.add(label, "skip", f"would delete it from Sycope ({ds.path_of(a['passthrough_name'])})")
        else:
            delete_entry(client, cur)
            gone = ds.find(client, name, a["sycope_url"], a["passthrough_name"])[0] is None
            res.add(label, "ok" if gone else "fail", "deleted from Sycope" if gone else "still in Sycope",
                    "" if gone else manual)
        for o in others:
            res.add(f"External Destination {(o.get('config') or {}).get('name')}", "warn",
                    "posts to the recorder's Passthrough but was not made by the installer: left alone",
                    "alert actions that use it fail once the recorder is gone: remove it in Sycope")
    except pt.PassthroughError as exc:
        res.add(label, "fail" if apply else "warn", str(exc), manual)


# ---- 2. The recorder stack ---------------------------------------------------------------------
def _mounted(path: str) -> bool:
    try:
        return any(line.split()[4] == path for line in open("/proc/self/mountinfo"))
    except (OSError, IndexError):
        return True  # cannot tell: treat as mounted, which keeps the volume


def _entries(d: str) -> int | None:
    try:
        return len(os.listdir(d))
    except OSError:
        return None


def remove_volumes(ctx, res: Result, project: str, apply: bool) -> None:
    """The project's Docker volumes. A volume bound to a host directory (the PCAPs) is removed only when no
    container uses it and its mount point is not mounted, and the directory is checked before and after."""
    import json

    rc, out = ctx.r.probe(["docker", "volume", "ls", "-q", "--filter", f"label=com.docker.compose.project={project}"])
    for vol in (out.split() if rc == 0 else []):
        info = {}
        rc, raw = ctx.r.probe(["docker", "volume", "inspect", vol])
        try:
            info = json.loads(raw)[0] if rc == 0 else {}
        except (ValueError, IndexError):
            pass
        device = (info.get("Options") or {}).get("device")
        mount = info.get("Mountpoint") or os.path.join(DOCKER_VOLUMES, vol, "_data")
        users = ctx.r.probe(["docker", "ps", "-aq", "--filter", f"volume={vol}"])[1].split()
        if device and (users or _mounted(mount)):
            res.add(f"volume {vol}", "warn", f"kept: bound to {device} and still in use",
                    f"stop what uses it, then docker volume rm {vol} (the files in {device} stay)")
            continue
        if not apply:
            res.add(f"volume {vol}", "skip", "would remove it" + (f" (only the link to {device}: its files stay)" if device else ""))
            continue
        before = _entries(device) if device else None
        ctx.r.run(["docker", "volume", "rm", vol])
        after = _entries(device) if device else None
        if device and before != after and not ctx.dry:
            res.add(f"volume {vol}", "fail", f"{device} had {before} entries, now {after}",
                    "check the directory: Docker should not touch the files of a bind volume")
        else:
            res.add(f"volume {vol}", "ok", ("would remove" if ctx.dry else "removed")
                    + (f"; {device} and its files kept" if device else ""))


def _compose_down(ctx, res: Result, label: str, d: str, files: tuple[str, ...], project: str, apply: bool,
                  volumes: bool) -> bool:
    running = ctx.r.probe(["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={project}"])[1].split()
    if not running:
        return True
    if not apply:
        res.add(label, "skip", f"would stop and remove {len(running)} container(s) and the images built for them")
        return True
    flags = ["down", "--rmi", "local", "--remove-orphans"] + (["-v"] if volumes else [])
    have = all(os.path.exists(os.path.join(d, f)) for f in (".env", *files))
    if have:
        cmd = (f"cd {shlex.quote(d)} && docker compose --env-file .env "
               + " ".join(f"-f {shlex.quote(f)}" for f in files) + " " + " ".join(flags))
        rc, out = ctx.r.run(cmd, timeout=600)
    else:
        rc, out = 1, ""
    if rc != 0:  # the files are gone or no longer parse: by the project name
        rc, out = ctx.r.run(["docker", "compose", "-p", project, *flags], timeout=600)
    res.add(label, "ok" if rc == 0 else "fail", "containers stopped and removed" if rc == 0
            else "docker compose down failed: " + (out.strip()[-200:] or f"exit {rc}"),
            "" if rc == 0 else f"docker compose -p {project} down")
    return rc == 0


def _remove_release_dir(ctx, res: Result, label: str, d: str, apply: bool, keep: tuple[str, ...] = ()) -> None:
    """Remove a directory the installer copied a release into; the `keep` entries (an own certificate) stay."""
    if not os.path.isdir(d):
        return
    if _within(ctx.repo, d):
        res.add(label, "warn", f"{d} kept: the uninstaller runs from it", f"rm -rf {d} by hand afterwards")
        return
    if not os.path.isfile(os.path.join(d, st.DEPLOYED)):  # the installer's own marker, whatever the answers say
        res.add(label, "warn", f"{d} kept: no {st.DEPLOYED} record, so it is not a deployment of this installer",
                f"check what it holds and remove it by hand if it is not needed (rm -rf {d})")
        return
    kept = [k for k in keep if os.path.exists(os.path.join(d, k))]
    if not kept:
        remove(ctx, res, label, d, apply, recursive=True)
        return
    part = Result()
    for name in sorted(os.listdir(d)):
        if name not in kept:
            remove(ctx, part, label, os.path.join(d, name), apply, recursive=True)
    res.items += [i for i in part.items if i.status in ("warn", "fail")]
    res.add(label, "warn" if apply else "skip", f"{'removed' if apply else 'would remove'} {d}, except "
            + ", ".join(kept) + " (the operator's own certificate)", f"rm -rf {d} when the certificate is not needed")


def own_cert_dirs(d: str) -> tuple[str, ...]:
    """The top-level entries of `d` that hold the operator's own certificate (certs/, or caddy/certs/ of a 0.3
    stack): files the repository does not ship."""
    out = []
    for top, sub in (("certs", "certs"), ("caddy", os.path.join("caddy", "certs"))):
        try:
            if [f for f in os.listdir(os.path.join(d, sub)) if f not in ("README.md", ".gitkeep")]:
                out.append(top)
        except OSError:
            continue
    return tuple(out)


def part_stack(ctx, apply: bool) -> Result:
    res, a = Result(), ctx.a
    d = a.get("install_dir") or DEFAULT_INSTALL_DIR
    project = st._project_name(d)
    docker = ctx.r.probe(["docker", "version", "--format", "{{.Server.Version}}"])[0] == 0
    if docker:
        if not _compose_down(ctx, res, "recorder containers", d, ("compose.yaml", "compose.ntop.yaml"), project,
                             apply, volumes=False):
            return res
        remove_volumes(ctx, res, project, apply)
    elif os.path.isdir(d):
        res.add("recorder containers", "warn", "Docker does not answer: containers and volumes not checked")
    if os.path.isdir(d) and not (os.path.exists(os.path.join(d, "compose.yaml"))
                                 or os.path.exists(os.path.join(d, st.DEPLOYED))):
        res.add("install directory", "warn", f"{d} kept: it does not look like a recorder release")
    elif os.path.isdir(d):
        _remove_release_dir(ctx, res, "install directory", d, apply, keep=own_cert_dirs(d))
    if not res.items:
        res.add("recorder stack", "ok", "not installed")
    return res


# ---- 3. Triage ---------------------------------------------------------------------------------
def part_triage(ctx, apply: bool) -> Result:
    res, a = Result(), ctx.a
    d = a.get("triage_dir") or tg.DEFAULT_DIR
    project = st._project_name(d)
    if ctx.r.probe(["docker", "version", "--format", "{{.Server.Version}}"])[0] == 0:
        if not _compose_down(ctx, res, "Triage containers", d, ("compose.yaml", tg.LIMITS_FILE), project, apply,
                             volumes=True):
            return res
        remove_volumes(ctx, res, project, apply)  # what `down -v` did not reach (the files were gone)
    if os.path.isdir(d):
        if tg.is_release_dir(d) or os.path.exists(os.path.join(d, tg.DEPLOYED)):
            _remove_release_dir(ctx, res, "Triage directory", d, apply)
        else:
            res.add("Triage directory", "warn", f"{d} kept: it does not look like a Triage release")
    if not res.items:
        res.add("Triage", "ok", "not installed")
    return res


# ---- 4. n2disk, nProbe, capture NIC, PF_RING ---------------------------------------------------
def part_n2disk(ctx, apply: bool) -> Result:
    res = Result()
    ext = legacy.find_external_n2disk(ctx.r)
    ctx.extra["uninstall_external_n2disk"] = ext
    if ext:
        res.add("adopted n2disk", "ok", f"not touched: {legacy.describe(ext)} runs outside the installer "
                "(unit, configuration, package and PF_RING stay)")
    for iface in interfaces(ctx):
        stop_unit(ctx, res, f"n2disk@{iface}.service", apply)
        path = os.path.join(st.N2DISK_CONF_DIR, f"n2disk-{iface}.conf")
        text = _read(path)
        if text is None:
            continue
        if text.startswith(st.MARKER):
            remove(ctx, res, f"n2disk config {iface}", path, apply)
        else:
            res.add(f"n2disk config {iface}", "warn", f"{path} kept: edited by hand")
    for name in ("10-recorder.conf", "20-tuning.conf"):
        remove(ctx, res, "n2disk drop-in", os.path.join(st.SYSTEMD_DIR, "n2disk@.service.d", name), apply)
    _rmdir_empty(ctx, os.path.join(st.SYSTEMD_DIR, "n2disk@.service.d"), apply)
    baks = glob.glob(os.path.join(st.N2DISK_CONF_DIR, "n2disk-*.conf.bak*"))
    if baks:
        res.add("earlier n2disk configs", "ok", f"kept ({len(baks)} .bak file(s) in {st.N2DISK_CONF_DIR}): "
                "they are the operator's earlier configurations")
    if not res.items:
        res.add("n2disk", "ok", "nothing of the installer's")
    return res


def part_nprobe(ctx, apply: bool) -> Result:
    res = Result()
    confs = np_.managed_confs()
    if confs:
        ctx.extra["had_nprobe_confs"] = True  # the packages part runs after the files are gone
    for name, path in sorted(confs.items()):
        stop_unit(ctx, res, f"nprobe@{name}.service", apply)
        remove(ctx, res, f"nProbe config {name}", path, apply)
    for name in ("10-recorder.conf", "20-tuning.conf"):
        remove(ctx, res, "nProbe drop-in", os.path.join(st.SYSTEMD_DIR, "nprobe@.service.d", name), apply)
    _rmdir_empty(ctx, os.path.join(st.SYSTEMD_DIR, "nprobe@.service.d"), apply)
    if not res.items:
        res.add("nProbe", "ok", "nothing of the installer's")
    return res


def part_capture(ctx, apply: bool) -> Result:
    res = Result()
    for iface in interfaces(ctx):
        stop_unit(ctx, res, f"recorder-capture-tune@{iface}.service", apply)
        stop_unit(ctx, res, f"recorder-capture-nic@{iface}.service", apply)
    for path in (os.path.join(st.SYSTEMD_DIR, tu.TUNE_UNIT_NAME), os.path.join(st.SYSTEMD_DIR, "recorder-capture-nic@.service"),
                 tu.IRQ_SPREAD_PATH, tu.SYSCTL_PATH):
        remove(ctx, res, os.path.basename(path), path, apply)
    _daemon_reload(ctx, apply)
    if res.items:
        res.add("NIC and kernel settings", "ok", "offloads, RX ring, interrupt spread and sysctl values stay as they are "
                "until the next reboot")
    else:
        res.add("capture NIC", "ok", "nothing of the installer's")
    return res


def part_pf_ring(ctx, apply: bool) -> Result:
    res = Result()
    if ctx.extra.get("uninstall_external_n2disk"):
        return res.add("PF_RING", "ok", "not touched: the adopted n2disk may use it")
    start = os.path.join(os.path.dirname(st.PF_RING_CONF), "pf_ring.start")
    if not os.path.exists(start):
        return res.add("PF_RING", "ok", "not set up by the installer")
    try:
        users = [f for f in os.listdir(os.path.join(st.PF_RING_PROC, "stats"))]
    except OSError:
        users = []
    if users and not apply:
        return res.add("PF_RING", "skip", f"would stop pf_ring once n2disk and nProbe are stopped ({len(users)} socket(s) now)")
    if users:
        return res.add("PF_RING", "warn", f"kept: {len(users)} socket(s) still use it ({', '.join(users[:3])})",
                       "stop what captures with it, then run the uninstaller again")
    stop_unit(ctx, res, "pf_ring.service", apply)
    remove(ctx, res, "pf_ring.start", start, apply)
    if (_read(st.PF_RING_CONF) or "").strip() == st.PF_RING_SLOTS:
        remove(ctx, res, "pf_ring.conf", st.PF_RING_CONF, apply)
    _rmdir_empty(ctx, os.path.dirname(st.PF_RING_CONF), apply)
    return res


def part_licence_inbox(ctx, apply: bool) -> Result:
    res = Result()
    stop_unit(ctx, res, li.PATH_UNIT_NAME, apply)
    for path in (os.path.join(st.SYSTEMD_DIR, li.PATH_UNIT_NAME), os.path.join(st.SYSTEMD_DIR, li.SERVICE_UNIT_NAME),
                 st.TUI_PATH):
        remove(ctx, res, os.path.basename(path), path, apply)  # also the units of a release that ran the unpacked copy
    if _within(ctx.repo, st.INSTALLER_HOME):  # the copy the units and the menu ran
        res.add("installer copy", "warn", f"{st.INSTALLER_HOME} kept: the uninstaller runs from it",
                f"rm -rf {st.INSTALLER_HOME} by hand afterwards")
    else:
        remove(ctx, res, "installer copy", st.INSTALLER_HOME, apply, recursive=True)
    _daemon_reload(ctx, apply)
    if ctx.r.probe(["getent", "group", li.INBOX_GROUP])[0] == 0:
        if not apply:
            res.add(f"group {li.INBOX_GROUP}", "skip", "would remove it")
        else:
            rc, out = ctx.r.run(["groupdel", li.INBOX_GROUP])
            res.add(f"group {li.INBOX_GROUP}", "ok" if rc == 0 else "warn", "removed" if rc == 0 else out.strip()[-120:])
    if not res.items:
        res.add("licence inbox", "ok", "not set up")
    return res


def _rmdir_empty(ctx, d: str, apply: bool) -> None:
    if apply and os.path.isdir(d) and not os.listdir(d):
        ctx.r.run(["rmdir", d])


# ---- 5. Packages -------------------------------------------------------------------------------
def owns_licence(ctx, pkg: str) -> str | None:
    """A licence path the package lists as its own, or None: such a package is never removed."""
    out = ctx.r.probe(["dpkg-query", "-L", pkg])[1]
    return next((p for p in out.splitlines() if re.fullmatch(r"/etc/[^/]*\.license", p.strip())), None)


def simulate(ctx, verb: str, pkgs: list[str]) -> tuple[set[str] | None, str]:
    """The packages apt would remove for `apt-get <verb> pkgs` (None when the simulation fails)."""
    rc, out = ctx.r.probe(["apt-get", "-s", verb, *pkgs], env={"DEBIAN_FRONTEND": "noninteractive"}, timeout=120)
    if rc != 0:
        return None, out.strip()[-200:]
    return {m.group(1) for m in re.finditer(r"^(?:Remv|Purg) (\S+)", out, re.M)}, ""


def _apt_remove(ctx, res: Result, label: str, verb: str, pkgs: list[str], apply: bool) -> bool:
    if not pkgs:
        return True
    for p in pkgs:
        lic = owns_licence(ctx, p)
        if lic:
            res.add(label, "warn", f"not removed: the package {p} lists the licence {lic} as its own")
            return False
    would, err = simulate(ctx, verb, pkgs)
    if would is None:
        res.add(label, "warn", f"not removed: apt-get -s {verb} failed ({err})")
        return False
    extra = sorted(would - set(pkgs))
    if extra:
        res.add(label, "warn", f"not removed: apt would also remove {', '.join(extra)}",
                f"apt-get {verb} {' '.join(pkgs)} by hand if that is intended")
        return False
    if not apply:
        res.add(label, "skip", f"would {verb} {', '.join(pkgs)}")
        return True
    rc, out = ctx.r.run(["apt-get", verb, "-y", "-qq", *pkgs], env={"DEBIAN_FRONTEND": "noninteractive"})
    left = [p for p in pkgs if not ctx.dry and _pkg(ctx, p)]
    ok = rc == 0 and not left
    res.add(label, "ok" if ok else "fail", f"{'would ' + verb if ctx.dry else verb + 'd'}: {', '.join(pkgs)}" if ok
            else f"apt-get {verb} failed: " + (out.strip()[-200:] or ", ".join(left)))
    return ok


def part_packages(ctx, apply: bool) -> Result:
    res, a = Result(), ctx.a
    ext = ctx.extra.get("uninstall_external_n2disk")
    ours = []
    if not ext:
        ours += [p for p in ("n2disk", "pfring-dkms") if _pkg(ctx, p)]
    if st.probes(a) or ctx.extra.get("had_nprobe_confs") or np_.managed_confs():
        ours += [p for p in ("nprobe",) if _pkg(ctx, p)]
    if ours and not ext and _pkg(ctx, "pfring") and not any(_pkg(ctx, p) for p in OTHER_NTOP if p != "apt-ntop"):
        ours.append("pfring")
    if ext:
        res.add("n2disk package", "ok", "kept: the adopted n2disk uses it")
    removed = _apt_remove(ctx, res, "ntop packages", "remove", ours, apply)
    stays = [p for p in ("n2disk", "nprobe", "pfring", *OTHER_NTOP) if _pkg(ctx, p) and not (removed and p in ours)]
    if _pkg(ctx, NTOP_REPO_PACKAGE):
        if stays:
            res.add("ntop repository", "ok", f"kept: {', '.join(stays)} still installed")
        else:
            _apt_remove(ctx, res, "ntop repository", "purge", [NTOP_REPO_PACKAGE], apply)
    if _left_by_installer("/tmp/apt-ntop-stable.deb"):
        remove(ctx, res, "downloaded package", "/tmp/apt-ntop-stable.deb", apply)
    res.add("base packages", "ok", "kept (" + ", ".join(st.BASE_PACKAGES[:4]) + ", ...): other software may use them")
    if not ctx.extra.get("remove_docker"):
        res.add("Docker", "ok", "kept (--remove-docker removes it)")
        return res
    docker = [p for p in DOCKER_PACKAGES if _pkg(ctx, p)]
    if docker:
        others = other_containers(ctx)
        if others:
            res.add("Docker", "warn", f"kept: other containers on this host ({', '.join(others[:5])})", "docker ps -a")
            return res
        if _apt_remove(ctx, res, "Docker", "remove", docker, apply):
            if (_read(DOCKER_LIST) or "").startswith("deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com"):
                remove(ctx, res, "Docker repository", DOCKER_LIST, apply)
                remove(ctx, res, "Docker key", DOCKER_KEY, apply)
            res.add("Docker data", "ok", "/var/lib/docker (images, build cache) stays; rm -rf /var/lib/docker /var/lib/containerd frees it")
    return res


def other_containers(ctx) -> list[str]:
    """Containers that are not the recorder's or Triage's: Docker stays while there is any."""
    ours = {st._project_name(ctx.a.get("install_dir") or DEFAULT_INSTALL_DIR),
            st._project_name(ctx.a.get("triage_dir") or tg.DEFAULT_DIR)}
    rc, out = ctx.r.probe(["docker", "ps", "-a", "--format", '{{.Names}} {{.Label "com.docker.compose.project"}}'])
    rows = [line.split() for line in out.splitlines() if line.strip()] if rc == 0 else []
    return [r[0] for r in rows if len(r) < 2 or r[1] not in ours]


# ---- 6. The installer's own state --------------------------------------------------------------
def part_state(ctx, apply: bool) -> Result:
    res = Result()
    d = ctx.extra.get("state_dir") or STATE_DIR
    if not os.path.isdir(d):
        return res.add("installer state", "ok", "none")
    for name in sorted(os.listdir(d)):
        path = os.path.join(d, name)
        if name == os.path.basename(licence.BACKUP_ROOT):
            res.add("licence backups", "ok", f"kept: {path}")
        elif name in {os.path.basename(h) for h in LICENCE_HOLDERS}:
            if _holds_files(path):
                res.add(name, "ok", f"kept: {path} holds licence files")
            else:
                remove(ctx, res, name, path, apply, recursive=True)
        elif name.startswith("uninstall-"):
            continue  # reports of earlier uninstalls: the record of what was removed
        elif name in STATE_REMOVE or name.endswith(".tmp"):
            remove(ctx, res, name, path, apply, recursive=True)
        else:
            res.add(name, "warn", f"{path} kept: not something the installer writes")
    return res


PARTS = [
    ("sycope", "Sycope Passthrough", part_sycope),
    ("stack", "Recorder stack", part_stack),
    ("triage", "Sycope Triage", part_triage),
    ("n2disk", "n2disk", part_n2disk),
    ("nprobe", "nProbe", part_nprobe),
    ("capture", "Capture NIC and tuning", part_capture),
    ("pf_ring", "PF_RING", part_pf_ring),
    ("licence_inbox", "Licence inbox and menu", part_licence_inbox),
]
# After the licence guard (n2disk -V still exists): packages, then the installer's own files.
LATE_PARTS = [
    ("packages", "Packages", part_packages),
    ("state", "Installer state", part_state),
]


def licence_files_check(before: dict) -> list[tuple[str, str, str]]:
    """The licence files now against the snapshot of the start: content, owner, group, mode. Without n2disk -V
    (the package may be gone by now); the SystemID was checked by the guard before the packages went."""
    out = []
    for path, digest in before["files"].items():
        if not os.path.isfile(path):
            out.append(("fail", f"licence file {path}", "has disappeared"))
            continue
        s = os.stat(path)
        now = [s.st_uid, s.st_gid, s.st_mode & 0o7777]
        if licence.sha256_file(path) != digest:
            out.append(("fail", f"licence file {path}", "changed"))
        elif before.get("meta", {}).get(path) and list(before["meta"][path]) != now:
            out.append(("fail", f"licence file {path}", "owner/group/mode changed"))
    if not out:
        out.append(("ok", "licence files", f"{len(before['files'])} unchanged" if before["files"] else "none before, none touched"))
    return out
