"""nProbe on the capture NIC: flows to the Sycope collector (profiles full and probe-only).

nProbe and n2disk both open their own PF_RING socket on the capture NIC: the kernel module gives each
socket a full copy, so neither sees less because the other is there (it costs one more copy per packet
in softirq; see README_SIZING.md for where that stops scaling). With more than one nProbe instance the
instances join one PF_RING cluster (`--cluster-id`, type 4 = 5-tuple, the same for both directions) and
share the flows; n2disk never joins the cluster, so it still records every packet.

Sycope needs IPFIX with %L7_PROTO for the nDPI application (Sycope 2.6 and later).

The nProbe licence (/etc/nprobe.license) is bound to nProbe's own SystemID, which is not n2disk's. It
is installed like the n2disk one: never over a valid licence (unless --replace-licence), checked with
`nprobe --version` and rolled back when it is not valid. The licence backup and the guard at the end
of the run already cover it (they look at every /etc/*.license).
"""

from __future__ import annotations

import os
import re
import stat

from . import licence
from .report import Result

NPROBE_LICENCE = "/etc/nprobe.license"  # module constants, so that tests can point them elsewhere
NPROBE_CONF_DIR = "/etc/nprobe"
SYSTEMD_DIR = "/etc/systemd/system"
MARKER = "# Managed by the recorder installer."
CLUSTER_ID = 10  # PF_RING cluster of the nProbe instances; n2disk is not in it
COLLECTOR_PORT = 2055
# Unidirectional records (no OUT_ fields: nProbe then exports each direction as its own flow, as a router
# does), IPv4 and IPv6, VLAN and the nDPI application.
TEMPLATE = ("%IPV4_SRC_ADDR %IPV4_DST_ADDR %IPV6_SRC_ADDR %IPV6_DST_ADDR %INPUT_SNMP %OUTPUT_SNMP "
            "%IN_PKTS %IN_BYTES %FIRST_SWITCHED %LAST_SWITCHED %L4_SRC_PORT %L4_DST_PORT %TCP_FLAGS "
            "%PROTOCOL %SRC_TOS %SRC_VLAN %L7_PROTO")
ACTIVE_TIMEOUT = 60  # seconds: a long flow is exported at least this often
IDLE_TIMEOUT = 30
MAX_FLOWS = 1048576  # per instance; ~0.5-1 GB of RAM at the full table
DROPIN = """# Bounded restarts, like n2disk: after 5 failures in 10 min the unit stays failed (visible);
# fix the cause, then `systemctl reset-failed nprobe@<name>`.
[Unit]
StartLimitIntervalSec=600
StartLimitBurst=5

[Service]
Restart=on-failure
RestartSec=30
"""


# ---- licence ----------------------------------------------------------------------------------
def nprobe_info(r) -> dict:
    """SystemID and licence state from `nprobe --version`.

    `state` is "valid", "invalid" or "unknown", with the same meaning as for n2disk: unknown (nprobe
    missing, no answer, no SystemID or no License line) means "may be valid", and such a licence is
    never overwritten. Seen on 11.2 without a licence:
        SystemID:      XXXXXXXXXXXXXXXXX--OL
        License:       Invalid license (/etc/nprobe.license) [Missing license file ...]
    """
    rc, out = r.probe("nprobe --version 2>&1", timeout=licence.INFO_TIMEOUT)
    sysid = re.search(r"^SystemID:\s*(\S+)", out, re.M)
    lic = re.search(r"^License:\s*(.*)$", out, re.M)
    state = "unknown"
    if rc == 0 and sysid and lic:
        text = lic.group(1)
        if re.search(r"invalid|expired", text, re.I):
            state = "invalid"
        elif text.strip() and not re.search(r"demo", text, re.I):
            state = "valid"
    return {"system_id": sysid.group(1) if sysid else "", "state": state, "licensed": state == "valid",
            "installed": rc != 127, "raw": out if rc else ""}


def _read(path: str, mode: str = "r", **kw):
    """The whole content of `path`, the file closed again before it returns."""
    with open(path, mode, **kw) as fh:
        return fh.read()


def _restore(r, target: str, previous: bytes | None, owner: tuple[int, int, int] | None) -> str:
    try:
        if previous is None:
            if os.path.lexists(target):
                os.unlink(target)
            return ""
        if not os.path.exists(target) or _read(target, "rb") != previous:
            r.write(target, previous, owner[2] if owner else None)
        if owner:
            os.chown(target, owner[0], owner[1])
            os.chmod(target, owner[2])
        return ""
    except OSError as exc:
        return f"{type(exc).__name__}: {exc}"


def install_licence(ctx, res: Result, apply: bool) -> None:
    """The only code that writes the nProbe licence; the same rules as steps._install_licence for n2disk."""
    given, target, name = ctx.a.get("nprobe_license_file") or "", NPROBE_LICENCE, "nProbe licence file"
    if not given or not os.path.isfile(given):
        return
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
    before = nprobe_info(ctx.r)
    if current is not None and not ctx.extra.get("replace_licence"):
        if before["state"] == "valid":
            res.add(name, "warn", "a valid nProbe licence is installed; the given file was not installed",
                    "use --replace-licence to replace it")
            return
        if before["state"] == "unknown":
            res.add(name, "warn", "could not determine whether the installed nProbe licence is valid; not replaced",
                    "run nprobe --version by hand, or use --replace-licence")
            return
    if not apply:
        res.add(name, "warn", f"{given} is not installed yet", "run the installer to install it")
        return
    if ctx.dry:
        res.add(name, "skip", f"would install {given} as {target} (dry run)")
        return
    try:
        ctx.r.write(target, new, 0o644)
    except Exception as exc:
        failed = _restore(ctx.r, target, current, owner)
        res.add(name, "fail", f"could not write {target}: {type(exc).__name__}: {exc}"
                + (f"; the previous licence could not be put back ({failed})" if failed else ""))
        return
    after = nprobe_info(ctx.r)
    if after["state"] == "valid":
        ctx.extra.setdefault("licence_written", {})[target] = licence.sha256_file(target)
        res.add(name, "ok", f"installed {given} as {target}")
        return
    failed = _restore(ctx.r, target, current, owner)
    sysid = after["system_id"] or before["system_id"] or "unknown"
    verdict = (f"the given licence is not valid for nProbe SystemID {sysid}" if after["state"] == "invalid"
               else "the given licence could not be verified (nprobe --version gave no answer)")
    if failed:
        res.add(name, "fail", f"{verdict} and the previous one could not be restored ({failed})")
    else:
        res.add(name, "fail", f"{verdict}; " + ("the previous licence was restored" if current is not None else "it was not kept"),
                f"ask ntop for an nProbe licence for SystemID {sysid}")


# ---- configuration ----------------------------------------------------------------------------
def instances(a: dict) -> int:
    return int(a.get("nprobe_instances") or 1)


def instance_names(a: dict) -> list[str]:
    """Unit instance names: the NIC for one instance, <nic>-1..N for more (the conf is nprobe-<name>.conf)."""
    iface, n = a["capture_iface"], instances(a)
    return [iface] if n == 1 else [f"{iface}-{i}" for i in range(1, n + 1)]


def collector(a: dict) -> str:
    c = a["collector"]
    return c if re.search(r":\d+$", c) else f"{c}:{COLLECTOR_PORT}"


def conf(a: dict, index: int) -> str:
    """The config of instance `index` (1-based)."""
    lines = [MARKER,
             f"--interface={a['capture_iface']}",
             f"--collector={collector(a)}",
             "--flow-version=10",
             f'--flow-templ="{a.get("nprobe_template") or TEMPLATE}"',
             f"--lifetime-timeout={a.get('nprobe_active_timeout') or ACTIVE_TIMEOUT}",
             f"--idle-timeout={a.get('nprobe_idle_timeout') or IDLE_TIMEOUT}",
             f"--max-num-flows={a.get('nprobe_max_flows') or MAX_FLOWS}",
             # IPFIX observation domain: instances that export from the same address must not share it
             f"--netflow-engine=0:{index}"]
    if instances(a) > 1:
        lines += ["# The instances share the flows of one PF_RING cluster (5-tuple, both directions to one instance).",
                  f"--cluster-id={CLUSTER_ID}", "--cluster-type=4"]
    return "\n".join(lines) + "\n"


def managed_confs() -> dict[str, str]:
    """name -> path of every nProbe config this installer wrote (any NIC, any count)."""
    out = {}
    try:
        names = sorted(os.listdir(NPROBE_CONF_DIR))
    except OSError:
        return out
    for f in names:
        m = re.fullmatch(r"nprobe-(.+)\.conf", f)
        p = os.path.join(NPROBE_CONF_DIR, f)
        if m and os.path.isfile(p):
            try:
                if _read(p).startswith(MARKER):
                    out[m.group(1)] = p
            except OSError:
                pass
    return out
