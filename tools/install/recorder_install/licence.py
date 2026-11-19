"""The n2disk licence is the one thing on the host the installer must never lose or damage.

A licence is bound to the SystemID n2disk derives from the management NIC, and the vendor needs
time to issue another. So the installer looks at the licence files before it does anything
(`snapshot`), keeps a private copy of them (`backup`, never deleted or rotated), changes them only
through the one guarded path in `steps.step_n2disk`, and compares the state at the end (`compare`).
Everything here is read-only except `backup`, which writes only under BACKUP_ROOT.

The paths are module constants so that tests can point them into a temporary directory.
"""

from __future__ import annotations

import glob
import grp
import hashlib
import json
import os
import pwd
import re
import shlex
import stat
import time
from datetime import datetime

from .system import Runner

LICENCE_GLOB = "/etc/*.license"  # n2disk, nprobe, ...
N2DISK_LICENCE = "/etc/n2disk.license"
BACKUP_ROOT = "/var/lib/sycope-recorder-installer/licence-backup"
# `n2disk -V` can abort or hang for a while right after n2disk was restarted or the host was busy
# building: an unknown answer is asked again before it is believed (tests patch these).
INFO_TRIES = 6
INFO_DELAY = 5.0
INFO_TIMEOUT = 60


class BackupError(Exception):
    """The licence backup could not be made or does not match its source: the run must stop."""


# The n2disk package ships one binary per licence edition: `n2disk` (10/40/100G), `n2disk5g`, `n2disk1g` (and
# links). A licence is valid only for its own binary; asked with another one, n2disk answers "Invalid license"
# and, in the versions seen, names the right one ("PLEASE USE THE n2disk1g BINARY"). ntop's n2disk@.service picks
# the binary the same way before each start (n2disk1g/n2disk5g --check-license), so the installer only has to
# judge the licence with the right binary. Only these names are ever run.
BINARIES = ("n2disk", "n2disk5g", "n2disk1g", "n2disk10g", "n2disknt")
EDITION_BINARIES = ("n2disk5g", "n2disk1g")  # asked when `n2disk` itself says invalid
_USE = re.compile(r"PLEASE USE THE (\S+) BINARY", re.I)


def _verdict(rc: int, out: str) -> tuple[str, str]:
    """(SystemID, state) of one `<binary> -V` answer: see n2disk_info."""
    sysid = re.search(r"^SystemID:\s*(\S+)", out, re.M)
    lic = re.search(r"^License:(.*)$", out, re.M)  # a valid key continues on the following lines
    state = "unknown"
    if rc == 0 and sysid and lic:
        if "Invalid" in lic.group(1):
            state = "invalid"
        elif re.search(r"^License Type:", out, re.M):
            state = "valid"
    return (sysid.group(1) if sysid else ""), state


def _edition(out: str) -> str:
    m = re.search(r"^Edition:\s*(.+?)\s*$", out, re.M)
    return m.group(1) if m else ""


def n2disk_info(r: Runner, tries: int = 1) -> dict:
    """SystemID and licence state as `n2disk -V` reports them (the one parser of that output).

    `state` is "valid", "invalid" or "unknown". Valid: rc 0, a SystemID, a `License Type:` line and no
    "Invalid" on the `License:` line. Invalid: rc 0, a SystemID and "Invalid license" on the `License:`
    line. Anything else (n2disk missing, SIGABRT, timeout, no SystemID, no License line) is unknown:
    the caller must then treat the licence as possibly valid and leave it alone. `licensed` is True
    only for "valid". An unknown answer is asked again up to `tries` times, INFO_DELAY seconds apart
    (a timeout, rc 124, is retried like any unknown answer; a command that does not exist, rc 127, is not); `tries` in the result says how many it took.

    When `n2disk` says invalid, the licence may be one of a smaller edition: the binary n2disk names
    and then the other edition binaries are asked once each, and the first valid answer wins (`binary`,
    `edition`). If the binary n2disk named gives no answer, the state is unknown: a licence that may be
    valid is never called invalid.
    """
    n = 0
    while True:
        n += 1
        # Through a shell: called directly (an argument list) n2disk -V aborts with SIGABRT on some
        # hosts; the same command line through sh works.
        rc, out = r.probe("n2disk -V 2>&1", timeout=INFO_TIMEOUT)
        sysid, state = _verdict(rc, out)
        if state != "unknown" or rc == 127 or n >= tries:
            break
        time.sleep(INFO_DELAY)
    binary, edition, raw = "n2disk", _edition(out), (out if rc else "")
    if state == "invalid":
        m = _USE.search(out)
        named = m.group(1) if m and m.group(1) in BINARIES and m.group(1) != "n2disk" else None
        for b in ([named] if named else []) + [b for b in EDITION_BINARIES if b != named]:
            rc2, out2 = r.probe(f"{b} -V 2>&1", timeout=INFO_TIMEOUT)
            sysid2, state2 = _verdict(rc2, out2)
            if state2 == "valid":
                state, binary, edition, sysid = "valid", b, _edition(out2), sysid2 or sysid
                break
            if b == named and state2 == "unknown":
                state = "unknown"  # n2disk said this binary is the right one, and it did not answer
                break
    return {"system_id": sysid, "state": state, "licensed": state == "valid",
            "binary": binary if state == "valid" else "", "edition": edition if state == "valid" else "",
            "raw": raw, "tries": n}


def sha256_file(path: str) -> str:
    """Content hash of a file; reading follows a symlink on purpose (the licence is its content)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def snapshot(r: Runner, tries: int | None = None) -> dict:
    """What the licence looks like now: file hashes, SystemID and validity. Read-only.

    A licence file that cannot be read raises OSError: the caller must treat "cannot see the
    licence" as a reason to stop, never as "no licence".
    """
    paths = [p for p in sorted(glob.glob(LICENCE_GLOB)) if os.path.isfile(p)]
    files = {p: sha256_file(p) for p in paths}
    meta = {}
    for p in paths:
        st = os.stat(p)
        meta[p] = [st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)]
    info = n2disk_info(r, tries=INFO_TRIES if tries is None else tries)  # read at call time: tests patch the constant
    return {"files": files, "meta": meta, "system_id": info["system_id"], "n2disk_valid": info["licensed"],
            "n2disk_state": info["state"], "n2disk_tries": info["tries"], "n2disk_binary": info["binary"]}


def latest_backup() -> str | None:
    """The newest backup directory (names are timestamps, so the last in sort order), or None."""
    try:
        names = sorted(n for n in os.listdir(BACKUP_ROOT) if os.path.isdir(os.path.join(BACKUP_ROOT, n)))
    except OSError:
        return None
    return os.path.join(BACKUP_ROOT, names[-1]) if names else None


def _hashes_in(directory: str) -> dict[str, str]:
    """name -> sha256 of the licence files in a backup directory (system-id.txt is not one)."""
    try:
        return {n: sha256_file(os.path.join(directory, n)) for n in sorted(os.listdir(directory))
                if n.endswith(".license") and os.path.isfile(os.path.join(directory, n))}
    except OSError:
        return {}


def _name_or_empty(lookup, ident: int) -> str:
    """The user or group name of a numeric id, or "" when this host does not know it."""
    try:
        return lookup(ident)
    except KeyError:
        return ""


def _meta_for(snap: dict, path: str) -> dict:
    """Owner, group (ids and names) and mode of one licence file, as the snapshot saw it."""
    uid, gid, mode = snap.get("meta", {}).get(path) or _stat_meta(path)
    return {"uid": uid, "gid": gid, "mode": f"{mode:04o}",
            "owner": _name_or_empty(lambda i: pwd.getpwuid(i).pw_name, uid),
            "group": _name_or_empty(lambda i: grp.getgrgid(i).gr_name, gid)}


def _stat_meta(path: str) -> list[int]:
    """[uid, gid, mode] of a file now (for snapshots that did not record it)."""
    st = os.stat(path)
    return [st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)]


def _meta_in(directory: str) -> dict:
    """The meta.json of a backup directory ({} when there is none or it is unreadable)."""
    try:
        with open(os.path.join(directory, "meta.json")) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _fsync_dir(path: str) -> None:
    """Make a new directory entry durable: a backup that is lost in a crash is no backup."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _new_dir(stamp: str) -> str:
    """Create BACKUP_ROOT/<stamp> (0700), or <stamp>-N when that name is taken. Never reuses a name."""
    if os.path.islink(BACKUP_ROOT):
        raise BackupError(f"{BACKUP_ROOT} is a symlink")
    os.makedirs(BACKUP_ROOT, mode=0o700, exist_ok=True)
    for n in range(100):
        path = os.path.join(BACKUP_ROOT, stamp if n == 0 else f"{stamp}-{n}")
        try:
            os.mkdir(path, 0o700)  # fails on an existing name, also on a symlink planted there
        except FileExistsError:
            continue
        os.chmod(path, 0o700)  # the umask may have cut it
        return path
    raise BackupError(f"no free backup name under {BACKUP_ROOT}")


def _copy_private(src: str, dst: str) -> None:
    """Copy a file to a new 0600 file; O_EXCL|O_NOFOLLOW so nothing is overwritten or followed."""
    with open(src, "rb") as fh:
        data = fh.read()
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
    os.chmod(dst, 0o600)


def backup(r: Runner, snap: dict, now: datetime) -> str | None:
    """Copy every licence file of `snap` to BACKUP_ROOT/<YYYYmmdd-HHMMSS>/ with system-id.txt.

    Returns the directory, or None when there is nothing to do: no licence files, a dry run, or the
    newest existing backup already has exactly these files and hashes. Raises BackupError when the
    copy fails or does not match the snapshot. Nothing under BACKUP_ROOT is ever deleted or rotated.
    """
    if r.read_only:
        raise RuntimeError("refusing to write a licence backup in check mode")
    files = snap["files"]
    if r.dry or not files:
        return None
    wanted = {os.path.basename(p): h for p, h in files.items()}
    metas = {os.path.basename(p): _meta_for(snap, p) for p in files}
    newest = latest_backup()
    if newest and _hashes_in(newest) == wanted and _meta_in(newest) == metas:
        return None
    try:
        directory = _new_dir(now.strftime("%Y%m%d-%H%M%S"))
        for path, digest in files.items():
            dst = os.path.join(directory, os.path.basename(path))
            _copy_private(path, dst)
            if sha256_file(dst) != digest:  # the source changed since the snapshot, or the copy is bad
                raise BackupError(f"{path} does not match its snapshot")
        _copy_private_text(os.path.join(directory, "system-id.txt"),
                           f"{snap['system_id']}\nstate: {_state(snap)}\n")
        _copy_private_text(os.path.join(directory, "meta.json"), json.dumps(metas, indent=2, sort_keys=True) + "\n")
        _fsync_dir(directory)
    except OSError as exc:
        raise BackupError(f"{type(exc).__name__}: {exc}") from exc
    return directory


def _copy_private_text(dst: str, text: str) -> None:
    """Write a new 0600 text file with the same O_EXCL|O_NOFOLLOW protection as the licence copies."""
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as out:
        out.write(text)
        out.flush()
        os.fsync(out.fileno())
    os.chmod(dst, 0o600)


_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\.license")  # a plain basename: no slash, no leading dot
_SAFE_MODE = re.compile(r"0?[0-7]{3,4}")
_SAFE_ID = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]*")  # a user/group name or a numeric id
# all matched with fullmatch: `$` would let a trailing newline through


def restore_command(backup_dir: str) -> str:
    """The shell line an operator runs to put the backed up licence files back, as they were.

    One `install -m <mode> -o <owner> -g <group> <backup file> <target>` per file, joined with `&&`.
    meta.json (every backup since the owner/mode was recorded) supplies mode, owner and group; a file
    without a valid entry, or a backup without meta.json, is restored 0644 root:root. A name that this
    host does not know is replaced by the numeric id. The directory listing and meta.json are untrusted
    data: only plain `*.license` basenames are used, mode/owner/group must look plain, and every dynamic
    part is shell-quoted. When no file survives that, the answer says so instead of naming a command.
    """
    target = os.path.dirname(LICENCE_GLOB)
    meta = _meta_in(backup_dir)
    try:
        names = sorted(n for n in os.listdir(backup_dir) if _SAFE_NAME.fullmatch(n))
    except OSError:
        names = []
    if not names:
        return f"nothing to restore: no valid *.license file in {shlex.quote(backup_dir)}"
    lines = []
    for name in names:
        m = meta.get(name) if isinstance(meta.get(name), dict) else {}
        owner = m.get("owner") or (m.get("uid") if isinstance(m.get("uid"), int) else "")
        group = m.get("group") or (m.get("gid") if isinstance(m.get("gid"), int) else "")
        owner, group, mode = str(owner), str(group), str(m.get("mode", ""))
        if not (_SAFE_ID.fullmatch(owner) and _SAFE_ID.fullmatch(group) and _SAFE_MODE.fullmatch(mode)):
            owner, group, mode = "root", "root", "0644"  # missing or invalid entry: the safe default
        lines.append(f"install -m {shlex.quote(mode)} -o {shlex.quote(owner)} -g {shlex.quote(group)} "
                     f"{shlex.quote(os.path.join(backup_dir, name))} {shlex.quote(os.path.join(target, name))}")
    return " && ".join(lines)


def _state(snap: dict) -> str:
    """valid | invalid | unknown of a snapshot (older shapes only had the boolean)."""
    return snap.get("n2disk_state") or ("valid" if snap["n2disk_valid"] else "invalid")


def compare(before: dict, after: dict, written: dict[str, str], backup_dir: str | None) -> list[tuple[str, str, str, str]]:
    """Judge the licence at the end of a run against the start: a list of (status, name, detail, hint).

    `written` maps the paths step_n2disk installed (and verified) in this run to the hash it wrote:
    only those may differ in content, owner, group or mode. Anything else that changed or vanished is a
    failure carrying the restore command, as is a licence that was valid and is now invalid. A licence
    that was valid and whose validity cannot be read now (n2disk -V gave no answer) is only a warning:
    the files are intact, the check is what failed.
    """
    fix = (f"restore the licence from the backup taken at the start: {restore_command(backup_dir)}"
           if backup_dir else "no licence file existed at the start, so there is nothing to restore")
    out: list[tuple[str, str, str, str]] = []
    b_files, a_files = before["files"], after["files"]
    b_state, a_state = _state(before), _state(after)
    if before["system_id"] and after["system_id"] != before["system_id"]:
        if after["system_id"] or a_state != "unknown":
            out.append(("fail", "SystemID", f"was {before['system_id']}, now {after['system_id'] or 'unreadable'}", fix))
        else:
            out.append(("warn", "SystemID", f"was {before['system_id']}, could not be read now (n2disk -V gave no answer)", fix))
    if b_state == "valid" and a_state == "invalid":
        out.append(("fail", "n2disk licence", "was valid, is no longer valid", fix))
    elif b_state == "valid" and a_state == "unknown":
        out.append(("warn", "n2disk licence", "was valid; its validity could not be determined at the end "
                    "(n2disk -V gave no answer)", "run n2disk -V by hand; " + fix))
    for path, digest in b_files.items():
        if path not in a_files:
            out.append(("fail", f"licence file {path}", "has disappeared", fix))
        elif a_files[path] != digest and written.get(path) != a_files[path]:
            out.append(("fail", f"licence file {path}", "changed, and not by the licence step of this run", fix))
        elif path in written:
            continue  # the licence step set its owner and mode on purpose
        elif before.get("meta", {}).get(path) and after.get("meta", {}).get(path) \
                and before["meta"][path] != after["meta"][path]:
            was, now = before["meta"][path], after["meta"][path]
            out.append(("fail", f"licence file {path}", f"owner/group/mode changed from {was[0]}:{was[1]} {was[2]:o} "
                        f"to {now[0]}:{now[1]} {now[2]:o}", fix))
    for path in a_files:
        if path not in b_files and written.get(path) != a_files[path]:
            out.append(("warn", f"licence file {path}", "appeared during the run (not installed by the licence step)",
                        "check where it came from; the installer left it as it is"))
    if any(i[0] == "fail" for i in out):
        return out
    sid = after["system_id"] or before["system_id"] or "unknown"
    installed = [p for p in a_files if p in written and b_files.get(p) != a_files[p]]
    if installed and a_state == "valid":
        out.insert(0, ("ok", "licence", f"installed by this run and valid for SystemID {sid}", ""))
    elif not a_files and not b_files:
        out.insert(0, ("ok", "licence", "no licence before, none after (nothing was lost)", ""))
    elif a_state == "valid":
        out.insert(0, ("ok", "licence", f"licence unchanged and valid for SystemID {sid}", ""))
    elif a_state == "unknown" and b_state == "unknown":
        out.insert(0, ("ok", "licence", "licence files unchanged; n2disk -V gave no answer before or after, so validity "
                       "is unknown", ""))
    elif a_state == "unknown":
        out.insert(0, ("warn", "licence", "licence files unchanged, but n2disk -V gave no answer at the end",
                       "run n2disk -V by hand"))
    else:
        out.insert(0, ("warn", "licence", f"licence files unchanged, but not valid for SystemID {sid} "
                       "(they were not valid at the start either)", "install a licence issued for this SystemID"))
    return out
