"""Licences delivered after the installation: `install.sh --licence [file ...]` and the inbox.

The customer gets the ntop licences after the host exists (they are bound to its SystemIDs), so a licence
must be easy to bring in later and must still go through the one guarded path: the backup taken at the
start, `steps._install_licence` / `nprobe.install_licence` (never over a valid licence without
--replace-licence, verified by the product, rolled back when invalid) and the guard at the end.

Ways in, all ending here:
- `install.sh --licence n2disk.license nprobe.license` (explicit files);
- the inbox: a file copied into INBOX (`scp` by a member of the group INBOX_GROUP) is picked up by the
  path unit `sycope-licence-inbox.path`, which runs `install.sh --licence --yes`;
- `sycope-licence`, the console menu, which writes a pasted key into the inbox and runs the same.

A file's product comes from its name (`n2disk...` or `nprobe...`, as ntop sends them). Every processed
file is moved out of the inbox (to DONE or REJECTED with a time stamp), never deleted. Only regular
files up to MAX_SIZE are read, without following symlinks: the inbox is writable by a group.
"""

from __future__ import annotations

import os
import re
import socket
import stat
import time

from . import licence
from . import nprobe as np_

INBOX = "/var/lib/sycope-recorder-installer/inbox"
DONE = "/var/lib/sycope-recorder-installer/licence-done"
REJECTED = "/var/lib/sycope-recorder-installer/licence-rejected"
REQUEST = "/var/lib/sycope-recorder-installer/licence-request.txt"
INBOX_GROUP = "sycope-licence"
MAX_SIZE = 64 * 1024
PATH_UNIT_NAME = "sycope-licence-inbox.path"
SERVICE_UNIT_NAME = "sycope-licence-inbox.service"


def product_of(name: str) -> str | None:
    """'n2disk' or 'nprobe' from a file name, or None."""
    low = os.path.basename(name).lower()
    if "n2disk" in low:
        return "n2disk"
    if "nprobe" in low:
        return "nprobe"
    return None


def read_candidate(path: str) -> tuple[bytes | None, str]:
    """(content, "") of a regular file up to MAX_SIZE that is not a symlink, or (None, reason)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    except OSError as exc:
        return None, f"cannot open ({exc.strerror})"
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None, "not a regular file"
        if info.st_size > MAX_SIZE or info.st_size == 0:
            return None, f"size {info.st_size} bytes (a licence is a short text)"
        data = os.read(fd, MAX_SIZE + 1)
    finally:
        os.close(fd)
    if not re.fullmatch(rb"[\x20-\x7e\r\n\t]+", data):
        return None, "not plain text"
    return data, ""


def inbox_files() -> list[str]:
    try:
        names = sorted(os.listdir(INBOX))
    except OSError:
        return []
    return [os.path.join(INBOX, n) for n in names if not n.startswith(".")]


def staged_copy(content: bytes, product: str, stamp: str) -> str:
    """A root-only copy of a candidate: what is installed is what was checked, whatever happens in the inbox."""
    d = os.path.join(DONE, ".staging")
    os.makedirs(d, mode=0o700, exist_ok=True)
    path = os.path.join(d, f"{stamp}-{product}.license")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(content)
    return path


def file_away(path: str, ok: bool, stamp: str) -> str:
    """Move an inbox file to DONE or REJECTED (never delete); returns the new path, or "" if it could not."""
    if not os.path.dirname(os.path.abspath(path)) == os.path.abspath(INBOX):
        return ""  # an explicit file elsewhere: the operator's own copy stays where it is
    target_dir = DONE if ok else REJECTED
    os.makedirs(target_dir, mode=0o700, exist_ok=True)
    target = os.path.join(target_dir, f"{stamp}-{os.path.basename(path)}")
    try:
        os.replace(path, target)
        return target
    except OSError:
        return ""


def request_text(n2disk: dict, nprobe: dict, host: str | None = None) -> str:
    """The text to send to ntop (or Sycope support) for licences of this host."""
    lines = [f"Licence request for host {host or socket.gethostname()} ({time.strftime('%Y-%m-%d')})", ""]
    for name, info, cmd in (("n2disk", n2disk, "n2disk -V"), ("nProbe", nprobe, "nprobe --version")):
        if not info.get("installed", True) and not info.get("system_id"):
            continue
        state = {"valid": "licensed", "invalid": "no valid licence", "unknown": "state unknown"}[info["state"]]
        lines.append(f"{name:<7} SystemID: {info['system_id'] or '(not readable: run ' + cmd + ')'}   [{state}]")
    lines += ["", "Each product needs its own licence for its own SystemID. Send the keys back as files named",
              "n2disk.license and nprobe.license."]
    return "\n".join(lines) + "\n"


def n2disk_state(r) -> dict:
    info = licence.n2disk_info(r)
    return {**info, "installed": bool(info["system_id"]) or info["state"] != "unknown"}


def nprobe_state(r) -> dict:
    return np_.nprobe_info(r)


PATH_UNIT = f"""[Unit]
Description=Install ntop licences dropped into {INBOX}

[Path]
DirectoryNotEmpty={INBOX}
MakeDirectory=yes
DirectoryMode=2770

[Install]
WantedBy=multi-user.target
"""


def service_unit(install_sh: str) -> str:
    return f"""[Unit]
Description=Install ntop licences from {INBOX}

[Service]
Type=oneshot
ExecStart={install_sh} --licence --yes
"""
