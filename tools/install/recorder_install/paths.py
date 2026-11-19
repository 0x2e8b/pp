"""The directory answers (install, rolling, alerts, Triage) and what the installer may delete in them.

The installer runs as root: it syncs a release into the install directory with `rsync --delete`, chowns the
rolling directory, and the uninstaller removes the install directories recursively. A typo in an answer
(`/home/user`, `/var/lib`, the PCAP directory) must not reach any of that, so:

* `problem()` checks one answer: an absolute, normalised path of plain characters, not a system or home
  directory, and not the same as, inside or around the other directories (compared with symlinks resolved).
* `foreign()` is the guard right before a destructive sync: it says why a directory is not one the
  installer may overwrite (it exists, holds files and is not recognisably its own deployment).

Pure functions over the file system (read only), so that they can be tested on temporary directories.
"""

from __future__ import annotations

import os
import pwd
import re

# Plain path characters only: the paths go into .env files, n2disk's configuration and command lines.
_SAFE = re.compile(r"/[A-Za-z0-9._+/-]*")
# Nothing the installer manages lives inside these.
NOT_UNDER = ("/proc", "/sys", "/dev", "/run", "/boot", "/etc", "/bin", "/sbin", "/lib", "/lib32", "/lib64",
             "/libx32", "/tmp", "/var/tmp", "/lost+found", "/snap")
# Top-level directories of the system: never an answer themselves (their sub-directories may be).
SYSTEM_TOP = ("/home", "/media", "/mnt", "/opt", "/root", "/srv", "/usr", "/var")
# /usr/local, /var/lib and the like are system directories too: a directory of its own goes one level deeper.
TWO_DEEP = ("/usr", "/var")


def within(path: str, root: str) -> bool:
    """`path` is `root` or inside it (both already resolved)."""
    return path == root or path.startswith(root.rstrip("/") + "/")


def _homes() -> set[str]:
    out = {"/root"}
    try:
        out |= {os.path.normpath(p.pw_dir) for p in pwd.getpwall() if p.pw_dir not in ("", "/")}
    except OSError:
        pass
    return out


def system_reason(path: str, top_level_ok: bool = False) -> str | None:
    """Why `path` (absolute, normalised) is a system or home directory, or None."""
    if path == "/":
        return "the root directory"
    for root in NOT_UNDER:
        if within(path, root):
            return f"inside {root}, a system directory"
    parts = path.strip("/").split("/")
    if len(parts) == 1 and (not top_level_ok or path in SYSTEM_TOP):
        return f"{path} is a top-level directory: use a directory of its own below it"
    if len(parts) == 2 and "/" + parts[0] in TWO_DEEP:
        return f"{path} is a system directory: use a directory of its own below it"
    if (len(parts) == 2 and parts[0] == "home") or path in _homes():
        return f"{path} is a home directory: use a directory of its own inside it"
    return None


def problem(value: str, others: list[tuple[str, str | None, bool]] | tuple = (), top_level_ok: bool = False) -> str | None:
    """Why `value` is not acceptable as one of the installer's directories, or None.

    `others` are (label, path, same_ok): directories it must be neither inside of nor contain, nor equal unless
    `same_ok`. The checks run on the path as given and on the path with symlinks resolved.
    """
    if not _SAFE.fullmatch(value):
        return ("an absolute path of letters, digits, '.', '_', '+' and '-' (no spaces, quotes or other characters), "
                "e.g. /opt/sycope-recorder")
    if os.path.normpath(value) != value or any(p in (".", "..") for p in value.split("/")):
        return f"a normalised path: no '.', '..', '//' or trailing '/' (e.g. {os.path.normpath(value)})"
    real = os.path.realpath(value)
    for p in dict.fromkeys((value, real)):
        why = system_reason(p, top_level_ok)
        if why:
            return why + ("" if p == value else f" ({value} resolves to {real})")
    for label, other, same_ok in others:
        if not other:
            continue
        o = os.path.realpath(other)
        if real == o:
            if same_ok:
                continue
            return f"the same directory as {label} ({other})"
        if within(real, o):
            return f"inside {label} ({other}): they must be separate"
        if within(o, real):
            return f"it contains {label} ({other}): they must be separate"
    return None


def _entries(d: str) -> list[str] | None:
    try:
        return os.listdir(d)
    except FileNotFoundError:
        return []
    except OSError:
        return None


def foreign(d: str, deployed: str, allowed: tuple[str, ...] = (), recognised: bool = False) -> str | None:
    """Why the installer must not sync a release over `d` with --delete, or None when it may.

    It may when `d` does not exist, holds nothing but the `allowed` entries (what the installer itself puts
    there before the first deployment, `lost+found` of a mount point), holds the installer's `deployed`
    record, or when the caller `recognised` it as an earlier deployment that it backed up and adopts.
    """
    if os.path.islink(d):
        real = os.path.realpath(d)
        if not os.path.isdir(real):
            return f"{d} is a symbolic link to {real}, which is not a directory"
    elif os.path.lexists(d) and not os.path.isdir(d):
        return f"{d} exists and is not a directory"
    names = _entries(d)
    if names is None:
        return f"{d} cannot be read"
    if os.path.isfile(os.path.join(d, deployed)) or recognised:
        return None
    other = sorted(n for n in names if n not in (*allowed, "lost+found"))
    if not other:
        return None
    shown = ", ".join(other[:5]) + (f" and {len(other) - 5} more" if len(other) > 5 else "")
    return f"{d} holds files this installer did not put there ({shown}) and no {deployed} record"
