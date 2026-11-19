"""Process helpers for the worker: identify a process reliably and kill a whole process group.

npcapextract runs in its own process group (start_new_session) so a cancel or a hard stop can kill
it together with anything it started. A PID alone is not an identity: after a restart the number can
belong to another process, so the worker records the start time (field 22 of /proc/<pid>/stat) and
compares it before killing anything it did not start itself. Without /proc (macOS development) the
helpers report "unknown" and the orphan cleanup does nothing.
"""

from __future__ import annotations

import os
import signal
import time


def proc_start(pid: int) -> int | None:
    """Start time of a process in clock ticks since boot, None when it is gone or unknown."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            data = fh.read().decode(errors="replace")
    except OSError:
        return None
    # comm (field 2) may contain spaces and parentheses: split after the last ')'
    fields = data[data.rfind(")") + 2:].split()
    try:
        return int(fields[19])  # field 22 overall; fields[0] is field 3
    except (IndexError, ValueError):
        return None


def proc_cmdline(pid: int) -> str:
    """Command line of a process joined with spaces, "" when unknown."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            return fh.read().replace(b"\0", b" ").decode(errors="replace").strip()
    except OSError:
        return ""


def _group_alive(pgid: int) -> bool:
    """Whether any member of the group still runs; the caller waits on this during the grace period."""
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # macOS answers EPERM when the only member left is an unreaped zombie: nothing to wait for.
        return False


def kill_group(pgid: int, grace: float = 5.0, reap=None) -> None:
    """SIGTERM the group, give it `grace` seconds, then SIGKILL whatever is left.

    `reap` is called on every poll of the grace period: the caller that spawned the leader passes its
    `Popen.poll`, because an exited leader nobody has waited for is a zombie that keeps the group
    "alive" until the grace period is over.

    Group 0 is the caller's own group and 1 is init's: killpg of either would take the worker or the
    container down, and a pid read from a row the web can write may be exactly that. Never signalled.
    """
    if pgid <= 1:
        return
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except PermissionError:
        pass  # macOS EPERM for a zombie-only group: the alive check below decides
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline and _group_alive(pgid):
        if reap is not None:
            reap()
        time.sleep(0.05)
    # Only signal a group that is still there: a gone group id can be reused by an unrelated group.
    if _group_alive(pgid):
        try:
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
