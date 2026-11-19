#!/usr/bin/env python3
"""Sycope Traffic Recorder uninstaller: removes what the installer set up, except the licences and the PCAPs.

    sudo tools/install/uninstall.sh                 show what would be removed, ask, remove
    sudo tools/install/uninstall.sh --dry-run       print the commands instead of running them
    sudo tools/install/uninstall.sh --yes           do not ask
    sudo tools/install/uninstall.sh --remove-docker also remove Docker (refused while other containers exist)
    sudo tools/install/uninstall.sh --keep-sycope   leave the Passthrough entries and the External Destination

Kept, always: the licence files (/etc/*.license), the licence backups and every licence file in the inbox
(/var/lib/sycope-recorder-installer), the rolling buffer and the alerts directory with all PCAPs, an n2disk
that runs outside n2disk@<nic> (with its package and PF_RING), configurations edited by hand, the operator's
own certificate, base packages. The licences are backed up first and checked at the end, as by the installer.

Removed: the recorder and Triage stacks (containers, built images, volumes, directories), the Sycope Passthrough
entries and the External Destination when they point at this recorder, n2disk@/nProbe services and their
configurations, the capture NIC and tuning units, PF_RING, the licence inbox units and menu, the ntop packages
and repository, and the installer's state (answers, passwords, reports). See recorder_install/uninstall.py.
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import time
from datetime import datetime

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import wizard  # noqa: E402  (licence backup and guard, the lock: the same code as the installer's)
from recorder_install import VERSION  # noqa: E402
from recorder_install import licence  # noqa: E402
from recorder_install import report as rpt  # noqa: E402
from recorder_install import steps as st  # noqa: E402
from recorder_install import uninstall as un  # noqa: E402
from recorder_install.state import Store  # noqa: E402
from recorder_install.system import Host, Runner  # noqa: E402
from recorder_install.ui import Console  # noqa: E402


def make_ctx(store: Store, runner: Runner, args) -> st.Ctx:
    a = dict(store.answers)
    a.setdefault("install_dir", un.DEFAULT_INSTALL_DIR)
    ctx = st.Ctx(a=a, secrets=dict(store.secrets), r=runner, host=Host(runner), repo=wizard.REPO, dry=args.dry_run)
    ctx.extra.update({"keep_sycope": args.keep_sycope, "remove_docker": args.remove_docker,
                      "state_dir": args.state_dir})
    return ctx


def run_parts(ctx: st.Ctx, console: Console, parts, apply: bool) -> list[rpt.Section]:
    sections = []
    for pid, title, fn in parts:
        console.section(title)
        try:
            res = fn(ctx, apply)
        except Exception as exc:  # one part failing must not leave the rest undone or unreported
            res = rpt.Result().add(title, "fail", f"{type(exc).__name__}: {exc}")
        for i in res.items:
            console.item(i.status, f"{i.name}: {i.detail}")
            if i.hint and i.status in ("warn", "fail"):
                console.say(f"           -> {i.hint}")
        sections.append(rpt.Section(pid, title, res, True))
    return sections


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog=__doc__.split("\n\n", 1)[1])
    ap.add_argument("--dry-run", action="store_true", help="print the changes instead of making them")
    ap.add_argument("--yes", "-y", action="store_true", help="do not ask for confirmation")
    ap.add_argument("--remove-docker", action="store_true", help="also remove Docker (not while other containers exist)")
    ap.add_argument("--keep-sycope", action="store_true", help="do not delete anything in Sycope")
    ap.add_argument("--state-dir", default=wizard.STATE_DIR)
    args = ap.parse_args(argv)
    if os.geteuid() != 0:
        print("run as root (sudo)", file=sys.stderr)
        return 2
    try:
        lock = wizard.take_lock(args.state_dir)
    except BlockingIOError:
        print("an installer run is in progress", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"cannot take the installer lock in {args.state_dir}: {exc}", file=sys.stderr)
        return 2
    try:
        return _run(args)
    finally:
        os.close(lock)


def _run(args) -> int:
    interactive = sys.stdin.isatty() and not args.yes
    console = Console(interactive)
    store = Store(args.state_dir).load()
    console.say(f"Sycope Traffic Recorder uninstaller {VERSION}" + ("  [dry run]" if args.dry_run else ""))
    if not store.loaded:
        console.say(f"  No installer state in {args.state_dir}: the answers are unknown, so only what can be found "
                    f"on the host (default install directory {un.DEFAULT_INSTALL_DIR}) is removed, and nothing in Sycope.")

    # The plan: every part only looks.
    plan_ctx = make_ctx(store, Runner(read_only=True, log=lambda m: None), args)
    console.say("\nWhat would be removed (and what stays):")
    plan = run_parts(plan_ctx, console, un.PARTS + un.LATE_PARTS, apply=False)
    todo = sum(1 for s in plan for i in s.result.items if i.status == "skip")
    if not todo:
        console.say("\nNothing to remove.")
        return 0
    console.say(f"\n{todo} item(s) to remove. The licences and the PCAP directories stay.")
    if not args.dry_run and not args.yes:
        if not interactive:
            console.say("Not a terminal: run with --yes to remove without asking.")
            return 2
        if not console.confirm("Remove them?", False):
            console.say("Nothing was changed.")
            return 2

    runner = Runner(dry=args.dry_run, log=lambda m: console.say(f"           {m}"))
    ctx = make_ctx(store, runner, args)
    backup_section = before = backup_dir = None
    if not args.dry_run:
        console.section("Licence backup")
        try:
            backup_section, before, backup_dir = wizard.licence_backup_section(console, runner, datetime.now())
        except (OSError, licence.BackupError) as exc:
            console.item("fail", f"the licence could not be backed up: {exc}; nothing was changed")
            return 2
    sections = run_parts(ctx, console, un.PARTS, apply=True)
    if before is not None:
        guard = wizard.licence_guard_section(console, runner, before, backup_dir, {})
        sections = [backup_section, *sections, guard]
        if any(i.status == "fail" for i in guard.result.items):
            console.say("  The licence changed: the packages and the installer state are left for now. "
                        "Restore the licence first (the command is above), then run the uninstaller again.")
            return _finish(console, args, sections)
    sections += run_parts(ctx, console, un.LATE_PARTS, apply=True)
    if before is not None:
        res = rpt.Result()
        console.section("Licence files")
        for status, name, detail in un.licence_files_check(before):
            res.add(name, status, detail, f"restore it: {licence.restore_command(backup_dir)}" if status == "fail" and backup_dir else "")
            console.item(status, f"{name}: {detail}")
        sections.append(rpt.Section("licence_files", "Licence files", res, True))
    return _finish(console, args, sections)


def _finish(console: Console, args, sections: list[rpt.Section]) -> int:
    notes = ["The licences are where they were; a later installation finds them (and the backups) again.",
             "PCAPs are kept: the rolling buffer and alerts directories are left for you to keep or delete."]
    mode = "dry-run" if args.dry_run else "uninstall"
    meta = {"at": time.strftime("%Y-%m-%d %H:%M:%S"), "host": socket.gethostname(), "version": VERSION, "mode": mode}
    console.section("Report")
    console.say(rpt.render_text(sections, notes, label=lambda s: console.status_label(s), only_problems=True))
    if not args.dry_run:
        try:
            os.makedirs(args.state_dir, mode=0o700, exist_ok=True)
            path = os.path.join(args.state_dir, f"uninstall-{time.strftime('%Y%m%d-%H%M%S')}.md")
            with open(path, "w") as fh:
                fh.write(rpt.render_markdown(sections, notes, meta))
            console.say(f"\nReport saved: {path}")
        except OSError as exc:
            console.say(f"\nThe report could not be saved: {exc}")
    return 1 if rpt.counts(sections)["fail"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
