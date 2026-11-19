"""Console output and prompts. Non-interactive runs answer from defaults and never block."""

from __future__ import annotations

import getpass
import sys
from typing import Callable

COLORS = {"ok": "\033[32m", "warn": "\033[33m", "fail": "\033[31m", "skip": "\033[36m", "off": "\033[0m"}
LABEL = {"ok": "OK", "warn": "WARN", "fail": "FAIL", "skip": "SKIP", "unchanged": "SAME"}


class MissingAnswer(Exception):
    """A required answer is missing in a run that cannot ask."""


class Console:
    def __init__(self, interactive: bool, color: bool | None = None, out=None) -> None:
        self.interactive = interactive
        self.out = out or sys.stdout
        self.color = self.out.isatty() if color is None else color

    def say(self, msg: str = "") -> None:
        print(msg, file=self.out, flush=True)

    def section(self, title: str) -> None:
        self.say(f"\n== {title}")

    def status_label(self, status: str) -> str:
        text = LABEL.get(status, status.upper())
        if not self.color:
            return text
        key = "ok" if status == "unchanged" else status
        return f"{COLORS.get(key, '')}{text}{COLORS['off']}"

    def item(self, status: str, text: str) -> None:
        self.say(f"  {self.status_label(status):<6} {text}")

    def ask(self, key: str, prompt: str, default: str | None = None, *,
            validate: Callable[[str], str | None] | None = None, secret: bool = False,
            required: bool = True) -> str:
        """Ask for a value. `validate` returns an error text or None. Without a terminal the
        default is used (or MissingAnswer if there is none and the value is required)."""
        while True:
            if not self.interactive:
                value = default
            else:
                shown = "" if secret or default is None else f" [{default}]"
                raw = (getpass.getpass if secret else input)(f"  {prompt}{shown}: ")
                value = raw.strip() or default
            if value in (None, ""):
                if required:
                    if not self.interactive:
                        raise MissingAnswer(key)
                    self.say("    a value is required")
                    continue
                return ""
            error = validate(value) if validate else None
            if error is None:
                return value
            if not self.interactive:
                raise MissingAnswer(f"{key}: {error}")
            self.say(f"    {error}")

    def confirm(self, prompt: str, default: bool = False) -> bool:
        if not self.interactive:
            return default
        raw = input(f"  {prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
        return default if not raw else raw in ("y", "yes")
