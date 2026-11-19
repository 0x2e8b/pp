"""What the installer remembers between runs: answers, secrets, and the result of every step.

`state.json` holds answers (no secrets) and per-step results with a fingerprint of the inputs the
step depends on. `secrets.json` (mode 600) holds the passwords. A step whose result is ok and
whose fingerprint is unchanged is not run again; `--redo` and `--from-scratch` override that.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any

SCHEMA = 1


class Store:
    def __init__(self, directory: str) -> None:
        self.dir = directory
        self.path = os.path.join(directory, "state.json")
        self.secrets_path = os.path.join(directory, "secrets.json")
        self.answers: dict[str, Any] = {}
        self.secrets: dict[str, str] = {}
        self.steps: dict[str, dict[str, Any]] = {}
        self.history: list[dict[str, Any]] = []
        self.loaded = False

    def load(self) -> "Store":
        for attr, path in (("_data", self.path), ("_sec", self.secrets_path)):
            try:
                with open(path) as fh:
                    setattr(self, attr, json.load(fh))
            except (OSError, ValueError):
                setattr(self, attr, {})
        if self._data.get("schema") == SCHEMA:
            self.answers = dict(self._data.get("answers", {}))
            self.steps = dict(self._data.get("steps", {}))
            self.history = list(self._data.get("history", []))
            self.loaded = True
        self.secrets = {k: v for k, v in self._sec.items() if isinstance(v, str)}
        return self

    def save(self) -> None:
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        self._write(self.path, {"schema": SCHEMA, "answers": self.answers, "steps": self.steps,
                                "history": self.history[-50:]}, 0o644)
        self._write(self.secrets_path, self.secrets, 0o600)

    @staticmethod
    def _write(path: str, data: Any, mode: int) -> None:
        tmp = f"{path}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, path)

    def reset(self) -> None:
        """Forget the step results (answers and secrets stay as defaults for the next questions)."""
        self.steps = {}

    def fingerprint(self, step_version: int, keys: tuple[str, ...]) -> str:
        payload = json.dumps({"v": step_version, "a": {k: self.answers.get(k) for k in keys}},
                             sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def unchanged(self, step_id: str, fingerprint: str) -> bool:
        rec = self.steps.get(step_id)
        return bool(rec) and rec.get("status") in ("ok", "warn") and rec.get("fingerprint") == fingerprint

    def record(self, step_id: str, status: str, fingerprint: str, detail: str) -> None:
        self.steps[step_id] = {"status": status, "fingerprint": fingerprint, "detail": detail,
                               "at": time.strftime("%Y-%m-%d %H:%M:%S")}
