"""The final report: what worked, what did not, and what to do about it."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

ORDER = {"fail": 0, "warn": 1, "ok": 2, "unchanged": 2, "skip": 3}


@dataclass
class Item:
    name: str
    status: str  # ok | warn | fail | skip | unchanged
    detail: str = ""
    hint: str = ""


@dataclass
class Result:
    items: list[Item] = field(default_factory=list)
    data: dict = field(default_factory=dict)

    def add(self, name: str, status: str, detail: str = "", hint: str = "") -> "Result":
        self.items.append(Item(name, status, detail, hint))
        return self

    @property
    def status(self) -> str:
        if not self.items:
            return "skip"
        return min((i.status for i in self.items), key=lambda s: ORDER.get(s, 2))


@dataclass
class Section:
    step_id: str
    title: str
    result: Result
    ran: bool  # False when the previous result was reused


def counts(sections: list[Section]) -> dict[str, int]:
    out = {"ok": 0, "warn": 0, "fail": 0, "skip": 0}
    for s in sections:
        for i in s.result.items:
            out["ok" if i.status == "unchanged" else i.status] = out.get(
                "ok" if i.status == "unchanged" else i.status, 0) + 1
    return out


def render_text(sections: list[Section], notes: list[str], *, label=lambda s: s.upper(),
                only_problems: bool = False) -> str:
    """The report as text. `only_problems` leaves out the OK items (the screen already showed them)."""
    lines = []
    for s in sections:
        if only_problems and not any(i.status in ("warn", "fail") for i in s.result.items):
            continue
        lines.append(f"\n{s.title}" + ("" if s.ran else "  (unchanged since the last run)"))
        for i in s.result.items:
            if only_problems and i.status not in ("warn", "fail"):
                continue
            lines.append(f"  {label(i.status):<6} {i.name}" + (f": {i.detail}" if i.detail else ""))
            if i.hint and i.status in ("warn", "fail"):
                lines.append(f"         -> {i.hint}")
    c = counts(sections)
    lines.append(f"\nResult: {c['ok']} ok, {c['warn']} warning(s), {c['fail']} failure(s), {c['skip']} skipped")
    if notes:
        lines.append("\nNext steps")
        lines += [f"  {n}" for n in notes]
    return "\n".join(lines)


def render_markdown(sections: list[Section], notes: list[str], meta: dict) -> str:
    c = counts(sections)
    out = [f"# Recorder installation report, {meta.get('at', time.strftime('%Y-%m-%d %H:%M:%S'))}", "",
           f"Host `{meta.get('host', '?')}`, installer version {meta.get('version', '?')}, mode "
           f"`{meta.get('mode', 'apply')}`.", "",
           f"**{c['ok']} ok, {c['warn']} warning(s), {c['fail']} failure(s), {c['skip']} skipped**", ""]
    for s in sections:
        out += [f"## {s.title}" + ("" if s.ran else " (unchanged since the last run)"), "",
                "| Status | Item | Detail |", "|---|---|---|"]
        for i in s.result.items:
            detail = (i.detail + (f" **Fix:** {i.hint}" if i.hint and i.status in ("warn", "fail") else ""))
            out.append(f"| {i.status.upper()} | {i.name} | {detail.replace('|', '/')} |")
        out.append("")
    if notes:
        out += ["## Next steps", ""] + [f"- {n}" for n in notes] + [""]
    return "\n".join(out)


def to_json(sections: list[Section], notes: list[str], meta: dict) -> str:
    return json.dumps({
        **meta, "counts": counts(sections), "notes": notes,
        "sections": [{"step": s.step_id, "title": s.title, "ran": s.ran, "items": [
            {"name": i.name, "status": i.status, "detail": i.detail, "hint": i.hint}
            for i in s.result.items]} for s in sections]}, indent=2)
