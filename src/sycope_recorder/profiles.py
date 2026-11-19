"""Per-definition extraction profiles, derived from Sycope alert definitions.

An alert payload carries only a bucket-end `timestamp` and the key fields of
one occurrence. Everything that says *what the alert covers* lives in the
alert definition (`alert-defs`): the NQL (aggregation keys, pre-filters,
source stream), `timeRange` (how far back the NQL looks) and `alertKey`. This
module turns one definition into a small profile dict that the recorder can
use to build a BPF filter and a time window for that definition, without
asking Sycope anything at alert time.

Verified on a live Sycope (2026-10-09): an alert with `timestamp` T covers
flows whose bucket lies in [T - timeRange, T). The counts of the alert
(`_countSessions`, packet sums) match a replay of the definition NQL over
exactly that range. The *packet* times of those flows can still be earlier
than the bucket (exporter idle/active timeout), which a profile cannot know:
that is a per-deployment lag, applied when the window is built.

Pure functions only; the HTTP side lives in tools/profiles/gen_profiles.py.
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sycope_recorder.alert import ParsedAlert

log = logging.getLogger("sycope_recorder")

# Group-by fields that exist in packet headers, so a BPF filter can use them.
# Anything else (country, AS, host name, DNS query, JA3) is enrichment.
PACKET_DIMS = ("clientIp", "serverIp", "serverPort", "protocol")
MAX_RANGE_S = 7 * 86400  # longest time_range_s a profile may have (range_seconds)

_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_DURATION = re.compile(r"^\s*(\d+)\s*([smhd])\s*$")
_STREAM = re.compile(r'\bsrc\s+stream\s*=\s*"([^"]+)"')
_BY = re.compile(r"\bby\s+(.+?)(?:\s+unwind\s*=\s*\w+)?\s*$")
_JOIN = re.compile(
    r"(\w+)\s*=\s*join\(\s*(\w+)\s*,\s*limit\s*=\s*(\d+)", re.IGNORECASE
)
_MACRO = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)\$")
_AND = re.compile(r"\s+and\s+", re.IGNORECASE)
# Field names are matched as Sycope spells them (as the grouping fields are, PACKET_DIMS); the keywords
# `in`, `or`, `and`, `not` in any case. A field spelt otherwise derives nothing (broader, never narrower).
_PORT_EQ = re.compile(r"^serverPort\s*=\s*(\d+)$")
_PORT_IN = re.compile(r"^serverPort\s+(?i:in)\s*\[([\d,\s]+)\]$")
_PROTO_EQ = re.compile(r"^protocol\s*=\s*(\d+)$")
_PROTO_IN = re.compile(r"^protocol\s+(?i:in)\s*\[([\d,\s]+)\]$")
_OR_CHAIN = re.compile(r"^(serverPort|protocol)\s*=\s*(\d+)(?:\s+(?i:or)\s+\1\s*=\s*\d+)+$")
# A negation operator (`not x`, `!x`, `!(...)`), not the comparisons `!=` and `not in`.
_NEG = re.compile(r"\bnot\b(?!\s+in\b)|!(?!=)", re.IGNORECASE)
_OR_TERM = re.compile(r"(\d+)")
_OR = re.compile(r"\bor\b", re.IGNORECASE)

# Keys under which a macro endpoint may carry the NQL text, most likely first.
_MACRO_KEYS = ("nql", "query", "expression", "definition", "value", "body", "text", "content")


def parse_duration(text: str | None) -> int | None:
    """'1m' -> 60, '1h' -> 3600; None when the text is not a plain duration."""
    m = _DURATION.match(text or "")
    return int(m.group(1)) * _UNITS[m.group(2)] if m else None


def _split_pipes(nql: str) -> list[str]:
    """Split an NQL pipeline on top-level '|' (not inside brackets, parens or quotes)."""
    parts, depth, quote, cur = [], 0, "", []
    for ch in nql:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "|" and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    parts.append("".join(cur).strip())
    return [p for p in parts if p]


def _group_by(aggr: str) -> list[dict[str, str]]:
    """`... by clientIp as clientIp, protocol as protocolName unwind=true` -> field/alias pairs."""
    m = _BY.search(aggr)
    if not m:
        return []
    out = []
    for item in m.group(1).split(","):
        bits = re.split(r"\s+as\s+", item.strip(), maxsplit=1)
        field = bits[0].strip()
        if field:
            out.append({"field": field, "alias": (bits[1].strip() if len(bits) == 2 else field)})
    return out


def macros_in(nql: str) -> list[str]:
    """Names of the `$MACRO$` references of an NQL text, in order, without repeats."""
    return list(dict.fromkeys(_MACRO.findall(nql or "")))


def macro_text(payload: Any) -> str | None:
    """The NQL text out of whatever the macro endpoint returned (a string or a JSON object)."""
    if isinstance(payload, str):
        return payload.strip() or None
    if isinstance(payload, dict):
        for key in _MACRO_KEYS:
            val = payload.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
            if isinstance(val, dict):
                inner = macro_text(val)
                if inner:
                    return inner
    return None


_LOOKUP_REF = re.compile(
    r'lookup\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*\{\s*"([^"]+)"\s*:\s*(\w+)\s*\}\s*\)\s*,\s*\[([^\]]*)\]',
    re.IGNORECASE)
_CIDR_KEYS = ("cidr", "subnet", "network", "ip", "address")
_ROW_KEYS = ("data", "entries", "items", "rows", "records", "content", "values", "elements")


def macro_lookup_refs(text: str | None) -> list[dict[str, Any]]:
    """Lookup conditions in a macro: `any(lookup("hosts & subnets", "trafficPolicy",
    {"cidr": serverIp}), ["DMZ"])` -> {lookup, field, key, ip_field, values}."""
    out = []
    for name, field, key, ip_field, vals in _LOOKUP_REF.findall(text or ""):
        values = [v for v in re.findall(r'"([^"]*)"', vals)]
        out.append({"lookup": name, "field": field, "key": key, "ip_field": ip_field,
                    "values": values})
    return out


def _rows(payload: Any) -> list[dict[str, Any]]:
    """The list of row objects inside whatever a lookup endpoint returned."""
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        for key in _ROW_KEYS:
            if isinstance(payload.get(key), (list, dict)):
                rows = _rows(payload[key])
                if rows:
                    return rows
        for val in payload.values():  # one level of nesting, e.g. {"config": {"entries": [...]}}
            if isinstance(val, (list, dict)):
                rows = _rows(val)
                if rows and any(k in rows[0] for k in _CIDR_KEYS):
                    return rows
    return []


def lookup_matches(payload: Any, field: str, values: list[str], key: str = "cidr") -> list[str]:
    """The networks of a lookup whose `field` holds any of `values` (a string or a list)."""
    wanted = {v.lower() for v in values}
    nets = []
    for row in _rows(payload):
        cell = row.get(field)
        have = {str(x).lower() for x in (cell if isinstance(cell, list) else [cell]) if x is not None}
        net = next((str(row[k]) for k in (key, *_CIDR_KEYS) if k in row and row[k]), None)
        if net and have & wanted:
            nets.append(net)
    return sorted(dict.fromkeys(nets))


def expand_macros(nql: str, macros: dict[str, str | None]) -> tuple[str, list[str], list[str]]:
    """Replace `$NAME$` by the macro's NQL where it is known.

    Returns (text, resolved names, unresolved names). An unresolved macro stays in the text as it
    is: the profile builder ignores a segment it does not understand, so the result is a broader
    filter, never a wrong one.
    """
    resolved: list[str] = []
    unresolved: list[str] = []

    def one(m: re.Match) -> str:
        text = macros.get(m.group(1))
        (resolved if text else unresolved).append(m.group(1))
        return text if text else m.group(0)

    out = _MACRO.sub(one, nql or "")
    return out, list(dict.fromkeys(resolved)), list(dict.fromkeys(unresolved))


def _mask(seg: str, nested: bool = False) -> str | None:
    """`seg` with quoted text, and unless `nested` everything in parentheses, blanked to `#`.

    Same length as `seg`, so match positions carry over; None when the parentheses do not balance
    (never with `nested`).
    """
    out: list[str] = []
    depth, quote, esc = 0, "", False
    for c in seg:
        hide = bool(quote) or (depth > 0 and not nested)
        if quote:
            esc, quote = (False, quote) if esc else (c == "\\", "" if c == quote else quote)
        elif c in "\"'":
            quote, hide = c, True
        elif c in "()" and not nested:
            depth += 1 if c == "(" else -1
            hide = True
            if depth < 0:
                return None
        out.append("#" if hide else c)
    return None if depth else "".join(out)


def _wrapped(seg: str) -> bool:
    """`seg` is one parenthesised group: `(a and b)`, not `(a) and (b)`."""
    return seg.startswith("(") and seg.endswith(")") and _mask(seg[1:-1]) is not None


def _terms(seg: str) -> list[str]:
    """The `and`-joined terms of one pipe segment that every match must satisfy.

    Outer parentheses are removed only when they enclose the whole segment. One field's OR chain
    (`serverPort = 53 or serverPort = 853`) is a single term; any other top-level `or` gives no
    terms, so nothing from an OR branch is ever taken as required. A top-level `and` term that is
    itself a parenthesised group gives that group's terms (it must hold too). A negated term (`not
    x`, `!x`, `not (...)`) gives nothing, and neither do the terms after it: nothing is taken from
    inside a negation, however far it reaches. `!=` and `not in` are comparisons, not negations.
    """
    seg = seg.strip()
    while _wrapped(seg):
        seg = seg[1:-1].strip()
    if _OR_CHAIN.match(seg):
        return [seg]
    flat = _mask(seg)
    if flat is None or _OR.search(flat):
        return []
    cuts = [0] + [x for m in _AND.finditer(flat) for x in m.span()] + [len(seg)]
    out: list[str] = []
    for a, b in zip(cuts[::2], cuts[1::2]):
        term = seg[a:b].strip()
        if _NEG.search(flat[a:b]):
            break
        if _wrapped(term):
            out += _terms(term)
        elif term:
            out.append(term)
    return out


def _static_filters(pre_aggr: list[str]) -> dict[str, list[int]]:
    """Constant port/protocol pre-filters of the definition (`serverPort = 53`).

    Also what a macro expands to: `serverPort = 53 and protocol = 17`, `serverPort = 53 or
    serverPort = 853`. Conditions on addresses, locations or roles are not packet-level here and
    are ignored. Only terms every match must satisfy count (see `_terms`): nothing from an OR
    branch (except one field's OR chain) or from a negation. Segments and terms are all AND-ed, so a
    key set twice keeps the values both allow (`serverPort in [53, 853] | serverPort = 853` -> 853);
    when none is left, nothing can match and the key is not derived at all.
    The result may be broader than the definition, never narrower.
    """
    static: dict[str, list[int]] = {}

    def put(key: str, values: list[int]) -> None:
        static[key] = [v for v in static[key] if v in values] if key in static else values

    for seg in pre_aggr:
        for term in _terms(seg):
            if m := _PORT_EQ.match(term):
                put("serverPort", [int(m.group(1))])
            elif m := _PORT_IN.match(term):
                put("serverPort", [int(x) for x in m.group(1).replace(" ", "").split(",") if x])
            elif m := _PROTO_EQ.match(term):
                put("protocol", [int(m.group(1))])
            elif m := _PROTO_IN.match(term):
                put("protocol", [int(x) for x in m.group(1).replace(" ", "").split(",") if x])
            elif m := _OR_CHAIN.match(term):
                put(m.group(1), [int(x) for x in _OR_TERM.findall(term)])
    return {k: v for k, v in static.items() if v}


def profile_from_def(defn: dict[str, Any],
                     macros: dict[str, str | None] | None = None) -> dict[str, Any]:
    """Build the extraction profile of one alert definition (an `alert-defs` item).

    `macros` maps macro names to their NQL (None = could not be read). Without it, macros are
    left alone and only listed; with it, readable ones are expanded before the filters are
    derived and the unreadable ones are reported in the notes.
    """
    nql = defn.get("nql") or ""
    used = macros_in(nql)
    unresolved: list[str] = []
    if macros is not None and used:
        nql, _resolved, unresolved = expand_macros(nql, macros)
    pipes = _split_pipes(nql)
    stream_m = _STREAM.search(pipes[0]) if pipes else None
    stream = stream_m.group(1) if stream_m else None

    aggr_i = next((i for i, p in enumerate(pipes) if p.lower().startswith("aggr")), None)
    aggr = pipes[aggr_i] if aggr_i is not None else ""
    pre_aggr = pipes[1:aggr_i] if aggr_i is not None else pipes[1:]

    group_by = _group_by(aggr)
    grouped = {g["field"] for g in group_by}
    packet = [g for g in group_by if g["field"] in PACKET_DIMS]
    unfilterable = [g["alias"] for g in group_by if g["field"] not in PACKET_DIMS]
    lists = {
        alias: {"dim": dim, "limit": int(limit)}
        for alias, dim, limit in _JOIN.findall(aggr)
        if dim in PACKET_DIMS
    }
    static = _static_filters(pre_aggr)

    notes: list[str] = []
    if stream == "netflowTotalAggr":
        shape = "aggregate"
        notes.append("whole-link aggregate: no packet filter can be derived")
    elif stream == "alerts":
        # An alert built from other alerts (Suspicious Host): there are no flows to read keys
        # from, but it groups by a host, and that host's traffic over the range is what to record.
        shape = "alerts:" + ("+".join(f for f in PACKET_DIMS if f in grouped) or "none")
        notes.append("built from other alerts: the filter is the grouped host, the window the range")
    elif stream == "netflow":
        shape = "+".join(f for f in PACKET_DIMS if f in grouped) or "static"
        if not packet and not static:
            notes.append("no packet-level key: only a time window can be extracted")
    else:
        shape = "unknown"
        notes.append(f"unrecognised source stream {stream!r}")
    if any(v["dim"] not in grouped for v in lists.values()):
        notes.append("a packet-level value list is truncated by the definition (join limit): "
                     "the filter cannot cover every value")

    if unresolved:
        notes.append("macros not readable: " + ", ".join(f"${m}$" for m in unresolved)
                     + " (their conditions are not part of the filter)")

    time_range = parse_duration(defn.get("timeRange"))
    if time_range is None:
        notes.append(f"unparsed timeRange {defn.get('timeRange')!r}, assumed 60s")
        time_range = 60
    return {
        "def_id": defn.get("id"),
        "name": defn.get("alertName"),
        "rule_id": defn.get("ruleId"),
        "active": bool(defn.get("active")),
        "stream": stream,
        "shape": shape,
        "time_range_s": time_range,
        "interval_s": parse_duration(defn.get("interval")) or 60,
        "throttling_min": defn.get("throttlingInMinutes"),
        "alert_key": list(defn.get("alertKey") or []),
        "packet_dims": packet,  # [{"field": "protocol", "alias": "protocolName"}]
        "unfilterable": unfilterable,
        "lists": lists,
        "static": static,
        "macros": used,
        "notes": notes,
    }


def build_profiles(defs: list[dict[str, Any]], active_only: bool = True,
                   macros: dict[str, str | None] | None = None) -> list[dict[str, Any]]:
    """Profiles for all definitions (active only by default), ordered by name."""
    out = [profile_from_def(d, macros) for d in defs if d.get("active") or not active_only]
    return sorted(out, key=lambda p: (p["name"] or "", p["def_id"] or ""))


# ---- the profiles file ------------------------------------------------------------------------
# profiles.json holds only what changes an extraction; everything else the generator learns from Sycope
# (shape, throttling, interval, macros, notes, ...) goes to a sidecar next to it (`info_path`), shown on the
# Profiles page and never used for a filter or window. The older format, one JSON list with every field in
# each profile, is still read.
FORMAT = 2
EDITABLE = ("def_id", "rule_id", "name", "time_range_s", "packet_dims", "static")
INFO = ("shape", "stream", "active", "interval_s", "throttling_min", "alert_key", "macros", "lists",
        "unfilterable", "notes")
HELP = {
    "def_id": "Sycope alert definition id. An alert is matched to its profile by this id (definitionId / "
              "alertDefId in the webhook). Must be unique.",
    "rule_id": "Rule id of the definition (template library). Used only when the webhook has no definition id "
               "and exactly one profile has this rule id.",
    "name": "Definition name. Shown on the queue and status pages next to the job; not used for matching.",
    "time_range_s": "CHANGES THE WINDOW. Seconds the definition looks back (its timeRange). An alert at T is "
                    "extracted from T - time_range_s - SR_EXPORTER_LAG_SECONDS to T + SR_WINDOW_MARGIN_SECONDS. "
                    "1 to 604800.",
    "packet_dims": "CHANGES THE BPF FILTER. Grouping fields of the definition that exist in packets: "
                   "{field, alias} with field one of clientIp, serverIp, serverPort, protocol. Each one present "
                   "in the alert becomes a term: host <clientIp>, host <serverIp>, port <serverPort>, <protocol>. "
                   "Remove one to make the filter broader; an empty list with no static means NO BPF FILTER.",
    "static": "CHANGES THE BPF FILTER. Constant pre-filters of the definition: {\"serverPort\": [53]} or "
              "{\"protocol\": [17]}. Used when the port or protocol is not in packet_dims: one protocol -> "
              "udp/tcp/icmp, several ports -> (port a or port b). Several protocols add no term.",
}


def info_path(path: str) -> str:
    """The sidecar of a profiles file: profiles.json -> profiles.info.json."""
    root, ext = os.path.splitext(path)
    return root + ".info" + (ext or ".json")


def profiles_of(data: Any) -> list[Any] | None:
    """The profile list of a parsed profiles file (the object of FORMAT 2, or the older bare list)."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("profiles"), list):
        return data["profiles"]
    return None


def dumps(profiles: list[dict[str, Any]]) -> str:
    """The profiles file: the field help, then each profile with its editable fields only."""
    doc = {"_help": HELP, "format": FORMAT,
           "profiles": [{k: p[k] for k in EDITABLE if k in p} for p in profiles]}
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def info_of(profiles: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """def_id -> the descriptive fields of each profile (what goes to the sidecar)."""
    return {str(p["def_id"]): {k: p[k] for k in INFO if k in p} for p in profiles if p.get("def_id")}


def dumps_info(profiles: list[dict[str, Any]] | dict[str, dict[str, Any]]) -> str:
    info = profiles if isinstance(profiles, dict) else info_of(profiles)
    doc = {"_about": "Read from the Sycope definitions when the profiles were built. Shown on the Profiles page, "
                     "never used for a filter or window. Rewritten by every rebuild; editing it changes only what "
                     "the page shows.", "format": FORMAT, "definitions": info}
    return json.dumps(doc, indent=2, sort_keys=False, ensure_ascii=False) + "\n"


def load_info(path: str) -> dict[str, dict[str, Any]]:
    """The sidecar of `path` (def_id -> descriptive fields); empty when it is missing or unreadable."""
    try:
        with open(info_path(path)) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    defs = data.get("definitions") if isinstance(data, dict) else None
    return {str(k): v for k, v in defs.items() if isinstance(v, dict)} if isinstance(defs, dict) else {}


# Payload fields that name the alert definition, most specific first. The
# definition id is per Sycope instance; the rule id is stable across instances
# (it comes from the template library) but can be shared by several definitions.
_DEF_ID_KEYS = ("definitionId", "alertDefId", "alertDefinitionId", "defId")
_RULE_ID_KEYS = ("ruleId", "alertRuleId")
_PROTO_NAME = {1: "icmp", 6: "tcp", 17: "udp"}


def _finite(value: Any) -> tuple[Any, bool]:
    """`value` with every inf/NaN (JSON `1e999`, `NaN`, `Infinity`), however deep, replaced by None;
    and whether there was one."""
    if isinstance(value, float) and not math.isfinite(value):
        return None, True
    if isinstance(value, list):
        pairs = [_finite(v) for v in value]
        return [v for v, _ in pairs], any(bad for _, bad in pairs)
    if isinstance(value, dict):
        fixed = {k: _finite(v) for k, v in value.items()}
        return {k: v for k, (v, _) in fixed.items()}, any(bad for _, bad in fixed.values())
    return value, False


def _port_list(v: Any) -> bool:
    return isinstance(v, list) and all(isinstance(n, int) and not isinstance(n, bool) and 0 <= n <= 65535
                                       for n in v)


# What a descriptive field must be for the pages to show it (the upload validator's rules, profile_store).
_INFO_OK = {
    "alert_key": lambda v: isinstance(v, list) and all(isinstance(x, str) for x in v),
    "macros": lambda v: isinstance(v, list) and all(isinstance(x, str) for x in v),
    "notes": lambda v: isinstance(v, list) and all(isinstance(x, str) for x in v),
    "unfilterable": lambda v: isinstance(v, list) and all(isinstance(x, str) for x in v),
    "active": lambda v: isinstance(v, bool),
    "lists": lambda v: isinstance(v, dict),
    "interval_s": lambda v: v is None or (isinstance(v, (int, float)) and not isinstance(v, bool)),
    "throttling_min": lambda v: v is None or (isinstance(v, (int, float)) and not isinstance(v, bool)),
}


def _usable(p: dict[str, Any], where: str) -> dict[str, Any] | None:
    """A loaded profile made safe to use and show, or None to skip it; each change is logged.

    An uploaded file was checked (profile_store.validate) but a mounted one was not, and Python's JSON
    reader accepts inf and NaN, which no JSON view can send. So: a non-finite number becomes null (a
    `time_range_s` then counts as unusable, see range_seconds); a `packet_dims` entry or a `static` key
    that the filter builder cannot use is dropped (the filter gets broader, never narrower); a descriptive
    field of the wrong type is dropped. A profile is skipped (its alerts are handled like those of a
    definition without a profile) when its def_id or rule_id is a list or an object, which cannot be looked
    up, or its packet_dims is not a list. A valid profile comes back unchanged."""
    p, bad = _finite(p)
    name = p.get("name") or p.get("def_id")
    label = f"{where} ({name})" if isinstance(name, str) else where
    if bad:
        log.warning("%s: non-finite number (inf/NaN) replaced by null", label)
    if any(isinstance(p.get(k), (list, dict)) for k in ("def_id", "rule_id")):
        log.warning("%s: def_id or rule_id is not a single value; profile skipped", label)
        return None
    dims = p.get("packet_dims")
    if dims is not None and not isinstance(dims, list):
        log.warning("%s: packet_dims is not a list; profile skipped (its alerts use the default filter)", label)
        return None
    if dims is not None:
        ok = [d for d in dims if isinstance(d, dict) and d.get("field") in PACKET_DIMS]
        if ok != dims:
            log.warning("%s: unusable packet_dims entries dropped (the filter is broader)", label)
            p["packet_dims"] = ok
    static = p.get("static")
    if static is not None:
        ok = {k: v for k, v in static.items() if k in ("serverPort", "protocol") and _port_list(v)} \
            if isinstance(static, dict) else {}
        if ok != static:
            log.warning("%s: unusable static entries dropped (the filter is broader)", label)
            p["static"] = ok
    for key, good in _INFO_OK.items():
        if key in p and not good(p[key]):
            log.warning("%s: %s %r is not usable; dropped", label, key, p[key])
            del p[key]
    return p


class ProfileBook:
    """The loaded profiles, looked up by the identifiers an alert payload carries."""

    def __init__(self, profiles: list[dict[str, Any]]) -> None:
        self.profiles = profiles
        self._by_def = {p["def_id"]: p for p in profiles if p.get("def_id")}
        by_rule: dict[str, list[dict[str, Any]]] = {}
        for p in profiles:
            if p.get("rule_id"):
                by_rule.setdefault(p["rule_id"], []).append(p)
        # A rule id shared by several definitions is ambiguous: do not guess.
        self._by_rule = {r: ps[0] for r, ps in by_rule.items() if len(ps) == 1}

    def __len__(self) -> int:
        return len(self.profiles)

    @classmethod
    def load(cls, path: str) -> "ProfileBook":
        """Read a profiles file and its sidecar; an empty path, or an unreadable file, gives an empty book.

        A profile keeps its own fields; the sidecar only fills the descriptive ones it lacks (an older
        single-list file carries them itself)."""
        if not path:
            return cls([])
        try:
            with open(path) as fh:
                data = profiles_of(json.load(fh))
            if data is None:
                raise ValueError("expected {\"profiles\": [...]} or a JSON list of profiles")
        except (OSError, ValueError) as exc:
            log.error("cannot load profiles from %s: %s (using default windows)", path, exc)
            return cls([])
        info = load_info(path)
        out = []
        for i, p in enumerate(data):
            if isinstance(p, dict):
                extra = info.get(str(p.get("def_id")), {})
                p = _usable({**{k: v for k, v in extra.items() if k in INFO}, **p}, f"{path}: profile {i + 1}")
                if p is not None:
                    out.append(p)
        return cls(out)

    def lookup(self, alert: dict[str, Any]) -> dict[str, Any] | None:
        """The profile of the alert's definition, or None (caller falls back to defaults)."""
        for key in _DEF_ID_KEYS:
            def_id = alert.get(key)
            if isinstance(def_id, (list, dict)):  # unhashable (was a 500); no definition id is a list
                continue
            if (p := self._by_def.get(def_id)) is not None:
                return p
        for key in _RULE_ID_KEYS:
            rule = alert.get(key)
            if isinstance(rule, str) and (p := self._by_rule.get(rule)) is not None:
                return p
        return None


def range_seconds(profile: dict[str, Any]) -> int | None:
    """The profile's `time_range_s` when it is usable, else None.

    Usable is what an upload must pass (profile_store.validate): an int, not a bool, from 1 s to
    MAX_RANGE_S. A mounted profiles file is loaded without that check (only inf/NaN become null, see
    _usable), so a profile can lack the field or carry "300", null, 0, a float or a huge number; every
    reader goes through here.
    """
    rng = profile.get("time_range_s")
    if isinstance(rng, int) and not isinstance(rng, bool) and 1 <= rng <= MAX_RANGE_S:
        return rng
    return None


def window_seconds(profile: dict[str, Any], lag: int, margin: int) -> tuple[int, int] | None:
    """(seconds before the alert timestamp, seconds after) to extract for this profile; None when
    its time_range_s is unusable (range_seconds), and the caller uses the default window.

    The alert timestamp ends the bucket, so the bucket is [T - range, T). `lag`
    reaches back for flows exported late (idle/active timeout of the exporter);
    `margin` covers clock skew and a timestamp taken slightly after the bucket.
    """
    rng = range_seconds(profile)
    return None if rng is None else (rng + lag, margin)


def profile_bpf(profile: dict[str, Any], parsed: "ParsedAlert") -> str | None:
    """BPF filter for one alert occurrence, limited to what the definition aggregates by.

    A dimension the definition does not group by is left out even if the payload
    has it: the alert then stands for all of that client's/server's traffic. A
    dimension the payload lacks is left out too (a broader filter, never a wrong
    one). Constant port/protocol pre-filters of the definition fill the gap
    when the port or protocol is not a grouping key. None = no usable filter.
    """
    dims = {d["field"] for d in profile.get("packet_dims", [])}
    static = profile.get("static", {})

    proto = parsed.protocol if "protocol" in dims else None
    if proto is None and len(static.get("protocol", [])) == 1:
        num = static["protocol"][0]
        proto = _PROTO_NAME.get(num) or f"ip proto {num}"
    port = parsed.server_port if "serverPort" in dims else None
    ports = [port] if port else list(static.get("serverPort", []))

    terms: list[str] = []
    if proto:
        terms.append(proto)
    hosts = []
    if "clientIp" in dims and parsed.client_ip:
        hosts.append(f"host {parsed.client_ip}")
    if "serverIp" in dims and parsed.server_ip:
        hosts.append(f"host {parsed.server_ip}")
    terms += hosts
    use_ports = bool(ports) and proto != "icmp"
    if use_ports:
        terms.append(f"port {ports[0]}" if len(ports) == 1
                     else "(" + " or ".join(f"port {p}" for p in ports) + ")")
    if not hosts and not use_ports:  # a bare protocol (or nothing) is too broad to be a filter
        return None
    return " and ".join(terms)
