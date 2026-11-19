"""Parses loosely-shaped Sycope alert JSON into a ParsedAlert.

Sycope alert payloads vary in field naming by alert type and Sycope
version, so this module tries a priority-ordered list of field name
aliases per logical field (client IP, server IP, port, protocol,
timestamp, id, name) and takes the first usable match. "Usable" means a
truthy value for the flow fields and timestamp (`serverPort: 0` or an
empty-string IP counts as absent), and for the alert id and name a value
that is not null, not empty and, for the id, has at least one character a
file name may keep. A null or empty id used to be kept as the text "None",
which gave every such alert the same link; it now falls through to a
synthesized id that is unique per alert and stable across redeliveries.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable

_ID_CHAR = re.compile(r"[A-Za-z0-9_-]")
_PROTO_BY_NUM = {1: "icmp", 6: "tcp", 17: "udp"}
_ALLOWED_PROTO = {"tcp", "udp", "icmp"}
MAX_PORT = 65535
# How far past the receiving host's clock an alert time may be. Sycope stamps an alert with the end of
# its bucket, before it sends it, so a later time is clock skew (or a day-first string read in another
# zone: at most 14 h) at best; a time a year ahead would only park the job in the queue until then.
MAX_FUTURE_S = 86400


@dataclass
class ParsedAlert:
    """Alert fields normalized from Sycope's loosely-shaped JSON payload."""

    client_ip: str | None
    server_ip: str | None
    server_port: int | None
    protocol: str | None
    timestamp: float
    alert_id: Any  # str, int, or None depending on the source payload's "id"/"alertId" field
    alert_name: str


def _find_field(alert: dict, aliases: list[str], extract: Callable[[Any], Any]) -> Any:
    """Try each alias in priority order, returning the first extracted value that is truthy.

    A field name being present isn't enough to accept it: 0, "", None, and
    [] are all treated as "this alias didn't actually give us a value" and
    the next alias is tried instead. This is deliberately different from
    the id/name lookup in parse_alert, which keys off presence alone (see
    module docstring) — a real port of 0 or an empty IP string is useless,
    but a null id is still a meaningful (if unfortunate) value to keep.
    """
    for name in aliases:
        if name in alert:
            value = extract(alert[name])
            if value:
                return value
    return None


def _valid_ip(text: str) -> str | None:
    """Return text only if it is a literal IPv4/IPv6 address.

    The value ends up inside a BPF expression (`host <ip>`), so anything
    else (e.g. "1.1.1.1 or port 22") would widen the capture filter and leak
    unrelated traffic into the PCAP. Invalid values count as "absent".
    An IPv6 scope id (`fe80::1%eth0`) is refused too: ipaddress accepts any
    text after the `%`, spaces and quotes included.
    """
    text = text.strip()
    if "%" in text:
        return None
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return None
    return text


def _ip(value: Any) -> str | None:
    """Accept a plain IP string, or one from a dict's "addressString" key; anything else (or a non-IP string) is unusable."""
    if isinstance(value, str):
        return _valid_ip(value)
    if isinstance(value, dict):
        inner = value.get("addressString")
        return _valid_ip(inner) if isinstance(inner, str) else None
    return None


def _port(value: Any) -> int | None:
    """Coerce to an int from 1 to 65535, rejecting bools, non-numeric strings, and anything outside that range as "no port"."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 < value <= MAX_PORT else None
    if isinstance(value, str):
        try:
            n = int(value)
        except ValueError:
            return None
        return n if 0 < n <= MAX_PORT else None
    return None


def _proto(value: Any) -> str | None:
    """Map a known IP protocol number to its name, or lowercase and validate a string; anything unrecognized is discarded."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return _PROTO_BY_NUM.get(value)
    if isinstance(value, str):
        if value.isascii() and value.isdigit() and len(value) <= 3:  # "6": the number as a string
            return _PROTO_BY_NUM.get(int(value))
        low = value.lower()
        return low if low in _ALLOWED_PROTO else None
    return None


def _numeric_ts(value: Any) -> float | None:
    """Parse a numeric (or numeric-string) timestamp, converting to seconds.

    Sycope sometimes sends Unix time in milliseconds instead of seconds
    with no explicit unit marker, so any value greater than 1e12 (a
    threshold far above any plausible seconds-based timestamp, but well
    below a milliseconds one) is assumed to be milliseconds and divided
    down; by the same rule a value above 1e15 is microseconds and one above
    1e18 nanoseconds. NaN and infinities are no time (None); the range is
    checked by _usable_ts.
    """
    if isinstance(value, bool):
        return None
    try:
        if isinstance(value, (int, float, str)):
            n = float(value)
        else:
            return None
    except (ValueError, OverflowError):  # OverflowError: an int too large for a float
        return None
    if not math.isfinite(n):
        return None
    if n > 1e18:
        return n / 1e9
    if n > 1e15:
        return n / 1e6
    return n / 1000.0 if n > 1e12 else n


def _usable_ts(ts: float | None, now: datetime) -> float | None:
    """`ts` when it is after the epoch and at most MAX_FUTURE_S past `now`, else None ("absent")."""
    if ts is None or not 0 < ts <= now.timestamp() + MAX_FUTURE_S:
        return None
    return ts


def _resolve_timestamp(alert: dict, now: datetime) -> float:
    """Resolve the alert timestamp via a fallback chain: numeric fields first, then a formatted string, then "now".

    Tries the numeric aliases (unixTimestamp/timestamp_unix/time, then a
    numeric "timestamp") via _find_field first since they're unambiguous
    once normalized to seconds. If none are usable, falls back to a
    "timestamp" string field in Sycope's day-first, 2-digit-year format
    (`%d.%m.%y %H:%M:%S`). If that's also missing or unparseable, the
    alert is timestamped with `now` rather than failing — a slightly
    wrong time is preferable to rejecting the alert outright. A value
    that is not finite, not after the epoch or more than MAX_FUTURE_S
    ahead of `now` counts as missing (_usable_ts).
    """
    numeric = _find_field(alert, ["unixTimestamp", "timestamp_unix", "time", "timestamp"],
                          lambda v: _usable_ts(_numeric_ts(v), now))
    if numeric:
        return numeric
    raw = alert.get("timestamp")
    if isinstance(raw, str):
        try:
            parsed = _usable_ts(datetime.strptime(raw, "%d.%m.%y %H:%M:%S").timestamp(), now)
        except ValueError:
            parsed = None
        if parsed is not None:
            return parsed
    return now.timestamp()


def _usable_id(value: Any) -> bool:
    """An id worth keying a job on: not null, not a bare boolean, and with a character that survives
    sanitizing (an id of "!!!" would otherwise collapse to the same "alert" for every such alert)."""
    if value is None or isinstance(value, bool):
        return False
    return bool(_ID_CHAR.search(str(value)))


def _usable_name(value: Any) -> bool:
    return value is not None and not isinstance(value, bool) and bool(str(value).strip())


def synthesized_id(timestamp: float, client_ip: str | None, server_ip: str | None,
                   server_port: int | None, protocol: str | None, name: Any) -> str:
    """`alert_<ts>_<8 hex>` for an alert that carries no usable id.

    The hash covers the fields that identify the event, so two different alerts in the same second no
    longer share an id (and a job), while the same webhook delivered twice maps to the same id, which is
    what the redelivery check needs.
    """
    key = "|".join(str(x) for x in (int(timestamp), client_ip, server_ip, server_port, protocol, name))
    return f"alert_{int(timestamp)}_{hashlib.sha1(key.encode()).hexdigest()[:8]}"


def parse_alert(alert: dict, *, now: datetime | None = None) -> ParsedAlert:
    """Normalize a raw Sycope alert dict into a ParsedAlert.

    The flow fields (client/server IP, port, protocol) and timestamp are resolved via _find_field's
    truthiness gate. The id is the first usable one of `id`, `alertId`; the name the first non-empty of
    `name`, `alertName`. When there is no usable id one is synthesized (synthesized_id), so a null or
    missing id no longer collapses distinct alerts onto one link.
    """
    now = now or datetime.now()
    client_ip = _find_field(alert, ["clientIp", "srcIp", "src_ip", "sourceIp", "source"], _ip)
    server_ip = _find_field(alert, ["serverIp", "dstIp", "dst_ip", "destIp", "destination"], _ip)
    server_port = _find_field(alert, ["serverPort", "dstPort", "dst_port", "destPort"], _port)
    protocol = _find_field(alert, ["protocolName", "protocol", "proto", "ipProtocol"], _proto)
    timestamp = _resolve_timestamp(alert, now)

    alert_name = next((alert[k] for k in ("name", "alertName") if k in alert and _usable_name(alert[k])),
                      "Unknown")
    alert_id = next((alert[k] for k in ("id", "alertId") if k in alert and _usable_id(alert[k])), None)
    if alert_id is None:
        alert_id = synthesized_id(timestamp, client_ip, server_ip, server_port, protocol, alert_name)

    return ParsedAlert(
        client_ip=client_ip,
        server_ip=server_ip,
        server_port=server_port,
        protocol=protocol,
        timestamp=timestamp,
        alert_id=alert_id,
        alert_name=alert_name,
    )


# Fields copied from the webhook payload for the status pages. Only short scalars
# (and short lists of them) are kept; the full payload is never stored.
_META_KEYS = ("ruleType", "ruleId", "severity", "score", "alertFlagThresholdLevel",
              "mitreTactic", "mitreTechnique", "mitreSubtechnique", "mitreId", "definitionId",
              "interval", "timeRange", "timestamp")


def _short(value: Any, limit: int = 200) -> str | int | float | None:
    if isinstance(value, bool) or value is None:
        return None if value is None else str(value)
    if isinstance(value, (int, float)):
        # JSON NaN/Infinity (1e400 too) stored here made the JSON status pages answer 500
        return value if isinstance(value, int) or math.isfinite(value) else None
    if isinstance(value, str):
        return value[:limit]
    if isinstance(value, list) and all(isinstance(v, (str, int, float)) for v in value):
        return ", ".join(str(v) for v in value)[:limit]
    return None


def alert_meta(alert: dict, parsed: ParsedAlert) -> dict:
    """What an analyst wants to see next to a PCAP: which alert it is, when, which flow.

    Keys: name, alertId, alertTime (UTC epoch seconds), client/server/port/protocol (validated
    values from parse_alert) plus the whitelisted payload fields in _META_KEYS and the alert's
    tags/alertKeys. Missing fields are simply absent.
    """
    meta: dict[str, Any] = {
        "name": _short(parsed.alert_name), "alertId": _short(parsed.alert_id),
        "alertTime": parsed.timestamp, "clientIp": parsed.client_ip,
        "serverIp": parsed.server_ip, "serverPort": parsed.server_port,
        "protocol": parsed.protocol,
    }
    for key in _META_KEYS + ("tags", "alertKeys"):
        if key in alert:
            val = _short(alert[key])
            if val not in (None, ""):
                meta[key] = val
    return {k: v for k, v in meta.items() if v is not None}
