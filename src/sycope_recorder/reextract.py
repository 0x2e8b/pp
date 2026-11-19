"""An operator's re-extraction of an alert's traffic: another window, optionally another filter.

The web turns the Re-extract form into a Plan for a new job next to the old one (whose file stays). The
filter is never text from the form: it is built here from parsed values only (addresses and networks
through `ipaddress`, ports as integers, the protocol from a fixed list), like every filter the recorder
writes. The root worker checks the row again before it runs (`jobs.validate_job_row`).
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import time
from dataclasses import dataclass

from sycope_recorder.config import Settings
from sycope_recorder.extraction import Plan, local_bound, local_epoch

MAX_SHIFT = 3600     # seconds a side of the window may move (earlier start, later end, or the reverse)
MAX_HOSTS = 16
MAX_PORTS = 16
PROTOCOLS = ("", "tcp", "udp", "icmp")
DIRECTIONS = {"any": "", "src": "src ", "dst": "dst "}
_SUFFIX = re.compile(r"_r\d+$")


class Invalid(ValueError):
    """The form asks for something the recorder will not run; the text says what."""


@dataclass
class Request:
    before: int = 0           # seconds the start moves earlier (negative: later)
    after: int = 0            # seconds the end moves later (negative: earlier)
    custom: bool = False      # False: keep the job's filter
    hosts: tuple = ()         # ((address or network text, "any"|"src"|"dst"), ...)
    match: str = "all"        # how several hosts combine: "all" (and) or "any" (or)
    ports: tuple = ()
    proto: str = ""


def _int(value: object, name: str, lo: int, hi: int) -> int:
    try:
        n = int(str(value if value not in (None, "") else 0).strip())
    except ValueError:
        raise Invalid(f"{name} must be a whole number of seconds") from None
    if not lo <= n <= hi:
        raise Invalid(f"{name} must be between {lo} and {hi} seconds")
    return n


def _list(value: object) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_request(data: dict) -> Request:
    """The Re-extract form (JSON from the page) as a validated Request; Invalid on anything else."""
    req = Request(before=_int(data.get("before"), "Earlier start", -MAX_SHIFT, MAX_SHIFT),
                  after=_int(data.get("after"), "Later end", -MAX_SHIFT, MAX_SHIFT),
                  custom=str(data.get("filter", "keep")) == "custom")
    if not req.custom:
        return req
    addrs, dirs = _list(data.get("addr")), _list(data.get("dir"))
    hosts = []
    for i, raw in enumerate(addrs):
        text = str(raw or "").strip()
        if not text:
            continue
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            raise Invalid(f"{text[:60]!r} is not an IP address or network") from None
        d = str(dirs[i]) if i < len(dirs) else "any"
        if d not in DIRECTIONS:
            raise Invalid("direction must be any, src or dst")
        hosts.append((str(net.network_address) if net.prefixlen == net.max_prefixlen else net.with_prefixlen, d))
    if len(hosts) > MAX_HOSTS:
        raise Invalid(f"at most {MAX_HOSTS} addresses")
    ports = []
    for raw in _list(data.get("port")):
        text = str(raw or "").strip()
        if not text:
            continue
        if not text.isdigit() or not 1 <= int(text) <= 65535:
            raise Invalid(f"{text[:20]!r} is not a port (1-65535)")
        if int(text) not in ports:
            ports.append(int(text))
    if len(ports) > MAX_PORTS:
        raise Invalid(f"at most {MAX_PORTS} ports")
    proto = str(data.get("proto") or "").lower()
    if proto not in PROTOCOLS:
        raise Invalid("protocol must be tcp, udp, icmp or any")
    match = str(data.get("match") or "all")
    if match not in ("all", "any"):
        raise Invalid("match must be all or any")
    req.hosts, req.ports, req.proto, req.match = tuple(hosts), tuple(ports), proto, match
    return req


def _proto_term(req: Request) -> str:
    """BPF `icmp` is ICMP over IPv4 only: with IPv6 addresses the filter needs `icmp6` (both when mixed)."""
    if req.proto != "icmp":
        return req.proto
    v6 = [":" in a for a, _d in req.hosts]
    if v6 and all(v6):
        return "icmp6"
    return "(icmp or icmp6)" if any(v6) or not v6 else "icmp"


def build_filter(req: Request) -> str:
    """The BPF of a custom filter, from validated parts only. Invalid if it would match too much."""
    if req.proto == "icmp" and req.ports:
        raise Invalid("ICMP has no ports: remove the ports or choose another protocol")
    terms = [_proto_term(req)] if req.proto else []
    hs = [f"{DIRECTIONS[d]}{'net' if '/' in a else 'host'} {a}" for a, d in req.hosts]
    if hs:
        terms.append(hs[0] if len(hs) == 1 else "(" + (" and " if req.match == "all" else " or ").join(hs) + ")")
    if req.ports:
        ps = [f"port {p}" for p in req.ports]
        terms.append(ps[0] if len(ps) == 1 else "(" + " or ".join(ps) + ")")
    if not hs and not req.ports:
        raise Invalid("the filter needs at least one address or port (a bare protocol matches everything)")
    return " and ".join(terms)


def new_name(job_id: str, taken: set[str]) -> str:
    """`<stem>_r<n>.pcap` for the n-th extraction of the same alert (n from 2), never a taken name."""
    stem = _SUFFIX.sub("", job_id.removesuffix(".pcap"))
    n = 2
    while f"{stem}_r{n}.pcap" in taken:
        n += 1
    return f"{stem}_r{n}.pcap"


def plan(job: dict, req: Request, settings: Settings, taken: set[str]) -> tuple[Plan, str]:
    """(Plan of the new job, what changed in words). Invalid when the result would not be runnable."""
    # Bounds move as epochs and each is formatted as its own local time, so a clock change between
    # the old and the new bound does not shift it. The end has its exact epoch in the row; the start
    # is read back from its string (local_epoch: the earlier reading in an hour a clock change repeats).
    try:
        begin, begin_epoch = local_bound(local_epoch(job["window_begin"]) - req.before)
        end_epoch = float(job["window_end_epoch"]) + req.after
        end, end_whole = local_bound(end_epoch)
    except (KeyError, TypeError, ValueError, OverflowError, OSError):
        raise Invalid("this job has no usable window") from None
    if begin_epoch >= end_whole:
        raise Invalid("the window would end before it starts")
    bpf = build_filter(req) if req.custom else str(job["bpf"])
    name = new_name(str(job["id"]), taken)
    while os.path.lexists(os.path.join(settings.output_dir, name)):  # a file whose row was pruned
        taken = taken | {name}
        name = new_name(str(job["id"]), taken)
    p = Plan(alert_id=job["alert_id"], filename=name, output_path=os.path.join(settings.output_dir, name),
             begin=begin, end=end, bpf=bpf, window_end_epoch=end_epoch, window_begin_epoch=begin_epoch)
    parts = [f"window {req.before:+d} s before / {req.after:+d} s after"]
    parts.append("filter changed" if req.custom and bpf != job["bpf"] else "same filter")
    return p, ", ".join(parts)


def meta_for(job: dict, req: Request, source_id: str) -> dict:
    """The new job's alert details: the source's, plus what the operator asked for."""
    try:
        meta = json.loads(job.get("alert_meta") or "{}")
    except ValueError:
        meta = {}
    if not isinstance(meta, dict):
        meta = {}
    meta["reextract"] = {"from": source_id, "before": req.before, "after": req.after,
                         "filter": "custom" if req.custom else "keep"}
    return meta


def on_disk_warning(p: Plan, rolling_minutes: int | None, now: float | None = None) -> str:
    """A note when the window starts before the oldest capture the rolling buffer still holds."""
    if rolling_minutes is None:
        return ""
    now = time.time() if now is None else now
    if p.window_begin_epoch < now - rolling_minutes * 60:
        return (f"the rolling buffer holds about {rolling_minutes} min: the start of this window is no longer "
                "on disk, so the file will miss its beginning (or the job ends as a miss)")
    return ""
