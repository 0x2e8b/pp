#!/usr/bin/env python3
"""Sycope Traffic Recorder installer: asks, checks, installs, reports, remembers.

    sudo tools/install/install.sh                  interactive (asks only what it does not know)
    sudo tools/install/install.sh --profile full   n2disk + recorder + nProbe (also: recorder-only, probe-only)
    sudo tools/install/install.sh --check          look only: no questions, no changes
    sudo tools/install/install.sh --dry-run        show what would be changed
    sudo tools/install/install.sh --redo stack,profiles    run these steps again
    sudo tools/install/install.sh --from-scratch   run every step again (ask all questions again)
    sudo tools/install/install.sh --status         the report of the last run
    sudo tools/install/install.sh --replace-licence   install the given licence file even over a valid one
    sudo tools/install/install.sh --update-passthrough   set the recorder's password in the Sycope Passthrough again
    sudo tools/install/install.sh --licence [n2disk.license nprobe.license]   install licences delivered later
                                                   (also those copied into the inbox), start what they unlock
    tools/install/install.sh --licence-request     the SystemIDs and the text to ask for licences
    sudo tools/install/uninstall.sh                remove the installation (keeps the licences and the PCAPs)

The n2disk licence (/etc/*.license) is copied to /var/lib/sycope-recorder-installer/licence-backup before
anything else, never replaced while valid unless --replace-licence is given, and checked again at the end.

It remembers its answers and the result of every step in /var/lib/sycope-recorder-installer
(the Sycope and recorder passwords in secrets.json, mode 600). A step whose last result was ok and
whose inputs did not change is not run again. It never deletes the contents of the PCAP
directories. Steps: see tools/install/recorder_install/steps.py.
"""

from __future__ import annotations

import argparse
import fcntl
import ipaddress
import json
import os
import re
import socket
import sys
import time
from datetime import datetime

sys.dont_write_bytecode = True  # run as root from a user's checkout: leave no root-owned .pyc behind
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from recorder_install import VERSION  # noqa: E402
from recorder_install import destination as ds  # noqa: E402
from recorder_install import legacy  # noqa: E402
from recorder_install import licence  # noqa: E402
from recorder_install import licence_inbox as li  # noqa: E402
from recorder_install import nprobe as np_  # noqa: E402
from recorder_install import paths  # noqa: E402
from recorder_install import report as rpt  # noqa: E402
from recorder_install import steps as st  # noqa: E402
from recorder_install import sycope as sy  # noqa: E402
from recorder_install import triage as tg  # noqa: E402
from recorder_install.state import Store  # noqa: E402
from recorder_install.system import Host, Runner  # noqa: E402
from recorder_install.ui import Console, MissingAnswer  # noqa: E402

REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
RELEASE_FILES = ("compose.yaml", "Dockerfile", "pyproject.toml", "src/sycope_recorder")
STATE_DIR = "/var/lib/sycope-recorder-installer"
ENV_ANSWERS = {  # answer key -> environment variable (the names of the earlier shell installer)
    "install_dir": "INSTALL_DIR", "capture_iface": "CAPTURE_IFACE", "public_host": "SR_PUBLIC_HOST",
    "rolling_dir": "ROLLING_DIR", "alerts_dir": "ALERTS_DIR", "rolling_limit": "ROLLING_LIMIT",
    "rolling_shrink": "ROLLING_SHRINK",
    "chunk_seconds": "CHUNK_SECONDS", "packet_slicing": "PACKET_SLICING", "capture_filter": "CAPTURE_FILTER",
    "basic_auth_user": "BASIC_AUTH_USER", "allowed_ips": "ALLOWED_IPS",
    "passthrough_name": "PASSTHROUGH_NAME", "destination_name": "DESTINATION_NAME", "license_file": "N2DISK_LICENSE_FILE",
    "sycope_url": "SYCOPE_URL", "sycope_user": "SYCOPE_USER", "profile": "INSTALL_PROFILE",
    "triage": "INSTALL_TRIAGE", "triage_src": "TRIAGE_SRC", "triage_dir": "TRIAGE_DIR", "triage_port": "TRIAGE_PORT",
    "triage_passthrough_name": "TRIAGE_PASSTHROUGH_NAME", "triage_sycope_user": "TRIAGE_SYCOPE_USER",
    "triage_memory_mb": "TRIAGE_MEMORY_MB", "https_port": "SR_HTTPS_PORT", "http_port": "SR_HTTP_PORT",
    "collector": "SYCOPE_COLLECTOR", "nprobe_instances": "NPROBE_INSTANCES", "nprobe_license_file": "NPROBE_LICENSE_FILE",
}
ENV_SECRETS = {"sycope_pass": "SYCOPE_PASS", "basic_auth_pass": "BASIC_AUTH_PASS",
               "triage_sycope_pass": "TRIAGE_SYCOPE_PASS"}


# ---- answers ---------------------------------------------------------------------------------
def v_iface(host: Host):
    def check(value: str) -> str | None:
        nic = next((n for n in host.nics() if n["name"] == value), None)
        if nic is None:
            return f"no such interface (physical interfaces: {', '.join(n['name'] for n in host.nics())})"
        return f"{value} has the IPv4 address {nic['ipv4']}: the capture NIC must have none" if nic["ipv4"] else None
    return check


def v_limit(host: Host | None = None, a: dict | None = None):
    """The rolling limit: a percentage, or MB of at least st.MIN_ROLLING_MB (see st.limit_problem). With
    the host and the answers, a percentage is also checked against the size of the capture volume."""
    def check(value: str) -> str | None:
        total = host.disk_total_gb(a["rolling_dir"]) * 1024 if host is not None and a and a.get("rolling_dir") else None
        return st.limit_problem(value, total)
    return check


def confirm_buffer_cut(console: Console, a: dict, host: Host, accepted: bool) -> bool:
    """True when the answered rolling limit may be used. It may not when n2disk would delete capture
    history to fit under it and nobody agreed: asked at the terminal, and without one only `accepted`
    (the answer rolling_shrink=yes, ROLLING_SHRINK=yes) lets it through."""
    total = host.disk_total_gb(a["rolling_dir"]) * 1024
    cut = st.buffer_cut(a, total, host.dir_used_mb(a["rolling_dir"]), st.current_rolling_limit(a["capture_iface"]))
    if cut is None:
        return True
    used, new = cut
    console.say(f"  The rolling buffer in {a['rolling_dir']} holds {used / 1024:.0f} GB. With the limit "
                f"{a['rolling_limit']} ({new / 1024:.1f} GB) n2disk deletes the oldest {(used - new) / 1024:.0f} GB "
                "of recorded traffic when it starts. That capture cannot be brought back.")
    if accepted:
        console.say("  Accepted by the answer rolling_shrink=yes.")
        return True
    if not console.interactive:
        raise MissingAnswer(f"rolling_limit: {a['rolling_limit']} would make n2disk delete {(used - new) / 1024:.0f} GB "
                            "of the rolling buffer; choose a larger limit, or accept it with the answer "
                            "rolling_shrink=yes (ROLLING_SHRINK=yes)")
    return console.confirm("Let n2disk delete that part of the buffer?", False)


def v_chunk(value: str) -> str | None:
    return None if value.isdigit() and 60 <= int(value) <= 3600 else "a number of seconds between 60 and 3600"


def v_slicing(value: str) -> str | None:
    return None if value in ("off", "2", "3", "4") else "off, 2, 3 or 4"


# A capture filter goes verbatim into a configuration file that root's n2disk reads, so it is kept to
# the characters a BPF expression needs. Not a shell: n2disk reads the file itself, nothing is expanded.
# The point is that a stray quote, newline or '#' cannot add or comment out a line of the config.
_FILTER_OK = re.compile(r"[A-Za-z0-9 ()\[\]:./!<>=&|+*-]*")


def v_filter(host: Host):
    """A capture filter: BPF characters only, and it must compile.

    Everything the filter drops is gone for good - it never reaches the buffer and cannot be
    extracted later - so a filter that does not compile must stop the installer rather than
    leave n2disk refusing to start (or, worse, recording something other than intended).
    """
    def check(value: str) -> str | None:
        if not _FILTER_OK.fullmatch(value):
            return "a BPF expression, e.g. 'host 10.0.0.1 and tcp port 443' (no quotes, newlines or '#')"
        if len(value) > 400:
            return "too long for the n2disk configuration (400 characters)"
        return None if host.bpf_compiles(value) else "not a valid BPF expression (tcpdump rejects it)"
    return check


def v_cidrs(value: str) -> str | None:
    try:
        for part in value.split():
            ipaddress.ip_network(part, strict=False)
    except ValueError as exc:
        return f"not a list of CIDR networks separated by spaces: {exc}"
    return None


def v_host(value: str) -> str | None:
    return "a host name or IP address, without https://" if "/" in value or " " in value else None


def v_url(value: str) -> str | None:
    return None if re.fullmatch(r"https?://[^\s/]+(:\d+)?/?", value) else "like https://sycope.example or https://10.0.0.5:8443"


def v_name(value: str) -> str | None:
    return None if re.fullmatch(r"[A-Za-z0-9_-]+", value) else "letters, digits, - and _ only"


def v_profile(value: str) -> str | None:
    return None if value in st.PROFILES else "one of " + ", ".join(st.PROFILES)


def v_collector(value: str) -> str | None:
    host, _, port = value.rpartition(":") if re.search(r":\d+$", value) else (value, "", "")
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
            return "an IP address or host name, optionally with :port (UDP, default 2055)"
    return None if not port or 0 < int(port) < 65536 else "port must be 1-65535"


def v_yesno(value: str) -> str | None:
    return None if value in ("yes", "no") else "yes or no"


def v_host_port(host: Host, own_dir: str, taken: tuple[str, ...] = ()):
    """A host port for a published container port: free, or held by the stack in `own_dir` itself."""
    own = "docker:" + st._project_name(own_dir)

    def check(value: str) -> str | None:
        if not (value.isdigit() and 1 <= int(value) < 65536):
            return "a TCP port 1-65535"
        if value in taken:
            return f"{value} is already used by the recorder"
        holder = host.port_holder(value)
        return None if holder in (None, own) else f"{value} is taken by {holder}"
    return check


def free_port(host: Host, own_dir: str, candidates: tuple[str, ...], taken: tuple[str, ...] = ()) -> str:
    """The first of `candidates` that is free (or already ours); the first one when none is."""
    check = v_host_port(host, own_dir, taken)
    return next((p for p in candidates if check(p) is None), candidates[0])


def ask_ports(console: Console, ask, a: dict, host: Host, old: dict) -> None:
    """The recorder's HTTPS and HTTP host ports: 443/80 unless another service holds them (a web server, MISP)."""
    d = a["install_dir"]
    https = free_port(host, d, (old.get("https_port") or "443", "443", "8443", "9443", "10443", "18443"))
    http = free_port(host, d, (old.get("http_port") or "80", "80", "8080", "8081", "9080", "18080"), (https,))
    for port, label in (("443", "HTTPS"), ("80", "HTTP")):
        holder = v_host_port(host, d)(port)
        if holder:
            console.say(f"  {label}: {holder}; the recorder needs another port (links then carry it).")
    ask("https_port", "Recorder HTTPS port on this host", https, v_host_port(host, d))
    ask("http_port", "Recorder HTTP port (redirect to HTTPS only)", http, v_host_port(host, d, (a["https_port"],)))


def v_triage_src(value: str) -> str | None:
    if value == tg.BUNDLED:
        return None if tg.bundled(REPO) else f"no Triage release zip in {os.path.join(REPO, 'bundled')}"
    return None if tg.is_release(value) else ("not a sycope_clusters release (a directory with compose.yaml, Dockerfile, "
                                              "src/sycope_clusters, or such a release as a .zip)")


def v_memory(value: str) -> str | None:
    return None if value.isdigit() and int(value) >= tg.MEMORY_MB else f"a number of MB, at least {tg.MEMORY_MB}"


def v_instances(value: str) -> str | None:
    return None if value.isdigit() and 1 <= int(value) <= 16 else "a number between 1 and 16"


DIR_LABELS = {"install_dir": "the install directory", "rolling_dir": "the rolling capture directory",
              "alerts_dir": "the extracted PCAPs directory", "triage_dir": "the Triage install directory"}


def v_dir(a: dict, key: str, earlier: tuple[str, ...], state_dir: str = STATE_DIR):
    """A directory answer (paths.problem): checked against the directories answered before it, the release the
    installer runs from (the install directory may be that release itself) and the installer's state.

    Every route goes through `ask`: the answers file and the environment (an error stops the run), a stored
    answer (the default of the question: asked again on a terminal, an error without one).
    """
    def check(value: str) -> str | None:
        others = [(DIR_LABELS[k], a.get(k), False) for k in earlier]
        others += [("the release this installer runs from", REPO, key == "install_dir"),
                   ("the installer's state", state_dir, False)]
        return paths.problem(value, others, top_level_ok=key in ("rolling_dir", "alerts_dir"))
    return check


def v_file(value: str) -> str | None:
    return None if os.path.isfile(value) else "no such file"


def collect(console: Console, store: Store, host: Host, args, file_answers: dict) -> tuple[dict, dict, dict | None]:
    """Fill the answers (from the answers file, the environment, the stored ones, or by asking)."""
    a = dict(store.answers)
    sec = dict(store.secrets)

    def pre(key: str):
        return file_answers.get(key) or os.environ.get(ENV_ANSWERS.get(key, "")) or None

    def ask(key, prompt, default, validate=None, required=True, secret=False):
        given = pre(key)
        if given is not None:  # given explicitly: use it, but still check it
            err = validate(given) if validate else None
            if err:
                raise MissingAnswer(f"{key}: {err}")
            a[key] = given
            return
        a[key] = console.ask(key, prompt, a.get(key) or default, validate=validate, required=required, secret=secret)

    console.section("Questions")
    console.say("  Press Enter to accept the value in brackets.")
    console.say("  Profiles: recorder-only = n2disk + recorder; full = n2disk + recorder + nProbe; "
                "probe-only = nProbe (flows to Sycope, no PCAP recording).")
    ask("profile", "Install profile", st.DEFAULT_PROFILE, v_profile)
    nics = [n for n in host.nics()]
    cands = [n["name"] for n in nics if not n["ipv4"]]
    if nics:
        console.say("  Network interfaces:")
        for n in nics:
            console.say(f"    {n['name']:<10} {n['mac']}  link {'up' if n['carrier'] else 'down'}  "
                        f"{'IPv4 ' + ','.join(n['ipv4']) if n['ipv4'] else 'no IPv4 (capture candidate)'}")
    ext = legacy.find_external_n2disk(host.r) if st.records(a) else None
    if ext:
        if legacy.recording(ext):
            console.say(f"  n2disk already records here: {legacy.describe(ext)}. The installer adopts it as it is")
        else:
            console.say(f"  n2disk is set up here but does not record ({ext['state']}; an expired licence?): "
                        f"{legacy.describe(ext)}. The installer adopts it as it is")
        console.say("  (no new n2disk, no change to its configuration, no restart); the recorder is set up to match it.")
    ext_iface = ((ext or {}).get("options") or {}).get("iface")
    ask("capture_iface", "Capture NIC (receives the mirrored traffic, no IP address)",
        ext_iface or (cands[0] if len(cands) == 1 else None), v_iface(host))
    if st.probes(a):
        ask("collector", "Sycope flow collector for nProbe (IP[:port], UDP, IPFIX)", None, v_collector)
        ask("nprobe_instances", "nProbe instances (1 up to ~1-2 Gbit/s; see README_SIZING.md)", "1", v_instances)
        ask("nprobe_license_file", "Path of the nProbe licence file (Enter to skip)", None, v_file, required=False)
    if not st.records(a):
        return a, sec, None
    # An earlier deployment (README_DEPLOY section 12): its .env and its n2disk give the defaults.
    old = legacy.env_defaults(pre("install_dir") or a.get("install_dir") or "/opt/sycope-recorder")
    ask("public_host", "Host or IP that appears in links and the TLS name", old.get("public_host") or host.primary_ip() or None,
        v_host)
    ask("install_dir", "Install directory", "/opt/sycope-recorder", v_dir(a, "install_dir", (), store.dir))
    ask_ports(console, ask, a, host, old)
    ext_opts = (ext or {}).get("options", {})
    ask("rolling_dir", "n2disk output directory (the rolling capture)",
        ext_opts.get("timeline_dir") or ext_opts.get("dump_dir") or old.get("rolling_dir") or "/storage/pcaps/rolling",
        v_dir(a, "rolling_dir", ("install_dir",), store.dir))
    ask("alerts_dir", "Directory for extracted PCAPs", old.get("alerts_dir") or "/storage/pcaps/alerts",
        v_dir(a, "alerts_dir", ("install_dir", "rolling_dir"), store.dir))
    if ext:
        console.say("  n2disk is managed outside the installer: its size limit, file duration, slicing and filter stay")
        console.say("  as they are in its configuration. The recorder only has to wait as long as its files last.")
        dur = ext_opts.get("duration")
        ask("chunk_seconds", "n2disk file duration in seconds (= SR_CHUNK_SECONDS)",
            dur if dur and dur.isdigit() else old.get("chunk_seconds") or "300", v_chunk)
        a.setdefault("rolling_limit", ext_opts.get("disk_limit") or "60%")  # not used while n2disk is external
        a.setdefault("packet_slicing", "off")
        a.setdefault("capture_filter", "")
        return _collect_rest(console, a, sec, ask, pre, file_answers, old, host)
    while True:
        ask("rolling_limit", "Rolling capture size limit (% of the volume, e.g. 60%, or MB, e.g. 81920)", "60%",
            v_limit(host, a))
        if confirm_buffer_cut(console, a, host, str(pre("rolling_shrink") or "").lower() in ("y", "yes")):
            break
        if pre("rolling_limit") is not None:  # given in the answers file or the environment: not asked again
            raise MissingAnswer("rolling_limit: not accepted at the terminal; change the answer")
        a.pop("rolling_limit", None)
    ask("chunk_seconds", "n2disk file duration in seconds (= SR_CHUNK_SECONDS)", "300", v_chunk)
    console.say("  Packet slicing: n2disk writes only the headers of each packet and drops the payload, so the")
    console.say("  rolling buffer holds a longer history on the same disk. It is a capture setting: what is cut")
    console.say("  away is gone from the PCAP for good, and the extracted evidence has no payload either.")
    console.say("    off  whole packets (default): the extracted PCAP is full evidence, payload included.")
    console.say("    4    up to L4: IP and TCP/UDP headers, no payload. Who talked to whom, when, how much.")
    console.say("         Extraction, the BPF filter and the n2disk index all keep working: they use L3/L4 only.")
    console.say("    3    up to L3: IP headers, no ports. Extraction by port no longer matches - rarely useful.")
    console.say("    2    up to L2: Ethernet headers only. The recorder cannot filter such a capture by IP.")
    console.say("  Choose off unless the disk cannot hold the history the customer asks for; 4 is the useful cut.")
    ask("packet_slicing", "Packet slicing (off, 4, 3, 2)", "off", v_slicing)
    console.say("  Capture filter: a BPF expression that narrows what n2disk records at all, so the rolling")
    console.say("  buffer holds a longer history of the traffic that matters. Everything it drops never reaches")
    console.say("  the disk and can never be extracted - unlike packet slicing, which keeps every packet.")
    console.say("  Leave it empty (the default) to record everything; that is the safe choice for evidence.")
    console.say("    e.g.  not host 10.1.2.3            exclude a noisy backup server")
    console.say("          net 10.0.0.0/8               record only internal traffic")
    console.say("  The alert's own filter is applied at extraction, on top of whatever was recorded here.")
    ask("capture_filter", "Capture filter (BPF, Enter for everything)", None, v_filter(host), required=False)
    return _collect_rest(console, a, sec, ask, pre, file_answers, old, host)


def _collect_rest(console: Console, a: dict, sec: dict, ask, pre, file_answers: dict, old: dict, host: Host):
    """The questions after the capture ones: access, licence, the earlier login, Sycope, Triage."""
    console.say("  Allowed networks: only these addresses reach the recorder at all (pages, API, PCAP downloads and the")
    console.say("  webhook), and they still need the login. Sycope's address (from the Sycope URL asked below) and this")
    console.say("  host's own are added, so alerts and the Passthrough keep working; without a Sycope URL, include Sycope.")
    ask("allowed_ips", "Networks allowed to reach the recorder (CIDRs separated by spaces)",
        old.get("allowed_ips") or "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16", v_cidrs)
    ask("basic_auth_user", "API login user", old.get("basic_auth_user") or "sycope")
    d = a["install_dir"]
    if (legacy.legacy_stack(d, st.DEPLOYED) and not os.path.exists(os.path.join(d, "credentials"))
            and not sec.get("basic_auth_pass") and not os.environ.get(ENV_SECRETS["basic_auth_pass"])
            and console.interactive):
        console.say(f"  {d} holds an earlier recorder whose password the installer does not know. Give it to keep it")
        console.say("  (Sycope's webhook and download links may use it), or press Enter for a new one, which the")
        console.say("  installer then puts into the Passthrough (anything else that uses the old one stops working).")
        pw = console.ask("basic_auth_pass", f"Current password of the recorder login '{a['basic_auth_user']}'", None,
                         required=False, secret=True)
        if pw:
            sec["basic_auth_pass"] = pw
    ask("license_file", "Path of the n2disk licence file (Enter to skip)", None, v_file, required=False)

    console.section("Sycope")
    console.say("  The login lets the installer check the alert definitions and create the recorder's Passthrough;")
    console.say("  it is also needed to offer Sycope Triage (asked after a successful login).")
    sycope = None
    for attempt in range(3):
        ask("sycope_url", "Sycope URL (Enter to skip)", None, v_url, required=False)
        if not a.get("sycope_url"):
            break
        ask("sycope_user", "Sycope user", None)
        pw = os.environ.get(ENV_SECRETS["sycope_pass"]) or file_answers.get("sycope_pass")
        if not pw and sec.get("sycope_pass") and (
                not console.interactive or console.confirm("Use the Sycope password stored from the last run?", True)):
            pw = sec["sycope_pass"]
        if not pw:
            pw = console.ask("sycope_pass", "Sycope password", None, secret=True)  # raises when it cannot ask
        a["passthrough_name"] = a.get("passthrough_name") or "recorder"
        ask("passthrough_name", "Name of the Sycope Passthrough that will point at this recorder",
            "recorder", v_name)
        ask("destination_name", "Name of the Sycope External Destination (REST) that posts alerts to it",
            ds.DEFAULT_NAME, v_name)
        sycope = sy.inspect(REPO, a["sycope_url"], a["sycope_user"], pw, a["passthrough_name"])
        if sycope["ok"]:
            sec["sycope_pass"] = pw
            console.item("ok", f"logged in to {a['sycope_url']} ({sycope['defs_active']} active alert definitions)")
            break
        console.item("fail", f"login failed: {sycope['error']}")
        if not console.interactive:
            break
        a.pop("sycope_url", None)
        sec.pop("sycope_pass", None)
    if sec.get("basic_auth_pass") is None and os.environ.get(ENV_SECRETS["basic_auth_pass"]):
        sec["basic_auth_pass"] = os.environ[ENV_SECRETS["basic_auth_pass"]]
    if a.get("sycope_url") and sycope and sycope.get("ok"):
        _collect_triage(console, a, sec, ask, file_answers, host)
    else:
        console.section("Sycope Triage (optional)")
        wanted = str(pre("triage") or a.get("triage") or "no").lower() in ("yes", "y", "true", "1")
        console.item("warn" if wanted else "skip", "Triage needs the Sycope login above (it reads Sycope and gets its own Passthrough); "
                     "run the installer again with the Sycope URL to install it")
        a["triage"] = "no"
    return a, sec, sycope


def _collect_triage(console: Console, a: dict, sec: dict, ask, file_answers: dict, host: Host) -> None:
    console.section("Sycope Triage (optional)")
    console.say("  Sycope Triage (alert triage and clustering) can run beside the recorder: two more containers on")
    console.say(f"  port {tg.DEFAULT_PORT}, reached through its own Sycope Passthrough. It needs about "
                f"{tg.MEMORY_MB} MB of memory")
    avail = tg.mem_available_mb()
    console.say(f"  (capped at that; {avail if avail is not None else '?'} MB available now) and a copy of its release.")
    ask("triage", "Install Sycope Triage too (yes/no)", "no", v_yesno)
    if a["triage"] != "yes":
        return
    zipped = tg.bundled(REPO)
    if zipped and not (file_answers.get("triage_src") or os.environ.get(ENV_ANSWERS["triage_src"])):
        # the package carries its Triage: take it, whatever its version, and remember just "bundled" so that the
        # next package's zip is taken the same way (an earlier answer naming an old zip does not stick)
        a["triage_src"] = tg.BUNDLED
        console.say(f"  Triage release: {zipped} (bundled with the recorder)")
    else:
        found = [p for p in (os.path.join(os.path.dirname(REPO), "sycope_clusters"), os.path.join(REPO, "sycope_clusters"))
                 if tg.is_release_dir(p)]
        ask("triage_src", "Path of the Triage release (sycope_clusters directory or a release zip)",
            found[0] if found else None, v_triage_src)
    ask("triage_dir", "Triage install directory", tg.DEFAULT_DIR,
        v_dir(a, "triage_dir", ("install_dir", "rolling_dir", "alerts_dir")))
    mine = (st.https_port(a), st.http_port(a))
    ask("triage_port", "Triage HTTPS port",
        free_port(host, a["triage_dir"], (tg.DEFAULT_PORT, "8445", "8446", "9444", "18444"), mine),
        v_host_port(host, a["triage_dir"], mine))
    ask("triage_memory_mb", "Triage memory budget in MB (2048; 2560 for ~2M alerts/day)", str(tg.MEMORY_MB), v_memory)
    ask("triage_passthrough_name", "Name of Triage's Sycope Passthrough", tg.DEFAULT_PASSTHROUGH, v_name)
    console.say("  Triage reads alerts, flows, lookups and the audit log with its own Sycope account (a read-only")
    console.say("  account is enough, plus the right to call the recorder's External Destination for Get PCAP).")
    ask("triage_sycope_user", "Sycope user for Triage", a["sycope_user"])
    if a["triage_sycope_user"] != a["sycope_user"]:
        pw = os.environ.get(ENV_SECRETS["triage_sycope_pass"]) or file_answers.get("triage_sycope_pass") \
            or sec.get("triage_sycope_pass")
        if not pw:
            pw = console.ask("triage_sycope_pass", f"Sycope password of {a['triage_sycope_user']}", None, secret=True)
        sec["triage_sycope_pass"] = pw
    else:
        sec.pop("triage_sycope_pass", None)


# ---- run -------------------------------------------------------------------------------------
def next_steps(ctx: st.Ctx) -> list[str]:
    a, notes = ctx.a, []
    if st.probes(a):
        if ctx.extra.get("nprobe_licensed") is False:
            notes.append(f"nProbe licence: install {st.np_.NPROBE_LICENCE} for nProbe SystemID "
                         f"{ctx.extra.get('nprobe_system_id') or '?'} (not the n2disk one) and run this installer again.")
        notes.append(f"Sycope: flows arrive as IPFIX on {st.np_.collector(a)} from this host's management address; "
                     "add %L7_PROTO (IPFIX 35632.118) in Discovery Mode once, to get the nDPI application.")
    if not st.records(a):
        return notes + ["Run the installer again after fixing a warning or failure: finished steps are skipped. "
                        "`--redo <step>` repeats one, `--from-scratch` repeats all."]
    d = a["install_dir"]
    notes.append(f"Recorder login (Basic auth): {d}/credentials (mode 600). Status pages: https://{st.base(a)}/queue")
    if ctx.extra.get("licensed") is False and ctx.extra.get("licence_state") != "unknown":
        notes.append(f"n2disk licence: install {licence.N2DISK_LICENCE} for SystemID {ctx.extra.get('system_id', '?')} and run this "
                     "installer again (recording and the verification of the capture start then).")
    if a.get("sycope_url"):
        host = re.sub(r"^https?://", "", a["sycope_url"]).rstrip("/")
        name = a["passthrough_name"]
        notes += [
            (f"Sycope Passthrough '{name}': set up by the installer and checked through Sycope." if ctx.extra.get("passthrough_ok")
             else f"Sycope Passthrough '{name}' (the installer could not set it up, see above): upstream "
                  f"https://{st.base(a)}, Basic auth user {a['basic_auth_user']} with the password from "
                  f"{d}/credentials, verify TLS off (internal CA), access rules GET ^/([A-Za-z0-9_-]+)?/?$, "
                  "GET ^/downloads/.*, POST ^/.*"),
            (f"Sycope External Destination '{ctx.extra['destination']}': set up by the installer; choose it as the "
             "action of the alert definitions that should record." if ctx.extra.get("destination")
             else f"Sycope External Destination (REST client, the installer could not set it up, see above): HTTPS, "
                  f"host {host.split(':')[0]}, port {host.split(':')[1] if ':' in host else '443'}, POST "
                  f"/npm/api/v1/passthrough/{name}/extract, Basic auth with a Sycope account "
                  "(no trailing slash, no filter/before/after parameters: profiles decide)."),
            f"Links returned to Sycope start with https://{host}/npm/api/v1/passthrough/{name}/<alertId>.",
        ]
        dead = ctx.extra.get("dead_destinations") or []
        if dead:
            notes.append("NOT RECORDING: the External Destination" + ("s " if len(dead) > 1 else " ")
                         + ", ".join(f"'{d}'" for d in dead) + " post" + ("" if len(dead) > 1 else "s")
                         + " to a Passthrough that no longer exists in Sycope. Alert definitions that use "
                         + ("them" if len(dead) > 1 else "it") + " as their action record nothing until they are "
                         f"given the destination of this install, or the path is changed to "
                         f"/npm/api/v1/passthrough/{name}/extract.")
    notes.append("Run the installer again after fixing a warning or failure: finished steps are skipped. "
                 "`--redo <step>` repeats one, `--from-scratch` repeats all.")
    return notes


def run_steps(ctx: st.Ctx, console: Console, store: Store, args, redo: set[str]) -> list[rpt.Section]:
    """Run every step; a step that raises is a `fail` item and the run goes on (the licence guard still runs).

    Each step's result is written to state.json as soon as it is known, so a run killed in the middle
    leaves the finished steps recorded and the next run continues from the one that did not finish.
    """
    sections, crashed = [], set()
    chosen = st.profile(ctx.a)
    for step in st.STEPS:
        if chosen not in step.profiles:
            continue  # not part of this host's profile; a step of another profile is never undone here
        fp = store.fingerprint(step.version, step.keys)
        forced = (args.from_scratch or step.id in redo
                  or (step.id in ("n2disk", "nprobe") and bool(ctx.extra.get("replace_licence")))
                  or (step.id == "passthrough" and bool(ctx.extra.get("update_passthrough")))
                  or (step.id == "e2e" and bool(ctx.extra.get("stack_deployed"))))
        console.section(step.title)
        blocked = [n for n in step.needs if n in crashed]
        if blocked and not args.check:
            res = rpt.Result().add(step.title, "skip", f"not run: {', '.join(blocked)} did not complete",
                                   "fix that and run the installer again")
            for i in res.items:
                console.item(i.status, f"{i.name}: {i.detail}")
            sections.append(rpt.Section(step.id, step.title, res, True))
            crashed.add(step.id)  # whatever needs this step must wait as well
            continue
        try:
            if step.always or args.check:
                res, ran = step.fn(ctx, False), True
            else:
                res = step.fn(ctx, False)
                if res.status == "ok" and store.unchanged(step.id, fp) and not forced:
                    ran = False
                else:
                    res, ran = step.fn(ctx, True), True
        except Exception as exc:
            crashed.add(step.id)
            res, ran = rpt.Result().add(step.title, "fail", f"{type(exc).__name__}: {exc}",
                                        "fix the cause and run the installer again: it continues from this step"), True
        if not ran:
            for i in res.items:
                i.status = "unchanged" if i.status == "ok" else i.status
        for i in res.items:
            console.item(i.status, f"{i.name}" + (f": {i.detail}" if i.detail else ""))
            if i.hint and i.status in ("warn", "fail"):
                console.say(f"           -> {i.hint}")
        sections.append(rpt.Section(step.id, step.title, res, ran))
        if ran and not (args.check or args.dry_run) and not step.always:
            store.record(step.id, res.status, fp, "; ".join(i.detail for i in res.items if i.status != "ok")[:300])
            store.save()
    return sections


def licence_backup_section(console: Console, runner: Runner, now: datetime) -> tuple[rpt.Section, dict, str | None]:
    """Take the first licence snapshot and the backup (before any step). Raises on a failure to back up.

    Returns the report section, the snapshot, and the directory that holds the backup of this state
    (the new one, or the existing one that was already identical).
    """
    res = rpt.Result()
    snap = licence.snapshot(runner)
    taken = licence.backup(runner, snap, now)
    directory = taken or (licence.latest_backup() if snap["files"] else None)
    if not snap["files"]:
        res.add("licence files", "ok", f"none in {os.path.dirname(licence.LICENCE_GLOB)} (nothing to back up)")
    elif taken:
        res.add("licence backup", "ok", f"{len(snap['files'])} file(s) copied to {taken}")
    else:
        res.add("licence backup", "ok", f"the licence is already backed up in {directory}")
    if directory:
        res.add("restore command", "ok", licence.restore_command(directory))
    if snap.get("n2disk_tries", 1) > 1:
        res.add("n2disk -V", "ok" if snap["n2disk_state"] != "unknown" else "warn",
                f"{'answered' if snap['n2disk_state'] != 'unknown' else 'gave no answer'} after {snap['n2disk_tries']} tries")
    if snap["files"]:
        state = snap.get("n2disk_state", "unknown")
        res.add("licence", "ok" if state == "valid" else "warn",
                f"SystemID {snap['system_id'] or 'unknown'}, n2disk licence "
                + {"valid": "valid", "invalid": "missing or invalid", "unknown": "validity unknown (n2disk -V gave no answer)"}[state])
    for i in res.items:
        console.item(i.status, f"{i.name}: {i.detail}")
    return rpt.Section("licence_backup", "Licence backup", res, True), snap, directory


def licence_guard_section(console: Console, runner: Runner, before: dict, directory: str | None, written: dict) -> rpt.Section:
    """Compare the licence now with the snapshot from the start; a loss is a `fail` with the restore command."""
    res = rpt.Result()
    console.section("Licence guard")
    try:
        after = licence.snapshot(runner)
        for status, name, detail, hint in licence.compare(before, after, written, directory):
            res.add(name, status, detail, hint)
        if after.get("n2disk_tries", 1) > 1:
            res.add("n2disk -V", "ok" if after["n2disk_state"] != "unknown" else "warn",
                    f"answered after {after['n2disk_tries']} tries" if after["n2disk_state"] != "unknown"
                    else f"gave no answer in {after['n2disk_tries']} tries")
    except Exception as exc:  # cannot look: that is not "all is well"
        res.add("licence", "fail", f"cannot read the licence after the run: {type(exc).__name__}: {exc}",
                f"restore from the backup if needed: {licence.restore_command(directory)}" if directory else "")
    for i in res.items:
        console.item(i.status, f"{i.name}: {i.detail}")
        if i.hint and i.status in ("warn", "fail"):
            console.say(f"           -> {i.hint}")
    return rpt.Section("licence_guard", "Licence guard", res, True)


def wipe_stack(console: Console, ctx: st.Ctx, args) -> None:
    d = ctx.a["install_dir"]
    if not os.path.exists(os.path.join(d, "compose.yaml")):
        return
    refused = st.foreign_install_dir(ctx, d, legacy.legacy_stack(d, st.DEPLOYED), st.read_env(os.path.join(d, ".env")))
    if refused:  # `down -v` deletes the volumes of whatever compose project lives there
        console.say(f"  --wipe-stack: nothing wiped: {refused}.")
        return
    console.say(f"  --wipe-stack: this stops the recorder and deletes its Docker volumes (job history, Caddy data) in {d}.")
    console.say("  PCAPs in the rolling and alerts directories are never touched.")
    if not (args.yes or console.confirm("Continue?", False)):
        raise SystemExit("aborted")
    ctx.r.run(st._compose(ctx, "down", "-v"))


# ---- --licence ---------------------------------------------------------------------------------
def licence_mode(args) -> int:
    """Install the licences given as files and those in the inbox, then start what they unlock.

    Only the licence path: backup first, the guarded install per product, n2disk/nProbe started through their
    configuration steps (with the remembered answers), the guard at the end. No questions, no other step.
    """
    console = Console(False)
    store = Store(args.state_dir).load()
    runner = Runner(log=lambda m: console.say(f"           {m}"))
    console.say(f"Sycope Traffic Recorder installer {VERSION}  [licences]")
    candidates = [os.path.abspath(f) for f in args.files] + li.inbox_files()
    console.section("Licence backup")
    try:
        backup_section, before, backup_dir = licence_backup_section(console, runner, datetime.now())
    except (OSError, licence.BackupError) as exc:
        console.item("fail", f"the licence could not be backed up: {exc}; nothing was changed")
        return 2
    a = dict(store.answers)
    ctx = st.Ctx(a=a, secrets={}, r=runner, host=Host(runner), repo=REPO)
    ctx.extra["replace_licence"] = args.replace_licence
    ctx.extra["licence_backup_dir"] = backup_dir
    console.section("Licences")
    res, installed = rpt.Result(), set()
    stamp = time.strftime("%Y%m%d-%H%M%S")
    if not candidates:
        res.add("licence files", "skip", f"none given and none in {li.INBOX}")
    for n, path in enumerate(candidates):
        name, product = os.path.basename(path), li.product_of(path)
        data, why = li.read_candidate(path) if product else (None, "the name says neither n2disk nor nprobe")
        if data is None:
            res.add(name, "fail", why, "send it as n2disk.license or nprobe.license (plain text)")
            li.file_away(path, False, stamp)
            continue
        one = rpt.Result()
        staged = li.staged_copy(data, product, f"{stamp}-{n}")
        if product == "n2disk":
            ctx.a["license_file"] = staged
            st._install_licence(ctx, one, True)
        else:
            ctx.a["nprobe_license_file"] = staged
            np_.install_licence(ctx, one, True)
        ok = bool(one.items) and one.status == "ok"
        for i in one.items:
            res.add(f"{name} ({product})", i.status, i.detail, i.hint)
        moved = li.file_away(path, ok, stamp)
        if moved:
            res.add(f"{name} filed", "ok", moved)
        if ok:
            installed.add(product)
    for i in res.items:
        console.item(i.status, f"{i.name}: {i.detail}")
    sections = [backup_section, rpt.Section("licences", "Licences", res, True)]
    iface = a.get("capture_iface")
    if "n2disk" in installed and st.records(a) and iface and a.get("rolling_dir"):
        console.section("n2disk")
        runner.run(["systemctl", "reset-failed", f"n2disk@{iface}.service"])
        sections.append(rpt.Section("n2disk_config", "n2disk", st.step_n2disk_config(ctx, True), True))
    if "nprobe" in installed and st.probes(a) and iface and a.get("collector"):
        console.section("nProbe")
        for unit in np_.instance_names(a):
            runner.run(["systemctl", "reset-failed", f"nprobe@{unit}.service"])
        ctx.extra["nprobe_licensed"] = None
        sections.append(rpt.Section("nprobe_config", "nProbe", st.step_nprobe_config(ctx, True), True))
    sections.append(licence_guard_section(console, runner, before, backup_dir, ctx.extra.get("licence_written", {})))
    text = write_request(runner)
    notes = [] if "no valid licence" not in text else ["Still missing (send this to ntop or Sycope support):\n" + text]
    console.section("Report")
    console.say(rpt.render_text(sections, notes, label=lambda s: console.status_label(s), only_problems=True))
    rdir = os.path.join(args.state_dir, "reports")
    os.makedirs(rdir, exist_ok=True)
    meta = {"at": time.strftime("%Y-%m-%d %H:%M:%S"), "host": socket.gethostname(), "version": VERSION, "mode": "licence"}
    md = rpt.render_markdown(sections, notes, meta)
    for fname in (f"licence-{stamp}.md", "licence-latest.md"):
        with open(os.path.join(rdir, fname), "w") as fh:
            fh.write(md)
    return 1 if rpt.counts(sections)["fail"] else 0


def write_request(runner: Runner) -> str:
    """The licence request text, also kept in li.REQUEST for the console menu and the login message."""
    text = li.request_text(li.n2disk_state(runner), li.nprobe_state(runner))
    try:
        os.makedirs(os.path.dirname(li.REQUEST), mode=0o700, exist_ok=True)
        with open(li.REQUEST, "w") as fh:
            fh.write(text)
    except OSError:
        pass  # not root (--licence-request may run as anyone): the text is printed anyway
    return text


LOCK_NAME = "installer.lock"


def take_lock(state_dir: str) -> int:
    """Exclusive, non-blocking lock for the whole run: two installers must not change the host at once.

    Returns the open descriptor (the lock lives as long as it is open); raises BlockingIOError when
    another run holds it.
    """
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    fd = os.open(os.path.join(state_dir, LOCK_NAME), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise
    return fd


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog=__doc__.split("\n\n", 1)[1])
    ap.add_argument("--check", action="store_true", help="inspect only: no questions, no changes")
    ap.add_argument("--dry-run", action="store_true", help="print the changes instead of making them")
    ap.add_argument("--yes", "-y", action="store_true", help="do not ask: use stored answers, environment and defaults")
    ap.add_argument("--redo", default="", help="comma-separated steps to run again: " + ",".join(s.id for s in st.STEPS))
    ap.add_argument("--from-scratch", action="store_true", help="forget the step results and run everything again")
    ap.add_argument("--wipe-stack", action="store_true", help="with --from-scratch: also stop the containers and delete their Docker volumes")
    ap.add_argument("--answers", help="a JSON file with answers (keys as in the state file)")
    ap.add_argument("--profile", choices=st.PROFILES,
                    help="what this host runs (default: the remembered answer, else recorder-only)")
    ap.add_argument("--update-passthrough", action="store_true",
                    help="write the Sycope Passthrough entry again, with the recorder's password")
    ap.add_argument("--replace-licence", action="store_true",
                    help="install the licence file given in the answers even when a valid licence is installed (this run only)")
    ap.add_argument("--licence", action="store_true",
                    help="only install licences: the files given and those in the inbox, then start what they unlock")
    ap.add_argument("--licence-request", action="store_true", help="print the SystemIDs and the licence request text")
    ap.add_argument("files", nargs="*", help="with --licence: licence files (n2disk*.license, nprobe*.license)")
    ap.add_argument("--state-dir", default=STATE_DIR)
    ap.add_argument("--status", action="store_true", help="print the report of the last run")
    args = ap.parse_args(argv)

    if args.status:
        p = os.path.join(args.state_dir, "reports", "latest.md")
        if os.path.exists(p):
            with open(p) as fh:
                print(fh.read())
        else:
            print("no report yet")
        return 0
    if args.licence_request:
        print(write_request(Runner(read_only=True, log=lambda m: None)), end="")
        return 0
    if args.files and not args.licence:
        ap.error("licence files are given with --licence")
    redo = {x for x in args.redo.split(",") if x}
    unknown = redo - {s.id for s in st.STEPS}
    if unknown:
        ap.error(f"unknown step(s): {', '.join(sorted(unknown))}")
    if os.geteuid() != 0:
        print("run as root (sudo)", file=sys.stderr)
        return 2
    missing = [f for f in RELEASE_FILES if not os.path.exists(os.path.join(REPO, f))]
    # The stack step copies REPO to the install directory: it must be the whole release, not a home dir. --licence
    # needs only tools/install: the inbox unit and the menu run it from the root-owned copy (steps.INSTALLER_HOME).
    if missing and not args.licence:
        print(f"{REPO} is not a whole recorder release (missing {', '.join(missing)}): copy the whole release "
              "directory (tools/ alone is not enough) and run its tools/install/install.sh", file=sys.stderr)
        return 2

    lock = None
    if not (args.check or args.dry_run):  # inspection changes nothing, so it may run beside another run
        try:
            lock = take_lock(args.state_dir)
        except BlockingIOError:
            print("another installer run is in progress", file=sys.stderr)
            return 2
        except OSError as exc:
            print(f"cannot take the installer lock in {args.state_dir}: {exc}", file=sys.stderr)
            return 2
    try:
        return licence_mode(args) if args.licence else _run(args, redo)
    finally:
        if lock is not None:
            os.close(lock)


def _run(args, redo: set[str]) -> int:
    """The installer run proper, called by main while it holds the lock (so the backup is always taken under it)."""
    interactive = sys.stdin.isatty() and not (args.yes or args.check)
    console = Console(interactive)
    store = Store(args.state_dir).load()
    runner = Runner(dry=args.dry_run, read_only=args.check, log=lambda m: console.say(f"           {m}"))
    host = Host(runner)
    file_answers = {}
    if args.answers:
        with open(args.answers) as fh:
            file_answers = json.load(fh)
    if getattr(args, "profile", None):
        file_answers["profile"] = args.profile

    console.say(f"Sycope Traffic Recorder installer {VERSION}"
                + ("  [check only]" if args.check else "  [dry run]" if args.dry_run else ""))
    if args.check and not store.loaded and not file_answers:
        console.say("  Nothing is remembered yet: run once without --check (or give --answers).")
        return 2
    backup_section = lic_before = backup_dir = None
    if not (args.check or args.dry_run):
        console.section("Licence backup")
        try:
            backup_section, lic_before, backup_dir = licence_backup_section(console, runner, datetime.now())
        except (OSError, licence.BackupError) as exc:
            console.item("fail", f"the licence could not be backed up: {exc}")
            console.say("  The installer does not continue without a backup of the n2disk licence. Nothing was changed. "
                        f"Fix the cause (disk space and permissions of {licence.BACKUP_ROOT}) and run it again.")
            return 2
    try:
        answers, secrets_, sycope = collect(console, store, host, args, file_answers)
    except MissingAnswer as exc:
        console.say(f"\nMissing or invalid answer: {exc}. Run interactively, or give it in the environment / --answers.")
        return 2
    ctx = st.Ctx(a=answers, secrets=secrets_, r=runner, host=host, repo=REPO, sycope=sycope, dry=args.dry_run)
    ctx.extra["replace_licence"] = args.replace_licence  # this run only: never stored in state.json
    ctx.extra["update_passthrough"] = args.update_passthrough
    ctx.extra["licence_backup_dir"] = backup_dir
    if not (args.check or args.dry_run):
        store.answers, store.secrets = answers, secrets_
        store.save()
    if args.from_scratch:
        store.reset()
        if args.wipe_stack and not (args.check or args.dry_run):
            wipe_stack(console, ctx, args)

    try:
        sections = run_steps(ctx, console, store, args, redo)
    except BaseException:  # Ctrl-C or a bug outside a step: still look at the licence before leaving
        if lic_before is not None:
            licence_guard_section(console, runner, lic_before, backup_dir, ctx.extra.get("licence_written", {}))
        raise
    if lic_before is not None:
        sections.insert(0, backup_section)
        sections.append(licence_guard_section(console, runner, lic_before, backup_dir, ctx.extra.get("licence_written", {})))
    notes = next_steps(ctx)
    mode = "check" if args.check else "dry-run" if args.dry_run else "apply"
    meta = {"at": time.strftime("%Y-%m-%d %H:%M:%S"), "host": socket.gethostname(), "version": VERSION, "mode": mode}
    console.section("Report")
    console.say(rpt.render_text(sections, notes, label=lambda s: console.status_label(s), only_problems=True))
    if not (args.check or args.dry_run):
        store.history.append({**meta, "counts": rpt.counts(sections)})
        store.secrets = ctx.secrets  # the generated Basic-auth password
        store.save()
        rdir = os.path.join(args.state_dir, "reports")
        os.makedirs(rdir, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        md, js = rpt.render_markdown(sections, notes, meta), rpt.to_json(sections, notes, meta)
        for name, text in ((f"report-{stamp}.md", md), (f"report-{stamp}.json", js), ("latest.md", md), ("latest.json", js)):
            with open(os.path.join(rdir, name), "w") as fh:
                fh.write(text)
        console.say(f"\nReport saved: {rdir}/report-{stamp}.md")
    return 1 if rpt.counts(sections)["fail"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
