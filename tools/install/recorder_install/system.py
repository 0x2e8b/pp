"""Looking at the host and changing it. Probes always run; changes honour --dry-run."""

from __future__ import annotations

import errno
import os
import re
import shutil
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
import urllib.error
import urllib.request


class Runner:
    """Runs commands. `probe` is read-only and always runs; `run` changes the host."""

    def __init__(self, dry: bool = False, read_only: bool = False, log=None) -> None:
        self.dry, self.read_only, self.log = dry, read_only, log or (lambda msg: None)

    def probe(self, cmd, timeout: int = 30, env: dict | None = None,
              input: str | None = None) -> tuple[int, str]:
        """Run a command; `input` goes to its stdin (use it for secrets: arguments show up in `ps`).

        rc 124 means it timed out (like coreutils `timeout`), 127 that it could not be started (not found).
        """
        try:
            p = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True,
                               timeout=timeout, env={**os.environ, **(env or {})}, input=input)
        except subprocess.TimeoutExpired as exc:
            return 124, f"timed out after {timeout} s: {exc.cmd if isinstance(exc.cmd, str) else ' '.join(map(str, exc.cmd))}"
        except OSError as exc:
            return 127, str(exc)
        return p.returncode, (p.stdout + p.stderr).strip()

    def run(self, cmd, timeout: int = 1800, env: dict | None = None,
            input: str | None = None) -> tuple[int, str]:
        if self.read_only:
            raise RuntimeError(f"refusing to change the host in check mode: {cmd}")
        self.log(f"+ {cmd if isinstance(cmd, str) else ' '.join(map(str, cmd))}")
        if self.dry:
            return 0, ""
        return self.probe(cmd, timeout=timeout, env=env, input=input)

    def run_live(self, cmd, timeout: int = 1800) -> tuple[int, str]:
        """`run`, with the command's output shown line by line as it comes (docker builds take minutes and the
        operator should see that something happens). Returns the whole output like `run`. A test double that
        replaces `run` keeps its own behaviour here."""
        if type(self).run is not Runner.run or self.dry or self.read_only:
            return self.run(cmd, timeout=timeout)
        self.log(f"+ {cmd if isinstance(cmd, str) else ' '.join(map(str, cmd))}")
        try:
            p = subprocess.Popen(cmd, shell=isinstance(cmd, str), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, errors="replace", env={**os.environ, "COMPOSE_PROGRESS": "plain"})
        except OSError as exc:
            return 127, str(exc)
        killed = []
        timer = threading.Timer(timeout, lambda: (killed.append(1), p.kill()))
        timer.start()
        lines = []
        try:
            assert p.stdout is not None
            for line in p.stdout:
                line = line.rstrip()
                lines.append(line)
                if line.strip():
                    self.log("| " + line[:160])
            rc = p.wait()
        finally:
            timer.cancel()
        out = "\n".join(lines).strip()
        return (124, f"timed out after {timeout} s\n{out}") if killed else (rc, out)

    def write(self, path: str, content: str | bytes, mode: int | None = None) -> None:
        """Write a file atomically: a temp file in the same directory, fsync, then rename over the target.

        A crash or a full disk leaves the old file whole instead of a truncated one, which matters for
        the n2disk licence above all. An existing target keeps its owner and group, and its mode unless
        `mode` is given (a new file gets `mode`, default 0644). A symlink at `path` is refused: writing
        through it would change some other file. Bytes are written as they are.
        """
        if self.read_only:
            raise RuntimeError(f"refusing to write {path} in check mode")
        if os.path.islink(path):
            raise OSError(errno.ELOOP, "refusing to write through a symlink", path)
        if self.dry:
            self.log(f"+ write {path} ({len(content)} bytes)")
            return
        data = content.encode() if isinstance(content, str) else content
        old = os.stat(path) if os.path.exists(path) else None
        if mode is None:
            mode = stat.S_IMODE(old.st_mode) if old else 0o644
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = f"{path}.tmp-{os.getpid()}"
        try:
            os.unlink(tmp)  # a leftover of a crashed run with the same pid
        except FileNotFoundError:
            pass
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            if old is not None:
                os.chown(tmp, old.st_uid, old.st_gid)
            os.chmod(tmp, mode)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


class Host:
    """Facts about the machine. Tests replace this with a fake."""

    def __init__(self, runner: Runner) -> None:
        self.r = runner

    def os_release(self) -> dict[str, str]:
        out = {}
        try:
            with open("/etc/os-release") as fh:
                for line in fh:
                    if "=" in line:
                        k, v = line.strip().split("=", 1)
                        out[k] = v.strip('"')
        except OSError:
            pass
        return out

    def arch(self) -> str:
        return os.uname().machine

    def is_root(self) -> bool:
        return os.geteuid() == 0

    def cpu_count(self) -> int:
        return os.cpu_count() or 1

    def mem_mb(self) -> int:
        try:
            with open("/proc/meminfo") as fh:
                for line in fh:
                    if line.startswith("MemTotal:"):
                        return int(line.split()[1]) // 1024
        except OSError:
            pass
        return 0

    @staticmethod
    def _existing(path: str) -> str:
        while path and not os.path.exists(path):
            parent = os.path.dirname(path)
            if parent == path:
                break
            path = parent
        return path or "/"

    def disk_free_gb(self, path: str) -> float:
        return shutil.disk_usage(self._existing(path)).free / 1024**3

    def disk_total_gb(self, path: str) -> float:
        return shutil.disk_usage(self._existing(path)).total / 1024**3

    def dir_used_mb(self, path: str) -> float | None:
        """MB the files under `path` take, or None when it cannot be told. A directory that is a volume
        of its own is answered by the filesystem (no walk over a large capture); any other by `du`."""
        if not os.path.isdir(path):
            return 0.0
        if os.path.ismount(path):
            return shutil.disk_usage(path).used / 1024**2
        rc, out = self.r.probe(["du", "-sm", "--one-file-system", path], timeout=300)
        try:
            return float(out.split()[0]) if rc == 0 else None
        except (IndexError, ValueError):
            return None

    def same_filesystem(self, a: str, b: str) -> bool:
        return os.stat(self._existing(a)).st_dev == os.stat(self._existing(b)).st_dev

    def timezone(self) -> str:
        rc, out = self.r.probe(["timedatectl", "show", "-p", "Timezone", "--value"])
        return out if rc == 0 and out else "UTC"

    def ntp_synced(self) -> bool:
        rc, out = self.r.probe(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
        return rc == 0 and out.strip() == "yes"

    def primary_ip(self) -> str:
        rc, out = self.r.probe(["ip", "-4", "route", "get", "1.1.1.1"])
        m = re.search(r" src (\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if (rc == 0 and m) else ""

    def addresses(self) -> set[str]:
        """Every IPv4 and IPv6 address configured on this host, on any interface (empty when `ip` fails)."""
        rc, out = self.r.probe(["ip", "-o", "addr", "show"])
        return set(re.findall(r"\binet6? ([0-9A-Fa-f.:]+)/", out)) if rc == 0 else set()

    def default_route_ifaces(self) -> list[str]:
        """Every interface that carries an IPv4 or IPv6 default route: the host's management NICs."""
        out: list[str] = []
        for family in ("-4", "-6"):
            rc, text = self.r.probe(["ip", family, "route", "show", "default"])
            if rc == 0:
                out += [d for d in re.findall(r"\bdev (\S+)", text) if d not in out]
        return out

    def nics(self) -> list[dict]:
        """Physical-looking interfaces with what matters for choosing a capture NIC."""
        out = []
        base = "/sys/class/net"
        for name in sorted(os.listdir(base)):
            if name == "lo" or not os.path.isdir(f"{base}/{name}/device"):
                continue

            def read(attr: str, _n: str = name) -> str:
                try:
                    return open(f"{base}/{_n}/{attr}").read().strip()
                except OSError:
                    return ""
            rc, addr = self.r.probe(["ip", "-4", "-o", "addr", "show", "dev", name])
            out.append({"name": name, "mac": read("address"), "state": read("operstate"),
                        "carrier": read("carrier") == "1", "mtu": read("mtu"),
                        "ipv4": [m for m in re.findall(r"inet (\S+)", addr)] if rc == 0 else []})
        return out

    # A 24-byte libpcap header, no packets: microsecond magic, v2.4, snaplen 262144, LINKTYPE_ETHERNET.
    # tcpdump reads the link type from the file before it compiles the filter, so the filter is
    # checked against Ethernet, exactly as n2disk will use it on the capture NIC.
    _EMPTY_PCAP = (b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 8
                   + b"\x00\x00\x04\x00\x01\x00\x00\x00")

    def bpf_compiles(self, expr: str) -> bool:
        """Does tcpdump accept this filter? (`-d` compiles and prints it, it captures nothing.)

        Without tcpdump the answer is True: a missing checker must not block the install.
        """
        if not shutil.which("tcpdump"):
            return True
        fd, path = tempfile.mkstemp(prefix="bpfcheck-", suffix=".pcap")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(self._EMPTY_PCAP)
            rc, _ = self.r.probe(["tcpdump", "-r", path, "-d", expr])
            return rc == 0
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def port_listening(self, port: int) -> bool:
        with socket.socket() as s:
            s.settimeout(1)
            return s.connect_ex(("127.0.0.1", port)) == 0

    def reachable(self, url: str) -> bool:
        try:
            urllib.request.urlopen(url, timeout=10)
            return True
        except urllib.error.HTTPError:
            return True  # it answered
        except Exception:
            return False

    def port_holder(self, port: int | str) -> str | None:
        """Who listens on TCP `port` on the host: None when nobody; `docker:<compose project or container>` when a
        container publishes it; else the process name from ss (`apache2`, `nginx`, ...)."""
        _, out = self.r.probe(["ss", "-ltnpH", f"sport = :{port}"])
        if not out.strip():
            return None
        m = re.search(r'users:\(\("([^"]+)"', out)
        name = m.group(1) if m else ""
        if name in ("", "docker-proxy"):
            _, ps = self.r.probe(["docker", "ps", "--filter", f"publish={port}", "--format",
                                  '{{.Label "com.docker.compose.project"}} {{.Names}}'])
            if ps.split():
                return "docker:" + ps.split()[0]
        return name or "an unknown process"

    def busy_ip(self, iface: str, seconds: int = 5) -> str | None:
        """The IPv4 address seen most often on `iface` in a few seconds (None if none or tcpdump is not usable)."""
        if shutil.which("tcpdump") is None:
            return None
        _, out = self.r.probe(["timeout", str(seconds), "tcpdump", "-nn", "-q", "-i", iface, "-c", "500", "ip"],
                              timeout=seconds + 10)
        counts: dict[str, int] = {}
        for m in re.finditer(r" IP (\d+\.\d+\.\d+\.\d+)(?:\.\d+)? > (\d+\.\d+\.\d+\.\d+)", out):
            for ip in m.groups():
                counts[ip] = counts.get(ip, 0) + 1
        return max(counts, key=counts.get) if counts else None

    def packet_sample(self, iface: str, seconds: int = 5) -> int | None:
        """Packets seen on `iface` in a few seconds (None if tcpdump is not usable)."""
        if shutil.which("tcpdump") is None:
            return None
        rc, out = self.r.probe(["timeout", str(seconds), "tcpdump", "-nn", "-i", iface, "-c", "1000",
                                "-w", "/dev/null"], timeout=seconds + 10)
        m = re.search(r"(\d+) packets? captured", out)
        return int(m.group(1)) if m else None


def insecure_context() -> ssl.SSLContext:
    """TLS context that accepts the recorder's own (internal CA) certificate: this talks to itself."""
    sslctx = ssl.create_default_context()
    sslctx.check_hostname, sslctx.verify_mode = False, ssl.CERT_NONE
    return sslctx


def healthz_status(authority: str) -> int | None:
    """HTTP status of https://<authority>/healthz (`host` or `host:port`; certificate not verified), None if no answer."""
    sslctx = insecure_context()
    try:
        with urllib.request.urlopen(f"https://{authority}/healthz", timeout=5, context=sslctx) as r:
            return r.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception:
        return None
