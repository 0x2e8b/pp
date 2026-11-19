"""Host tuning for capture: NIC offloads and ring, kernel settings, limits and priority of n2disk and nProbe.

Everything is a file the installer owns (unit, sysctl.d, drop-ins), so it survives a reboot and a re-run
compares it byte for byte. Deliberately not done:
- real-time scheduling (CPUSchedulingPolicy=rr/fifo): n2disk's and nProbe's capture threads poll, and a
  real-time poller can starve the kernel's own softirq and RCU threads, which then drops packets or
  hangs the host. A negative nice value and a protected OOM score are enough to keep them ahead;
- pinning n2disk's or nProbe's threads to cores: the right cores depend on the core count, the NIC queues and
  what else runs on the host (README_SIZING.md). The NIC's interrupts are only spread, one per CPU.
"""

from __future__ import annotations

TUNE_UNIT_NAME = "recorder-capture-tune@.service"
# A leading "-" lets a step fail without failing the unit: vmxnet3 has no LRO switch, some NICs no ring setting.
TUNE_UNIT = """[Unit]
Description=Capture NIC %i: no packet merging offloads, large RX ring
After=recorder-capture-nic@%i.service
Wants=recorder-capture-nic@%i.service
Before=n2disk@%i.service nprobe@%i.service

[Service]
Type=oneshot
RemainAfterExit=yes
# Merged (GRO/LRO) or split (TSO/GSO) packets are not what was on the wire: n2disk would record them and
# nProbe would count them wrongly.
ExecStart=-/usr/sbin/ethtool -K %i gro off
ExecStart=-/usr/sbin/ethtool -K %i lro off
ExecStart=-/usr/sbin/ethtool -K %i tso off
ExecStart=-/usr/sbin/ethtool -K %i gso off
ExecStart=-/usr/sbin/ethtool -K %i rxvlan off
ExecStart=-/usr/sbin/ethtool -G %i rx 4096
# Last: a ring change can reset the NIC's queues.
ExecStart=-/usr/local/sbin/recorder-irq-spread %i

[Install]
WantedBy=multi-user.target
"""
IRQ_SPREAD_PATH = "/usr/local/sbin/recorder-irq-spread"
IRQ_SPREAD = """#!/bin/sh
# Managed by the recorder installer: spreads the interrupts of capture NIC $1 over the CPUs, one each, round robin.
# The kernel's own placement can put two RX queues on one CPU and leave another without any: measured on vmxnet3
# with two capture consumers, the busiest core went from ~90% to ~50% at the same traffic. irqbalance undoes this.
dev="/sys/class/net/$1/device/msi_irqs"
[ -d "$dev" ] || exit 0
n=$(nproc)
i=0
for irq in $(ls "$dev" | sort -n); do
    echo $((i % n)) > "/proc/irq/$irq/smp_affinity_list" 2>/dev/null || true
    i=$((i + 1))
done
"""
# Prints "<irq> <effective cpu list>" for each interrupt of the NIC given as $1.
IRQ_PROBE = ('for i in $(ls "/sys/class/net/$1/device/msi_irqs" 2>/dev/null); do '
             'echo "$i $(cat /proc/irq/$i/effective_affinity_list 2>/dev/null)"; done')
SYSCTL_PATH = "/etc/sysctl.d/60-recorder-capture.conf"
SYSCTL = """# Managed by the recorder installer.
# Backlog for bursts that the softirq cannot drain at once.
net.core.netdev_max_backlog = 250000
net.core.rmem_max = 268435456
net.core.rmem_default = 33554432
# Write back steadily in small portions instead of stalling every writer on a huge dirty set:
# n2disk writes the capture stream for ever, the page cache is for the extractions.
vm.dirty_background_bytes = 268435456
vm.dirty_bytes = 1073741824
vm.swappiness = 1
"""
DROPIN_N2DISK = """# Managed by the recorder installer: n2disk is the last process to lose CPU or be killed.
[Service]
LimitMEMLOCK=infinity
LimitNOFILE=65535
Nice=-10
IOSchedulingClass=best-effort
IOSchedulingPriority=0
OOMScoreAdjust=-900
"""
DROPIN_NPROBE = """# Managed by the recorder installer: nProbe runs ahead of the recorder, behind n2disk.
[Service]
LimitMEMLOCK=infinity
LimitNOFILE=65535
Nice=-5
OOMScoreAdjust=-500
"""
OFFLOADS = ("generic-receive-offload", "large-receive-offload", "tcp-segmentation-offload",
            "generic-segmentation-offload")


def offloads_on(ethtool_k: str) -> list[str]:
    """The packet-merging offloads that `ethtool -k` reports on (a [fixed] one cannot be changed: ignored)."""
    on = []
    for line in ethtool_k.splitlines():
        name, _, value = line.strip().partition(":")
        if name in OFFLOADS and value.strip().startswith("on") and "[fixed]" not in value:
            on.append(name)
    return on


def rx_ring(ethtool_g: str) -> tuple[int | None, int | None]:
    """(maximum, current) RX ring size from `ethtool -g`."""
    vals, section = {}, None
    for line in ethtool_g.splitlines():
        low = line.strip().lower()
        if low.startswith("pre-set maximums"):
            section = "max"
        elif low.startswith("current hardware settings"):
            section = "cur"
        elif low.startswith("rx:") and section and section not in vals:
            v = low.split(":", 1)[1].strip()
            vals[section] = int(v) if v.isdigit() else None
    return vals.get("max"), vals.get("cur")


def irq_crowding(probe_out: str, cpus: int) -> list[str]:
    """CPUs that serve more than one of the NIC's interrupts while another CPU serves none ([] = spread well)."""
    per_cpu: dict[str, int] = {}
    for line in probe_out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            per_cpu[parts[1]] = per_cpu.get(parts[1], 0) + 1
    if not per_cpu or cpus <= len(per_cpu):
        return []
    return sorted((c for c, n in per_cpu.items() if n > 1), key=int)
