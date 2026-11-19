# Sizing: recorder, n2disk and nProbe on one host

This guide sizes one virtual machine (or server) that runs the install profile `full`: n2disk records every packet of
the capture NIC into a rolling buffer, nProbe exports flows (IPFIX) to the Sycope collector, and the recorder cuts
PCAPs for alerts. `recorder-only` needs the same minus the nProbe rows; `probe-only` needs only the nProbe, receive and
system rows.

**Two kinds of numbers.** *Measured* figures come from the lab (VMware ESXi VM, vmxnet3, PF_RING kernel module without
ZC, n2disk 3.10, 4 vCPU on Zen 2). *Planned* figures are estimates that the stress test of section 7 must confirm on
the target hardware before go-live. Each table says which it is.

## 1. The rules that decide the size

1. **n2disk never loses packets; nProbe may lose first.** The PCAP is evidence. nProbe gets its own cores, and when the
   host is short of CPU it is nProbe that runs behind, never n2disk.
2. **Without PF_RING ZC every consumer costs one kernel copy of every packet.** n2disk and nProbe each open their own
   PF_RING socket on the capture NIC and each receives the full stream. The packet is received once; each further
   socket adds a copy into its ring, measured at +10-25% of the capture CPU (section 2), not double. What a consumer
   does with the packet costs more: nDPI added 40-50%. It scales with packets per second, not with bit rate.
3. **Packets per second, not Gbit/s, is the limit.** 10 Gbit/s is 0.83 Mpps at 1500 B frames, ~1.5-2 Mpps for a
   typical enterprise mix and 14.88 Mpps at 64 B. 64 B line rate is out of reach without ZC and a physical NIC;
   size for the real mix and its peaks.
4. **Disk throughput and endurance decide the storage, capacity comes second.** The rolling buffer is overwritten
   completely once per history length.

## 2. What was measured

| Test (n2disk alone, PF_RING kernel module, vmxnet3, 4 vCPU) | Result |
|---|---|
| 1500 B frames | ~12.5 Gbit/s to disk (1.5 GB/s) with under 1% loss, after `--chunk-len=4096 --buffer-len=1024` |
| 64 B frames | ~1.2 Mpps without loss (the traffic generator was the limit) |
| Same with n2disk's default 0.1 MB write chunks | 27-83% loss above ~4 Gbit/s (the disk, not the CPU) |
| Recorder queue under 3 Gbit/s background | extractions ~1.5x slower, webhook p95 2.4 s (0.4 s idle) |

Second run (same VM, PF_RING 9.4 on Debian 13, traffic from a second VM with `pfsend`; nProbe 11.2 has no demo mode,
so a free consumer stands in for it on a second socket):

| Test | Result |
|---|---|
| n2disk + a second PF_RING socket (`pfcount`), 64-1500 B, up to ~9 Gbit/s / ~860 kpps | 0 n2disk loss; +10-25% capture CPU against n2disk alone |
| n2disk + nDPI on a second socket (`ndpiReader`), real traffic mix replayed (~450 B average, 28k flows), ~740 kpps | 0 loss on both; +40-50% CPU against n2disk alone; one nDPI thread kept up |
| Capture NIC interrupts as the kernel placed them (two RX queues on one vCPU, one vCPU without any) | busiest vCPU 76-91%, sporadic n2disk loss of 0.2-0.4% |
| The same, one RX queue interrupt per vCPU (what the installer now does) | busiest vCPU 40-53% at the same traffic |
| ... plus n2disk's reader and writer threads pinned to one vCPU | total CPU 5-8 points lower |
| 60 min at 2.9 Gbit/s, n2disk + `pfcount` + `ndpiReader`, rolling buffer overwritten ~14 times | 1.84 G packets, 0 loss on every consumer, CPU median 47% of 4 vCPU, n2disk memory flat |
| 12 extractions while recording 4.3 Gbit/s beside a second socket | 0.6 s median each, all complete, same as idle |
| Rolling volume (ext4 on a VMware virtual disk, `fio`) | 4 MB sequential write 2.1 GB/s; 64 KiB random read during that write only ~100 MB/s |

The generator, not the recorder, was the limit in every run. nProbe itself (flow tables, IPFIX export) has not been
measured yet; its rows below are planned.

## 3. CPU (planned)

Dedicated vCPUs backed by physical cores (full CPU reservation on ESXi), peak traffic on the capture NIC with a typical
mix. SMT siblings do not count as cores for the receive, n2disk and nProbe rows.

| Component | 1 Gbit/s | 5 Gbit/s | 10 Gbit/s |
|---|---|---|---|
| System, management, NIC interrupts | 1 | 2 | 2 |
| Kernel receive, two copies (n2disk + nProbe) | 1 | 4 | 8 |
| n2disk (capture, write, index) | 1 | 2 | 3 |
| nProbe with nDPI (instances x 1 core) | 1 | 3 | 6 |
| Recorder (web, worker, Caddy, npcapextract) | 2 | 2 | 3 |
| **Sum** | **6** | **13** | **22** |
| **Recommended vCPU** | **8** | **16** | **24-32** |

- More nProbe instances are set with the installer question `nprobe_instances`; they share one PF_RING cluster per
  5-tuple, so both directions of a connection reach the same instance.
- Interrupts: the installer spreads the capture NIC's queue interrupts one per vCPU at every boot
  (`recorder-capture-tune@<nic>`); the kernel's own placement put two queues on one vCPU in the lab and nearly
  doubled its load. `irqbalance` moves them back: the installer warns when it runs.
- Pinning: give n2disk's reader and writer threads (`--reader-cpu-affinity`, `--writer-cpu-affinity` in the n2disk
  configuration) and each nProbe instance (`--cpu-affinity`) their own cores. The installer does not pin them, the
  right cores depend on the host. Inside a VM, pinning only helps when the vCPUs are
  reserved and the VM has latency sensitivity *High* (ESXi) or pinned vCPUs (KVM); `isolcpus` in the guest is not
  needed.

## 4. Memory (planned)

| Component [GB] | 1 Gbit/s | 5 Gbit/s | 10 Gbit/s |
|---|---|---|---|
| System, Docker, recorder web | 4 | 4 | 4 |
| Recorder worker (npcapextract x slots) | 2 | 3 | 3 |
| PF_RING rings (65536 slots per socket) | 0.5 | 1 | 1 |
| n2disk buffer (`--buffer-len`, 1 GB by default) | 2 | 3 | 4 |
| nProbe flow tables (1M flows per instance) | 1 | 3 | 6 |
| **Sum** | **9.5** | **14** | **18** |
| **Recommended RAM** (rest is page cache for extractions) | **16** | **32** | **48-64** |

Reserve the VM's memory in full: ballooning or swapping under a 10 Gbit/s stream loses packets.

## 5. NIC and virtualisation

| Option | When | Notes |
|---|---|---|
| **PCI passthrough of a physical NIC** (Intel X710/E810, NVIDIA ConnectX-5/6) | 5-10 Gbit/s | The native driver gives RSS queues per core and the best kernel path. The only option for a sustained 10 Gbit/s without ZC, and the one that allows ZC later. vMotion and snapshots with memory are not possible. |
| **VMXNET3** on a dedicated vSwitch / port group | up to ~3-5 Gbit/s for both consumers (planned) | Measured: n2disk alone kept 12.5 Gbit/s of 1500 B frames. Port group security: promiscuous mode *Accept*; one uplink that only carries the SPAN/TAP traffic; enable RSS (several RX queues); RX ring 4096. |
| **SR-IOV VF** | not recommended for capture | A VF normally receives only its own MAC; mirrored traffic needs promiscuous/trusted VF support from the NIC, driver and hypervisor. |
| **virtio-net (KVM/Proxmox)** | lab, up to ~1-2 Gbit/s | Use multiqueue (`queues=` = vCPUs for receive) or prefer passthrough. |

Whatever the option: the capture NIC has no IP address, offloads that merge packets (GRO, LRO, TSO, GSO) are off, MTU
is at least the largest frame on the mirror. A passive TAP has one port per direction: both ports must reach the VM
(two capture NICs or a TAP aggregator), and the installer records one NIC.

**Licences.** n2disk and nProbe licences are bound to a SystemID that ntop derives from the VM hardware (management NIC
MAC among others), and n2disk's and nProbe's SystemIDs differ. A new VM, a new MAC or a changed vNIC means new
licences: order them after the VM's hardware is final, and fix the management NIC's MAC in the hypervisor.

## 6. Storage

**Throughput.** Sustained sequential write of at least 1.3x the peak capture rate, while extractions read at the same
time: 1 Gbit/s needs ~170 MB/s, 5 Gbit/s ~850 MB/s, 10 Gbit/s ~1.7 GB/s. n2disk writes 4 MB blocks, so IOPS hardly
matter for writing; extractions read index and data in smaller pieces, which favours SSD/NVMe. At 10 Gbit/s plan NVMe
(or a RAID controller with write cache and enough spindles to sustain 1.7 GB/s). Extractions compete with n2disk's
writes for the same volume: in the lab random reads fell to ~100 MB/s while the volume was written at full speed, so a
large extraction during a peak takes minutes, not seconds.

**Capacity.** Rolling buffer = average rate x history. Per hour of history: 1 Gbit/s = 450 GB, 5 Gbit/s = 2.25 TB,
10 Gbit/s = 4.5 TB (at 100% load, plus a few percent for the index).

| Average rate | 2 h | 6 h | 24 h |
|---|---|---|---|
| 1 Gbit/s | 0.9 TB | 2.7 TB | 10.8 TB |
| 5 Gbit/s | 4.5 TB | 13.5 TB | 54 TB |
| 10 Gbit/s | 9 TB | 27 TB | 108 TB |

- The minimum history is *exporter lag + the longest extraction window + one n2disk file* (`chunk_seconds`). Below it,
  alerts arrive after their packets have been overwritten (`miss`). With Sycope's default lag and the shipped profiles
  this is about 20 minutes at peak rate; plan at least 2 hours.
- **SSD endurance.** The buffer is rewritten once per history length, so the drive needs DWPD >= 24 h / history.
  2 hours of history is 12 DWPD. With 1 DWPD drives size the buffer for ~1.5 days of average traffic.
- **Packet slicing** (`PACKET_SLICING=4`, off by default) drops the payload at capture time, so the same disk holds a
  longer history. Measured in the lab (2026-10-29, n2disk 3.10, replayed demo traffic at 2.2 Gbit/s): 53 bytes written
  per packet against 1407 bytes on the wire, a 96% saving, with no drops. That figure is the best case - the saving is
  the share of bytes that is payload, and this capture is almost all full-size transfers. Small-packet traffic saves
  far less: the floor is the ~54 bytes of headers per packet, so size from the customer's own average packet size
  (`history = disk / (pps x 54 B)` once sliced) rather than from the percentage. The on-wire length is kept in each
  packet record, so volume statistics stay correct. The price is that the extracted PCAPs are headers only: metadata
  evidence, not content. `README_DEPLOY.md` section 0 has the levels.
- **Capture filter** (`CAPTURE_FILTER`, empty by default) drops whole packets before they are written, so the saving is
  simply the share of traffic it excludes - unlike slicing, it is exact and predictable once the customer's flow data
  says how much of the link is the excluded traffic. The price is absolute: what the filter drops is not evidence that
  was shortened, it is evidence that does not exist, and no later extraction can recover it. Use it for traffic that is
  known to be uninteresting and voluminous (backup or replication between two known hosts, storage replication), never
  as a general way to save disk. `README_DEPLOY.md` section 0 has the rules.
- Filesystem: XFS on its own volume, mounted `noatime`; the installer's rolling limit (`--disk-limit`) stays below the
  free space. The `alerts` directory (the extracted PCAPs, retention off by default) goes on a separate, redundant
  volume with a usage alarm.

## 7. Before go-live

Run the load check of `docs/GO_NO_GO.md` (section 5) on the target VM with the traffic mix you expect at 1.2x the
planned peak. Pass: zero n2disk drops, nProbe drops below 0.1%, every extracted PCAP matches the replayed
reference, and Sycope shows the flows without gaps. If it does not pass, the order of fixes is: more cores for
receive, PCI passthrough, fewer nProbe features, then ZC (licence per port) or a second host for nProbe.
