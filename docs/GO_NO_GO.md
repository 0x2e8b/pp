# Go / No-Go: acceptance of a recorder + nProbe host

For the deployment engineer, after the installer finished. Every line is a command and the answer that means *go*.
One *no-go* stops the hand-over. Replace `<nic>` with the capture NIC, `<sycope>` with the Sycope address and
`<collector>` with the flow collector. Profile `recorder-only` skips section 3, `probe-only` skips 4 and 5.

## 1. Installer and licences

| Check | Command | Go |
|---|---|---|
| Installer report | `sudo tools/install/install.sh --check` | no FAIL; every WARN understood and written down |
| n2disk licence | `sudo n2disk -V` | `License Type:` present, SystemID noted in the hand-over |
| nProbe licence | `nprobe --version` | `License:` not "Invalid", nProbe SystemID noted (it differs from n2disk's) |
| Licence backup | `ls /var/lib/sycope-recorder-installer/licence-backup/` | at least one directory with both licences |

## 2. Services

| Check | Command | Go |
|---|---|---|
| Capture NIC | `systemctl is-active recorder-capture-nic@<nic> recorder-capture-tune@<nic>` | `active` twice |
| NIC settings | `ethtool -k <nic> \| grep -E 'generic-receive\|large-receive'`; `ethtool -g <nic>` | offloads `off`; RX ring at maximum or 4096 |
| NIC interrupts | `for i in $(ls /sys/class/net/<nic>/device/msi_irqs); do cat /proc/irq/$i/effective_affinity_list; done`; `systemctl is-active irqbalance` | queue interrupts on different CPUs; irqbalance `inactive` |
| PF_RING | `cat /proc/net/pf_ring/info` | module loaded; `ls /proc/net/pf_ring/stats/` shows n2disk and nProbe |
| n2disk | `systemctl is-active n2disk@<nic>` | `active`, `journalctl -u n2disk@<nic>` says "packet mode" (PF_RING), not libpcap |
| nProbe | `systemctl is-active nprobe@<nic>` (or `nprobe@<nic>-1..N`) | `active` for every instance |
| Recorder stack | `cd /opt/sycope-recorder && sudo docker compose ps` | `api` and `caddy` up (healthy) |
| Self-check | `sudo docker compose exec api python -m sycope_recorder doctor` | every line OK |

## 3. Flows reach Sycope

| Check | Command | Go |
|---|---|---|
| Export leaves the host | `sudo tcpdump -ni any -c 5 udp and dst host <collector> and port 2055` | packets within 60 s |
| Sycope receives | Sycope: Settings, flow sources | this host's management address listed, IPFIX, no template errors |
| Application field | Sycope Raw Data, last 15 min | `%L7_PROTO` (nDPI application) filled after it was added in Discovery Mode |
| No gaps | Sycope traffic chart for the host, 1 h | no holes; volume close to the SPAN port counter of the switch |

## 4. Webhook to PCAP through Sycope

| Check | How | Go |
|---|---|---|
| Passthrough | installer report, section "Sycope Passthrough" | `GET /stats` through the entry OK |
| Test alert | trigger one alert of an active definition (or replay traffic that matches one) | Sycope sends the webhook; the recorder queue (`https://<sycope>/npm/api/v1/passthrough/<name>/queue`) shows the job `done` |
| Download | open the alert link in Sycope, then *Download* | a PCAP that opens in Wireshark and holds the alert's hosts in the alert's time window |

## 5. Load (before go-live; repeat after a hardware change)

Replay traffic at 1.2x the planned peak for 30 minutes (for example `tcpreplay -i <generator nic> --mbps <rate>
--loop 0 mix.pcap` from a second host into the SPAN port), while 100 test alerts go to the webhook.

| Check | Command | Go |
|---|---|---|
| NIC drops | `ethtool -S <nic> \| grep -iE 'drop\|miss\|err'` before and after | no increase |
| n2disk drops | `cat /proc/net/pf_ring/stats/*n2disk*` (or `n2disk` log statistics) | 0 lost packets |
| nProbe drops | `cat /proc/net/pf_ring/stats/*nprobe*` | below 0.1% lost |
| PCAP consistency | extract a window of the replay and compare: `capinfos` packet count and `tshark -r ... -q -z conv,ip` against the reference file | identical packets for the replayed hosts |
| Queue | recorder queue page | every test job `done`, none `miss` |
| History | `du -sh` of the rolling directory and the oldest file time | history at least the planned value (README_SIZING.md section 6) |

## Hand-over record

Host name, management address, capture NIC, profile, n2disk and nProbe SystemIDs and licence types, collector,
Passthrough name, rolling size and measured history, result of section 5 with the peak rate used, date and engineer.
