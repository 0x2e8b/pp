# Release notes

Sycope Traffic Recorder. The release number is shown on the System page, in `/stats` and in the debug bundle.
Upgrade steps: `README_DEPLOY.md` section 12 ("Updating later"), which also has the checklist for the first update
from the September 2026 deployment.

## v0.4b6

**Install profiles and nProbe.** The installer asks for a profile: `recorder-only` (default, the set-up so far),
`full` (adds nProbe on the same capture NIC: IPFIX with the nDPI application to the Sycope collector, one or more
instances) or `probe-only` (nProbe alone, no recorder). nProbe needs its own licence, bound to a SystemID that differs
from n2disk's; without one it is configured but not started.

**Licences after the installation.** `install.sh --licence-request` prints both SystemIDs to send to ntop.
A licence then comes in by `sudo sycope-licence` (console menu: paste the key or give a file), by copying the file
into the inbox `/var/lib/sycope-recorder-installer/inbox/` (picked up automatically) or by
`install.sh --licence <files>`. Every way goes through the same guard as the installation: a valid licence is never
replaced by an invalid one, and n2disk and nProbe are started once their licence is valid.

**Capture tuning.** A new installer step switches off the NIC offloads that merge or split packets, sets a large RX
ring, the kernel's receive and writeback settings and the priority of n2disk and nProbe, and spreads the capture
NIC's interrupts over the CPUs (in the lab the kernel had put two receive queues on one CPU, which ran at up to 91%
and lost packets now and then; spread, about half of that at the same traffic).

**Sizing and acceptance.** `README_SIZING.md` sizes CPU, memory, NIC and storage for 1, 5 and 10 Gbit/s, with the
figures measured in the lab; `docs/GO_NO_GO.md` is the checklist before going live, with a load check.

**Updating from v0.4b5.** In place, no schema change and no new setting; the recorder itself is unchanged. Run the
installer and keep the profile `recorder-only` for the same set-up (`README_DEPLOY.md` section 12).

## v0.4b5

**Installer sets up the Sycope Passthrough.** A new step creates the Passthrough entry that points at the recorder
(upstream, Basic auth, TLS settings and the access rules from the deployment guide), or corrects it when it already
points at this recorder, and then checks it by reaching the recorder through Sycope. An entry with the same name
that points elsewhere is left alone; nothing in Sycope is deleted. The Sycope user given to the installer needs the
right to edit Passthrough; without it the installer reports the values to enter by hand, as before.
`--update-passthrough` writes the entry again.

**Stronger recorder password.** A new install gets a 48-character Basic-auth password, kept in
`<install dir>/credentials` and put into Caddy and the Passthrough by the installer. An existing password is kept.

**n2disk licences of the 1G and 5G editions.** The installer now recognises them (they are valid only for
`n2disk1g` / `n2disk5g`): it reports which binary the licence is for instead of treating it as missing, and keeps a
1G/5G licence given to it.

**Pages.** Scrollbars keep one width when the mouse is over them, so the content beside them no longer jumps.

**Updating from v0.4b4.** In place, no schema change and no new setting. Run the installer to get the Passthrough
step (and the licence fix).

## v0.4b4

**Profiles file.** `profiles.json` now holds only the fields that change an extraction (`def_id`, `rule_id`, `name`,
`time_range_s`, `packet_dims`, `static`), with a `_help` block on top that says what each one changes. What is read
from Sycope besides that (throttling, interval, macros, notes) is kept in `profiles.info.json` next to it, shown on
the Profiles page and never used for a filter or window. The older list format still loads and uploads; the
download always gives the new format.

**Profiles page.** Two views of the same rows with a search box. *What gets recorded*: the BPF filter each
definition builds (`<client>`, `<server>`, `<port>`, `<protocol>` stand for the alert's values), the window around
the alert time ("6 min before, 30 s after") and the generator's notes. *Sycope settings*: throttling in words ("1
alert per 1 h for each server"), how often Sycope checks the definition, macros, active; none of it changes what is
recorded.

**Queue.** Auto refresh is off until switched on. When on, expanded rows and the scroll position stay across the
reload, and the reload waits while the re-extract dialog, a menu or a field is in use. A job's Origin says only
where it came from; the files re-extracted from it are listed under Re-extractions, and the history event reads
"re-extracted". The Profiles and Configuration pages have no auto refresh; Configuration has a search box. The
logo opens the queue, and the due time of a queued PCAP on the status page is shown as a time again.

**Updating from v0.4b3.** In place, no schema change and no new setting. An existing `profiles.json` keeps working;
run the installer (or *Rebuild from Sycope*) to get the new format.

## v0.4b3

**Capture performance (installer).** The generated n2disk configuration now writes in 4 MB chunks with a 1 GB
buffer (`--chunk-len=4096 --buffer-len=1024`). With the previous 0.1 MB chunks n2disk lost 27-83% of the packets
at 5-13 Gbit/s in a lab test, with the disk saturated by small writes and the CPU mostly idle; with 4 MB the same
virtual machine recorded 12.5 Gbit/s with under 1% loss. The memory recommendation is now 4 GB.

**PF_RING kernel module (installer).** A new step installs `pfring-dkms` (with the running kernel's headers) and
enables `pf_ring.service`, so that n2disk captures through PF_RING instead of silently falling back to libpcap.
The n2disk SystemID is compared before and after loading the module; if it changed, the module is removed again
and the step fails, so the licence is never put at risk. If the module cannot be loaded (for example Secure Boot
without an enrolled key), n2disk keeps recording through libpcap and the installer reports a warning.

**Webhook.** A 429 answer (queue full) now carries `X-Outcome: queue_full` and `X-Result` like every other answer.

**Pages.** The top bar shows Sycope's logo next to "recorder", and the scrollbars use Sycope's dark-mode style.

**Updating from v0.4b2.** In place, no schema change and no new setting. Run the installer once (it adds the module
and rewrites a managed n2disk configuration with a backup, restarting n2disk once); check its remembered rolling
size limit first, because the rewritten configuration uses it for `--disk-limit`.

## v0.4b2

**Re-extract.** An operator can request a new PCAP for an alert that already has one: `Re-extract…` next to Retry, in
the row menu and (window only, for ticked rows) in Action. The window can move up to 3600 s either side and, for a
single job, a new filter can be built from validated addresses or networks (with direction), ports and protocol. A
preview shows the resulting window, filter and file and warns when the rolling buffer no longer holds the start. The
old job and file stay; the new file is `<name>_r<n>.pcap`, and `?download=1&job=<file>` downloads a given one. The
alert link is still the status page and `?download=1` still gives the newest finished file. Behind `SR_QUEUE_EDIT`.

**Queue.** A row menu (download, status page, JSON, Open in Raw Data, copy link, copy BPF, Re-extract, Retry,
Cancel); field filters in Search like Sycope's chips (`clientIp=10.88.*`, `serverIp=10.0.0.0/8`, `serverPort=443`,
`state=`, `severity=`, `profile=`, `alertName=`, `alertId=`), editable with the most frequent values of the current
view; a time picker in the top bar with a histogram of the matching jobs; column order and widths by drag, kept per
browser and in saved views; **Download PCAPs (zip)** for ticked or all
matching finished jobs (at most 500 files / 4 GiB, no compression); packets and first/last packet time of each PCAP
in the row details. **Open in Raw Data** opens Sycope's Raw Data view of the job's flow over its window and needs only
`SR_SYCOPE_URL`.

**Pages.** The pages use Sycope's fonts (bundled, OFL) and colours. The status page shows one chronological history
with the file of each event. The System page follows Sycope's System Status layout
(system information, uptime, resources) and lists the disks with the recorder's own data on each volume.

**Database.** Schema 6 (job origin, parent job, PCAP content). A 0.4 database is migrated in place; take a copy of
`jobs.db` before updating if you may need to roll back to v0.4b1. No settings were added or removed.

## v0.4b1

**Architecture.** The `api` container runs two processes under supervisord: a web process (gunicorn, user `sr`) that
takes Sycope's webhook, queues a job and serves the pages, and a worker (root) that runs every `npcapextract`, retries,
and does the housekeeping. Restarting one does not interrupt the other. Both share only the SQLite job database
(`state/jobs.db`). The entrypoint prepares the shared state directory and never touches the PCAP or rolling directories.

**Queue page.** Redesigned after Sycope's alert view: an `Action` menu for bulk actions, a column selector, saved views,
free-text **Search** (alert, flow, state, time, profile, window, PCAP size; in the database over the whole queue, with
paging and sorting) and a gear for rows per page. Two-line sortable headers, coloured severity labels, empty values as
grey `<null>`. The column choice and the saved views live in the browser. The alert description is a collapsed item
next to Tags. The other pages (alert status, System, Profiles, Configuration) use the same colours.

**Persistent flag.** A job marked persistent keeps its row from bulk removal and from pruning the history, and its
**PCAP is never deleted by the retention sweep** (`SR_RETENTION_*`). Persistent files still count toward the size cap.
This replaces the `important` flag of earlier builds.

**Operator actions** (all behind `SR_QUEUE_EDIT`, off by default, with a cross-site guard): cancel queued and running
jobs, retry miss/failed/cancelled jobs, mark or unmark persistent, delete job rows, pause and resume the worker. The
bulk actions work on ticked rows or on everything matching the current filter.

**System page.** A Workers table (heartbeat, slot, current job), the rolling capture summary reported by the worker,
persistent outcome counters shared by both processes.

**Settings.** New: `SR_WORKER_STOP_GRACE_SECONDS`, `SR_WORKER_HEARTBEAT_SECONDS`, `SR_WORKER_STALE_SECONDS`. Removed:
`SR_MODE` (always queued) and `SR_LOG_BUFFER_LINES`. The retention settings, `npcapextract_path`/`_user`,
`timeline_dir` and `output_dir` can only be set in the environment, not by a configuration upload: move any retention
value from `config.override.json` to `.env` before updating, or the PCAPs are kept.

**Database.** Schema 5. A 0.3 database is moved aside to `jobs.db.0.3-<time>` on first start (nothing is deleted, the
queue starts empty); a schema-4 database from an earlier 0.4 build is migrated in place, history included. A database
written by a newer release is refused (`/healthz` answers 503). Take a copy of `jobs.db` before updating if you may
need to roll back.

**Installer.** `tools/install/install.sh` deploys 0.4 from any state (fresh host, running 0.3 or 0.4 stack, code
change, stale `.env`), lists the jobs still queued or running in the previous release, never touches the PCAP
directories and keeps the n2disk licence.

## v0.3b1

Everything after the first customer deployment (September 2026):

- **Job queue.** `POST /extract` queues one job and answers at once with the alert's link (`https://<base>/<alertId>`),
  always a status page; the PCAP is `?download=1` on the same path. Jobs wait until the n2disk file holding the window
  end is closed, retry with a wider window, survive restarts, and keep a history of events.
- **Per-definition profiles.** The BPF filter and the extraction window are derived from the alert's Sycope definition
  (grouping keys, `timeRange`, exporter lag) instead of fixed `before`/`after` values. Profiles come from
  `tools/profiles/gen_profiles.py` or rebuilt from Sycope on the Profiles page, validated and diffed before they apply.
- **Pages.** Queue (sortable, paged, expandable rows, Due column), alert status, System (self-checks, capture and
  storage), Profiles, Configuration (download, review, upload with a password), debug log bundle.
- **Self-checks.** `doctor`, `/healthz/deep` and a watchdog cover the failure classes seen at the first customer: n2disk
  not writing, time zone mismatch, `api` and `caddy` not sharing the alerts volume, a stale rolling capture.
- **Safety.** Alert IPs are validated before they reach the BPF filter; state-changing pages are off by default
  (`SR_QUEUE_EDIT`), guarded against cross-site requests and reachable only from `ALLOWED_UI_IPS`; PCAP retention is off
  by default; a free-space guard (`SR_MIN_FREE_BYTES`) refuses new extractions on a full disk.
- **Installer** (`tools/install/`): idempotent, remembers its answers, backs up and checks the n2disk licence.
