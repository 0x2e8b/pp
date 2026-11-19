# Deploying a Dist to a Target Host

This is the step-by-step runbook for taking a dist produced per
`README_DIST.md` (a pre-built `sycope-recorder-api` image, `caddy:2`,
`compose.yaml`, `caddy/Caddyfile`, and a `compose.dist.yaml` override) and
standing it up on a target host. Follow the steps in order — later steps
assume earlier ones are done.

**Which compose files a host uses.** Run every `docker compose` command in the deployment directory, with the
compose files of the host's layout:

- *A host set up by the installer* (section 0): `compose.yaml` and `compose.ntop.yaml`. The second file builds the
  image with ntop's `npcapextract` (build argument `INSTALL_NTOP=1`) and binds the `rolling` and `alerts` volumes to
  `SR_ROLLING_DIR` and `SR_ALERTS_DIR`. The installer writes `COMPOSE_FILE=compose.yaml:compose.ntop.yaml` into
  `.env`, so a plain `docker compose ...` in the install directory uses both files. A host installed by an earlier
  installer release has no such line (`grep COMPOSE_FILE .env`): run the installer again (it adds the line; when
  nothing else differs it rebuilds and restarts nothing) or pass `-f compose.yaml -f compose.ntop.yaml` on every
  command. Without either, `docker compose up -d --build` builds an image without `npcapextract` (every job then
  fails), and `up` or `run` offer to recreate `rolling` and `alerts` as plain Docker volumes instead of the bound
  directories (answer no).
- *A dist host* (steps 1-11, a pre-built image): `compose.yaml` and `compose.dist.yaml`, passed as
  `-f compose.yaml -f compose.dist.yaml` to the commands that create or change containers (`pull`, `up`, `run`).
  Commands that only look at or restart the running containers (`ps`, `logs`, `exec`, `restart`) work without
  them. Do not copy the installer's `COMPOSE_FILE` line into a dist host's `.env`: `compose.ntop.yaml` builds from
  source, which a dist does not have. `COMPOSE_FILE=compose.yaml:compose.dist.yaml` there is fine.

## 0. Scripted install: the wizard (Debian 12/13, Ubuntu 22.04/24.04)

Tested on Debian 12/13 and Ubuntu 22.04/24.04. Another Debian or Ubuntu release with Python 3.8 or newer (Ubuntu
20.04, Debian 11) is a warning, not a stop: there the installer expects n2disk and Docker with the compose plugin
to be installed already, and it does not add the ntop repository when n2disk is there (an upgrade of an existing
host). Python older than 3.8 (Ubuntu 18.04) is refused by `install.sh`.

```bash
sudo tools/install/install.sh              # interactive: asks, checks, installs, reports
sudo tools/install/install.sh --check      # look only: no questions, no changes
sudo tools/install/install.sh --dry-run    # print the changes instead of making them
sudo tools/install/install.sh --redo stack,profiles    # run these steps again
sudo tools/install/install.sh --from-scratch [--wipe-stack]   # run everything again
sudo tools/install/install.sh --status     # the report of the last run
sudo tools/install/install.sh --profile full   # what the host runs: recorder-only (default), full, probe-only
```

**Install profiles.** `recorder-only` is n2disk and the recorder (what every earlier installation is; a state file
without the answer means this). `full` adds nProbe on the same capture NIC. `probe-only` is nProbe alone: no n2disk,
no Docker, no stack and nothing written to Sycope. For nProbe the installer asks the Sycope flow collector
(`IP[:port]`, UDP, default port 2055; `SYCOPE_COLLECTOR`), the number of nProbe instances (`NPROBE_INSTANCES`, 1-16)
and an optional nProbe licence file (`NPROBE_LICENSE_FILE`). It installs `nprobe`, writes
`/etc/nprobe/nprobe-<nic>.conf` (IPFIX, `%L7_PROTO` for the nDPI application, active timeout 60 s, idle 30 s) and a
bounded-restart drop-in, and starts `nprobe@<nic>` only with a valid licence. nProbe's SystemID is not n2disk's, so it
needs its own licence; it is installed with the same rules as the n2disk one (never over a valid licence without
`--replace-licence`, checked with `nprobe --version`, rolled back when invalid, covered by the licence backup and the
guard). n2disk and nProbe each open their own PF_RING socket and each gets every packet; with more than one nProbe
instance the instances share a PF_RING cluster (5-tuple, both directions to the same instance, one IPFIX observation
domain each) and n2disk stays outside it. Changing the profile never removes what another profile installed: the host
checks warn about an nProbe left running. Sizing: `README_SIZING.md`.

**Packet slicing (`PACKET_SLICING`, default `off`).** n2disk can write only the headers of each packet and drop the
payload, so the same disk holds a longer history. The wizard explains the levels where it asks and writes
`--packet-slicing=<level>` into `/etc/n2disk/n2disk-<nic>.conf`; the step reports a sliced capture on every run, so it
is visible that the PCAPs have no payload. `off` records whole packets. `4` keeps the IP and TCP/UDP headers: the BPF
filter, the n2disk index and extraction all use L3/L4 only, so they keep working, and the extracted PCAP shows who
talked to whom, when and how much, without the content. `3` (IP headers, no ports) and `2` (Ethernet only) are
reported as a warning: below L4 the recorder can no longer filter by port, and at L2 not by IP either. Slicing happens
at capture time: what is cut away is not in the rolling buffer and cannot be recovered. Changing the answer rewrites
the configuration and restarts n2disk; files already on disk keep whatever was recorded when they were written.

**Capture filter (`CAPTURE_FILTER`, default empty: record everything).** A BPF expression that narrows what n2disk
records at all, written as `--filter=<expr>` into `/etc/n2disk/n2disk-<nic>.conf`. It is the other way to make a disk
hold a longer history, and the harsher one: unlike slicing, which keeps every packet without its payload, a filter
drops whole packets, and what it drops never reaches the rolling buffer and can never be extracted. The step reports a
filtered capture as a **warning on every run**, so it stays visible that the recording is not complete. The wizard
refuses a filter that tcpdump cannot compile (n2disk would fail to start) and one carrying a quote, a newline or a
`#`, which could add or comment out a line of the configuration. The alert's own filter is applied at extraction, on
top of whatever was recorded here, so a capture filter can only ever narrow what an alert can show. Changing the
answer rewrites the configuration and restarts n2disk; files already on disk keep what was recorded when they were
written. Useful shapes: `not host 10.1.2.3` (exclude a noisy backup server), `net 10.0.0.0/8` (internal traffic only).
Leave it empty when the PCAPs are evidence.

**Licences after the installation.** ntop issues a licence for a SystemID, so the keys usually arrive after the host
exists. Ask for them with `tools/install/install.sh --licence-request` (it prints the n2disk and the nProbe SystemID in
a text ready to send; the same text is kept in `/var/lib/sycope-recorder-installer/licence-request.txt`). When the
keys arrive, any of these installs them, all through the same guarded path (backup first, verified by the product,
rolled back when invalid, never over a valid licence without `--replace-licence`, compared at the end) and then starts
what they unlock (n2disk, the nProbe instances, after `systemctl reset-failed`):

- `sudo sycope-licence`: a console menu that shows the SystemIDs and the request text and takes a pasted key or a
  file path (a USB stick);
- `scp n2disk.license nprobe.license <user>@<host>:/var/lib/sycope-recorder-installer/inbox/` by a member of the
  group `sycope-licence` (`usermod -aG sycope-licence <user>`): the path unit `sycope-licence-inbox.path` installs them
  within seconds;
- `sudo tools/install/install.sh --licence n2disk.license nprobe.license`.

The product is taken from the file name (`n2disk*` or `nprobe*`). Processed inbox files are moved to
`licence-done/` or `licence-rejected/` beside the inbox, never deleted. The result is in
`/var/lib/sycope-recorder-installer/reports/licence-latest.md`. The menu and the path unit run the installer's
root-owned copy in `/usr/local/lib/sycope-recorder-installer` (refreshed by every installer run), never the directory
the release was unpacked in, which may then be deleted.

**What it asks** (Enter keeps the value in brackets; earlier answers are the defaults): the capture
NIC (it lists the interfaces and which have no IPv4 address), the host name or IP for links, the
install directory, the rolling and alerts directories, the rolling size limit, the n2disk file
duration (= `SR_CHUNK_SECONDS`), packet slicing, an optional capture filter, the allowed networks (who may
reach the recorder at all: they go into all three allowlists of section 6, with Sycope's address and this host's
own added, see below), the API login user, an optional n2disk
licence file, then **the Sycope URL, user and password** (the login is verified at once, three
tries), the name of the Sycope Passthrough that will point at this recorder and the name of the External
Destination that will post alerts to it. Without a terminal
(`--yes`, or a pipe) it takes answers from `--answers file.json`, the environment (`SYCOPE_URL`,
`SYCOPE_USER`, `SYCOPE_PASS`, `CAPTURE_IFACE`, `SR_PUBLIC_HOST`, `INSTALL_DIR`, `ROLLING_DIR`,
`ALERTS_DIR`, `ROLLING_LIMIT`, `CHUNK_SECONDS`, `PACKET_SLICING`, `CAPTURE_FILTER`, `ALLOWED_IPS`,
`PASSTHROUGH_NAME`, `DESTINATION_NAME`,
`N2DISK_LICENSE_FILE`, `BASIC_AUTH_USER`) or the remembered ones, and stops on a missing value.

The rolling limit is a percentage of the capture volume (`60%`) or a size in MB of at least 1024
(`81920` for 80 GB); a bare `80` is 80 MB and is refused. n2disk keeps the buffer under the limit by
deleting the oldest files, also when it starts: when the answered limit is below what the buffer holds,
the installer says how many GB of recorded traffic would be deleted and asks first (without a terminal it
stops, unless the answer `rolling_shrink=yes`, `ROLLING_SHRINK=yes`, accepts it for that run).

**What it checks and does**, in order: Sycope access (login, active definitions, which macros are
readable and which networks their lookup conditions select, clock difference, whether an External
Destination posting to `.../extract` exists and whether its path ends with a `/`), the host (OS,
architecture, CPU, memory, free space and whether `/storage` is its own filesystem, time zone and
NTP, ports 80/443, the capture NIC), base packages, the ntop repository, `n2disk` (with
`npcapextract`), its licence and the SystemID, the capture NIC unit and directories, the PF_RING kernel
module (`pfring-dkms`, SystemID compared before and after, n2disk restarted onto it), the n2disk
configuration (4 MB write chunks, 1 GB buffer), Docker, the extraction profiles and macro report, the stack (`.env` with a
generated Basic-auth login in `<install dir>/credentials`: a 48-character password made for this install), the Sycope
Passthrough, the Sycope External Destination, and a verification: `doctor`, a
webhook self-test (the recorder must answer `NO BPF FILTER` to an empty alert), the 0.4 process split (`web` and
`worker` RUNNING under supervisord, every gunicorn process UID 10001 and the worker UID 0, the state directory
`root:sr` 2775 and `/var/log/sycope-recorder` `root:sr` 2750, `/stats` `worker.alive` with a heartbeat of at most 60 s, and
the web user opening the newest PCAP), and a 15 s packet sample on the capture NIC.

**Its writes to Sycope: the Passthrough and the External Destination.** The step `passthrough` looks for the entry named `PASSTHROUGH_NAME`.
Missing, it is created: upstream `https://<public host>`, Basic auth with the recorder's login, TLS verification off
(Caddy's internal CA), the access rules of section 10 for the roles `ROLE_ADMIN` and `ROLE_USER` (add your own roles
in Sycope afterwards; the installer keeps them). Present and pointing at this recorder, it is corrected where it
differs (URL, auth, user, missing rules; its roles are kept) and gets the password when the installer made a new one
or when the check fails. Present and pointing elsewhere, it is left alone and reported. The installer never deletes
anything in Sycope (the uninstaller does, see below). At the end `GET /stats` is fetched through the entry, which proves the URL, TLS, the password and the rule
together. The Sycope user needs the right to edit Passthrough (`CONFIGURATION.passthrough.passthrough`); without it
the step warns and the report gives the values to enter by hand. `--update-passthrough` writes the entry (with the
password) again; it also takes over an entry that points at this host on another port (the recorder moved to another
HTTPS port before the installer remembered it).

The step `destination` does the same for the External Destination named `DESTINATION_NAME` (default
`Traffic_Recorder`): a REST client, `POST https://<sycope host>:<sycope port>/npm/api/v1/passthrough/<PASSTHROUGH_NAME>/extract`,
JSON, no query parameters (profiles decide the window and filter), TLS verification off, Basic auth with **the Sycope
user and password given to the installer** (the Passthrough sits behind Sycope's own login). Missing, it is created;
posting to this Passthrough, it is corrected where it differs (port, path, parameters, user) and gets the password
again; posting elsewhere, it is left alone. When another destination already posts to the Passthrough (made by hand,
under another name), no second one is created. The installer does not attach it to alert definitions: choose it as
the action of the definitions that should record. `--update-passthrough` also sets its password again (after a
change of the Sycope password). Everything else in Sycope is only read.

**Ports.** The recorder listens on 443 and 80 of the host unless something else holds them (Apache, nginx, MISP): the
wizard then names the holder and offers a free port (`https_port`, `http_port`; `SR_HTTPS_PORT`, `SR_HTTP_PORT`), and
the stack step refuses to start the containers on a port another service holds. Triage's port (8444) is checked the
same way.

**The report.** At the end it prints what worked, what did not and the fix for each warning or
failure, then the next steps with ready-to-paste values (the Passthrough values when the installer could not set it
up, the External Destination values when it could not create it, the link base). The full report is saved as
`/var/lib/sycope-recorder-installer/reports/report-<time>.md` and `.json`.

**What it remembers.** `/var/lib/sycope-recorder-installer/state.json` holds the answers and, for
every step, its result and a fingerprint of the inputs it depends on; `secrets.json` (mode 600)
holds the Sycope and recorder passwords (so a re-run does not ask for them again). A step whose
last result was ok and whose inputs did not change is not run again (`SAME` in the output); a
changed answer re-runs exactly the steps that depend on it; `--redo` and `--from-scratch` force
them. `--wipe-stack` (with `--from-scratch`) also removes the containers and Docker volumes after a
confirmation. **It never touches the contents of the rolling and alerts directories.** Without a
valid n2disk licence everything else is installed and recording stays off; the report prints the
SystemID, and running the installer again after installing `/etc/n2disk.license` finishes the job.

**Upgrading and re-running.** The installer works from any state: a fresh host, a host with Docker or n2disk already
there, a running or stopped 0.3 stack, a 0.4 stack, a code change, a stale `.env`.

- *The stack step* records what it deployed in `<install dir>/.deployed` (release, a SHA-256 fingerprint of `src/**/*.py`,
  `docker/`, `Dockerfile`, `compose*.yaml`, `caddy/`, `gunicorn.conf.py`, `pyproject.toml`, `uv.lock`, and the time). A
  later run does nothing when the `.env` has no drift, both containers run and the fingerprint still matches; any code
  change (a pulled fix, a new release) syncs, rebuilds and restarts the stack. Tests and docs do not count.
- *From a running 0.3 stack* it first reads the jobs still `queued` or `running` from the old database (read-only,
  through `docker compose exec`) and reports up to 50 of them with the total as "abandoned jobs of the previous release";
  it then replaces the stack without waiting (0.4 has no migration: it moves the old database aside as
  `jobs.db.0.3-<time>` on first start and the queue starts empty). PCAPs already extracted are kept. Trigger the alerts
  again if you still need those PCAPs. An unreadable queue (no container, no database) is reported as unknown and
  does not stop the upgrade.
- *`.env`*: `SR_MODE` and `SR_LOG_BUFFER_LINES` (gone in 0.4) are removed and reported; the Basic-auth login, secrets and
  any key you added stay byte for byte. Retention values that you set on the Configuration page are ignored in 0.4:
  put them in `.env`. A missing `COMPOSE_FILE=compose.yaml:compose.ntop.yaml` is added (see the top of this
  document); when it is the only difference, the running stack is left as it is.
- *Start*: the installer polls `https://<host>/healthz` (up to 120 s) instead of sleeping; a stack that does not answer is a
  failure with the hint `docker compose logs api` in the install directory, and `.deployed` is not written, so the next run
  deploys again.
- *The n2disk licence*: the first thing the installer does is copy `/etc/*.license` (and the SystemID, owner, group and mode
  of each file) to `/var/lib/sycope-recorder-installer/licence-backup/<time>/`; nothing there is ever deleted. A valid licence
  is never replaced by the file you give; `--replace-licence` installs it anyway (it is checked with `n2disk -V` and the
  previous one is put back if it is not valid). Licences of the smaller editions (1G, 5G) are valid only for their own
  binary (`n2disk1g`, `n2disk5g`): when `n2disk` answers invalid, the installer asks the binary it names and then
  the other edition binaries, and reports which one the licence is for. ntop's `n2disk@.service` starts that binary
  by itself; the installer warns if the installed unit does not select it. At the end the licence is compared with the backup and any difference is a
  failure with the restore command (`install -m <mode> -o <owner> -g <group> ...` per file).

The manual steps below stay the reference for what it does.

## 1. Check host prerequisites

- [ ] Linux host with Docker Engine + the Compose plugin installed
      (`docker compose version` succeeds).
- [ ] Enough disk under wherever `/storage/pcaps/rolling` and
      `/storage/pcaps/alerts` will live — rolling capture size is driven by
      n2disk's `--disk-limit` (`docs/reference/n2disk.conf`), alerts grow
      until removed: the app's own retention sweep (`SR_RETENTION_*`,
      step 6) is off by default.
- [ ] Inbound firewall allows `443` (and `80` if you want the HTTP→HTTPS
      redirect) from wherever Sycope and download clients connect from.
- [ ] Outbound: only needed if pulling images from a registry (dist option
      2A in `README_DIST.md`); not needed for the offline tarball path.

## 2. Check the recorder/capture side is ready

The `api` container only *reads* from the rolling capture — it does not
record traffic itself. Before deploying `api`, confirm:

- [ ] n2disk (see `docs/reference/`) is already running and writing
      rolling PCAPs + a timeline index to a known path on this host.
- [ ] That path is what you'll bind-mount as `rolling` in step 5 — note it
      down now.
- [ ] The `api` container can read that path. Legacy convention is the
      directory being owned `n2disk:ntop`; no matching group access is
      needed for extractions, since npcapextract runs as root in the
      worker (`SR_NPCAPEXTRACT_USER`, default `root`).
- [ ] n2disk captures through the PF_RING kernel module, not libpcap. Without the module n2disk still runs but logs
      `Unable to open PF_RING device ... Falling back to libpcap..` (`journalctl -u n2disk@<nic>`) and loses
      packets at much lower rates. The installer does this (step `pf_ring`); by hand: install `pfring-dkms`
      (it needs `linux-headers-$(uname -r)`), set
      `min_num_slots=65536` in `/etc/pf_ring/pf_ring.conf`, enable `pf_ring.service`, restart n2disk and check
      that the log says `Packet capture started (packet mode)`. Loading the module did not change the ntop
      SystemID in testing; still compare `n2disk --show-system-id` and run `n2disk --check-license` afterwards.
      Run both as root: as a normal user n2disk cannot read the DMI product UUID, prints a shorter SystemID
      and reports the licence as invalid although it is fine. With Secure Boot the DKMS module only loads
      after its key is enrolled (`mokutil`); until then n2disk keeps recording through libpcap.
- [ ] n2disk writes in 4 MB chunks (`--chunk-len=4096`, `--buffer-len=1024`; the installer's config has both).
      With the default 0.1 MB chunks the disk, not the CPU, was the limit: 27-83% loss at 5-13 Gbit/s in the
      lab, under 1% with 4 MB.

If the recorder isn't wired up yet, stop here and finish that first — do
not deploy `api` against an empty/missing rolling path, since every
`/extract` call is still answered 200 with a link but its job finds no data
to extract (it ends `miss` or `failed`).

## 3. Get the dist artifacts onto the host

Depending on which distribution method was used (see `README_DIST.md`):

- **Registry:** `docker login <registry>` then
  `docker compose -f compose.yaml -f compose.dist.yaml pull`.
- **Offline tarballs:** copy `sycope-recorder-api.tar`, `caddy.tar`,
  `compose.yaml`, `caddy/Caddyfile`, and `compose.dist.yaml` to a
  deployment directory (e.g. `/opt/sycope-recorder/`), then:
  ```bash
  docker load -i sycope-recorder-api.tar
  docker load -i caddy.tar
  ```
- [ ] Verify both images are present: `docker images | grep -E 'sycope-recorder-api|caddy'`.
- [ ] Verify the api image contains `npcapextract` (built with `--build-arg INSTALL_NTOP=1`, `README_DIST.md`
      step 1): `docker run --rm --entrypoint sh sycope-recorder-api:<tag> -c 'command -v npcapextract'` prints a
      path. An image without it starts, but `doctor` reports `npcapextract` FAIL (not found on PATH) and every
      job fails.
- [ ] Verify `compose.dist.yaml`'s `image:` tag matches what you just
      loaded/pulled — a mismatch here is the most common "why won't it
      start" mistake.

## 4. Lay out the deployment directory

On the target host, under your chosen deployment directory you should now
have exactly:

```
compose.yaml
compose.dist.yaml
caddy/Caddyfile
caddy/entrypoint.sh      # refuses to start Caddy on a malformed hash / missing certs
certs/                   # may be empty; own certificate goes here (step 7)
```

Do not copy source, tests, or docs — the dist intentionally excludes them.

## 5. Wire the `rolling` volume to the real capture path

`compose.yaml` defines `rolling` as a Docker-managed named volume by
default. Point it at the actual path from step 2 with a bind mount, added
to `compose.dist.yaml` alongside the `image:` override:

```yaml
volumes:
  rolling:
    driver: local
    driver_opts:
      type: none
      device: /storage/pcaps/rolling   # <- the real path from step 2
      o: bind
```

- [ ] Confirm the path exists and is non-empty (n2disk has written at
      least one rolling file) before moving on.

Do the same for `alerts` if you want PCAPs on a specific host path:

```yaml
volumes:
  alerts:
    driver: local
    driver_opts:
      type: none
      device: /storage/pcaps/alerts
      o: bind
```

**Rebind the named volume, never add a bind mount to one service only.**
`api` writes to `alerts` and `caddy` serves it from the same named volume.
A `volumes: - /storage/pcaps/alerts:/storage/pcaps/alerts` line under `api`
alone makes `api` write to the host while `caddy` keeps serving an empty
Docker volume: PCAPs exist on disk but every download link returns 404.
Check with `docker compose exec api ls /storage/pcaps/alerts` versus
`docker compose exec caddy ls /srv/alerts` - the listings must match.

## 6. Configure environment

Create a `.env` file next to `compose.yaml` (docker compose loads it
automatically). Required and commonly-set variables are below. `compose.yaml` passes every app setting to the container
except the container paths (`SR_STATE_DIR`, `SR_TIMELINE_DIR`, `SR_OUTPUT_DIR`), `SR_PROBE_URL` and
`SR_NPCAPEXTRACT_PATH`, which it fixes; a variable it does not list has no effect in `.env`.
Numeric settings have ranges (below, and the (i) texts on the Configuration page). The same ranges apply to `.env` and
to a configuration upload: an upload outside one is refused; an `.env` value outside one does not stop the api, it is
used as the nearest valid value, logged as `WARNING: SR_...=...: ... using ...` at start and shown by the `settings`
self-check (WARN in `doctor` and on the System page). `SR_PUBLIC_HOST`, `SR_DOWNLOAD_PREFIX`,
`SR_WORKER_STOP_GRACE_SECONDS`, `SR_MIN_FREE_BYTES` and the retention settings can only be set here, not uploaded.

| Variable | Required | Notes |
|---|---|---|
| `SR_PUBLIC_HOST` | **yes** | Hostname Sycope/clients will hit; used in the returned download URL and Caddy's TLS SNI. Environment only (Caddy reads it at start). |
| `BASIC_AUTH_USER` | **yes** | Shared Basic-auth username, enforced by Caddy. |
| `BASIC_AUTH_HASH` | **yes** | Bcrypt hash — generate in step 7, not a plaintext password. In `.env` wrap it in **single quotes**. |
| `ALLOWED_IPS` | no | CIDR allowlist for the legacy file links `/downloads/*` only (Caddy's file server); default open (`0.0.0.0/0 ::/0`). |
| `SR_DOWNLOAD_PREFIX` | no | Path segment for download URLs; default `downloads`. Environment only (Caddy reads it at start). |
| `ALLOWED_EXTRACT_IPS` | no | CIDR allowlist for the **webhook** (any POST that is not an operator action), i.e. Sycope's address; default open. |
| `ALLOWED_UI_IPS` | no | CIDR allowlist for everything else: the pages, the API (`/stats`, JSON), status links, PCAP downloads via `?download=1` and the operator's POST actions (delete, profiles, configuration). Defaults to `ALLOWED_EXTRACT_IPS` (the behaviour before v0.3b1, nothing opens up on upgrade). Set it to let analysts reach the pages directly while the webhook stays Sycope-only. Through Sycope Passthrough every request comes from Sycope's address, so it must be in this list too. |
| `SR_HTTPS_PORT`, `SR_HTTP_PORT` | no | Host ports Caddy is published on (default 443 and 80; compose only). Use them when another service holds 443/80 on the host. With another HTTPS port set `SR_DOWNLOAD_URL_BASE=<host>:<port>` (when links do not go through the Passthrough) and give the Passthrough entry the port in its URL; the installer does both. |
| `SR_DOWNLOAD_URL_BASE` | no | `host[/path]` placed in returned links instead of `SR_PUBLIC_HOST`, for when downloads are reached via another address, e.g. Sycope Passthrough: `sycope.example/npm/api/v1/passthrough/recorder`. Caddy still serves the files; the Passthrough upstream must point at it. |
| `SR_JOB_MAX_ATTEMPTS`, `SR_JOB_RETRY_DELAY_SECONDS`, `SR_QUEUE_MAX` | no | Defaults 3, 120, 2000. |
| `SR_PROFILES_FILE` | no | Path (in the container, e.g. `/profiles/profiles.json`, from `./profiles`) of the per-definition profiles made by `tools/profiles/gen_profiles.py`. Empty (default): every alert uses `SR_DEFAULT_BEFORE/AFTER` and the `filter` mode. With a profile, the definition decides the BPF filter and the window and the query parameters are ignored for that alert. The mounted file is not checked like an upload: unusable values are dropped or set to null with a warning in the log. See `docs/PROFILES.md`. |
| `SR_EXPORTER_LAG_SECONDS`, `SR_WINDOW_MARGIN_SECONDS` | no | Defaults 300 and 30. Profile window = `[T - timeRange - lag, T + margin]`. The lag must be at least the exporter's inactive timeout + the longest flow to cover; too small gives a partial PCAP silently (measured in the lab: full coverage up to a delay equal to the lag, 33% just above it, none a little further; see `docs/PROFILES.md`). |
| `SR_WINDOW_MAX_LAG_SECONDS` | no | Default 900. Retries after a `miss` look back further (lag x2, x4, ...) up to this total. |
| `SR_DEFAULT_BEFORE`, `SR_DEFAULT_AFTER`, `SR_DEFAULT_FILTER` | no | Defaults 360, 360 and `full`. Window (seconds before and after the alert time) and filter mode (`full`, `hosts`, `client`, `server`, `port`) of an alert without a profile; an unknown mode means `full`. |
| `SR_QUIET_WAIT_SECONDS`, `SR_QUIET_POLL_SECONDS` | no | Defaults 21600 and 30. A due job waits (no attempt used) until a rolling file starting after its window end exists, i.e. n2disk has closed the file holding the window end; a quiet link delays that. After this many seconds past the due time it extracts anyway. |
| `SR_WINDOW_WARN_SECONDS` | no | Default 30. A PCAP whose first packet is closer than this to the window start gets a warning on its status page (the window may have cut flows). |
| `SR_ROLLING_CHECK` | no | Default `true`. `false` on hosts without a capture (demo): the `rolling_fresh` check is skipped. |
| `SR_ROLLING_STALE_SECONDS`, `SR_WATCHDOG_INTERVAL_SECONDS` | no | Defaults 900 and 60 seconds. The `rolling_fresh` check fails when the newest rolling file is older than `SR_ROLLING_STALE_SECONDS`; the background self-checks run every `SR_WATCHDOG_INTERVAL_SECONDS`. |
| `SR_ROLLING_DIR`, `SR_ALERTS_DIR` | no | Defaults `/storage/pcaps/rolling` and `/storage/pcaps/alerts`. Host directories bound to the `rolling` and `alerts` volumes; used only with `compose.ntop.yaml`. |
| `SR_SYCOPE_URL`, `SR_SYCOPE_USER`, `SR_SYCOPE_PASSWORD`, `SR_SYCOPE_VERIFY_TLS` | no | `SR_SYCOPE_URL` alone enables the queue's "Open in Raw Data" links. All four enable "Rebuild from Sycope" on the Profiles page: the recorder logs in to Sycope read-only (alert definitions, macros, lookups) and stages new profiles for review; nothing is applied without confirmation. Use a **read-only account**: the password is stored in `.env` and in the container environment (masked in the System page and in the debug bundle). `SR_SYCOPE_VERIFY_TLS` defaults to `true`; Sycope's own self-signed certificate needs `false` or a trusted CA. The URL is `http(s)://<host>[:<port>][/path]` without a user, password, query or fragment. Rebuild from Sycope refuses loopback, link-local (169.254.0.0/16, fe80::/10), unspecified, multicast and reserved addresses and the names `localhost`, `api` and `caddy` (checked again on the address it connects to); private addresses are allowed. It follows no redirect and never shows Sycope's answer: an error gives a short reason only. An answer is limited to 32 MiB and the import to 10,000 alert definitions. |
| `SR_CONFIG_PASSWORD` | no | Enables downloading and uploading the configuration on the Configuration page (the file includes secrets, so it is password-protected; 5 wrong attempts lock it for 5 minutes). An upload becomes `config.override.json` in the state directory and is applied over the environment after a graceful reload; "Remove uploaded configuration" goes back to `.env` alone. Empty = disabled. Never put the password in the repository. |
| `SR_QUEUE_EDIT` | no | `false` (default): the queue page is read-only and the Profiles page cannot change anything. `true` enables row checkboxes, bulk delete (job rows only, PCAPs are never deleted), the persistent star (protects the row and its PCAP from retention), cancel, retry and mark-persistent actions, and on the Profiles page: upload, reload, revert and "Rebuild from Sycope" (each with a review before anything is applied). Cross-site requests are refused (`Sec-Fetch-Site` / `Origin`). |
| `SR_DEBUG_BUNDLE` | no | `false` (default). `true` adds "Download debug logs" to the Menu (`GET /logs`, a zip): recent api log (every npcapextract failure with its output), job table with history, self-checks, redacted settings, disk and rolling-dir summary. Only what the api container sees (no host journal, no PCAP content); credentials are redacted. The bundle holds `web.log` and `worker.log`. |
| `SR_WORKER_STOP_GRACE_SECONDS` | no | Default `30`, 1 to 60 (compose `stop_grace_period` is 90 s). On stop or reload the worker lets running extractions finish this long, then kills them and re-queues the jobs (no attempt used). Environment only: supervisord's wait for the worker is derived from it at container start. |
| `SR_WORKER_HEARTBEAT_SECONDS` | no | Default `5`. How often the worker records that it is alive. |
| `SR_WORKER_STALE_SECONDS` | no | Default `60`. Heartbeat age after which the System page, the queue page and `/healthz/deep` report the worker as dead. |
| `SR_CHUNK_SECONDS` | no | Default `300`; must equal n2disk's `--max-file-duration`. Jobs wait `window_end + chunk + SR_READY_MARGIN_SECONDS` (30 s) so the data is in closed, indexed files. |
| `SR_READY_MARGIN_SECONDS` | no | Default `30`. The margin added after `window_end + chunk` before a job runs. |
| `SR_MIN_FREE_BYTES` | no | Default 5 GiB. Extractions are refused (`ERROR: low disk space`) below this free space on the alerts filesystem. Environment only. |
| `SR_SILENCE_WARN_HOURS` | no | Default `0` (off). Log a warning if no webhook arrived for N hours. |
| `SR_MAX_CONCURRENT_EXTRACTIONS` | no | Compose default `4` (the app's own default is `1`), 1 to 16. The number of worker slots: how many `npcapextract` runs are active at once. Each reads `rolling/`, so tune to disk throughput; jobs beyond it wait in the queue. |
| `SR_NPCAPEXTRACT_USER` | no | Default `root`, passed as `npcapextract -u`. Without it npcapextract drops to `nobody` and fails with `Permission denied` writing to `alerts/`. Empty omits the flag. |
| `TZ` | no | Default `UTC`. The extraction window is built in the container's local time and must equal the n2disk host's timezone (compare `date` on host and in `docker compose exec api date`). |
| `SR_SITE_ADDRESS` | no | Caddy site address; defaults to `SR_PUBLIC_HOST`. Set to `:443` when serving a bare IP with your own certificate. |
| `SR_TLS` | no | Caddy `tls` arguments; default `internal`. See "Own certificate" below. |
| `SR_EXTRACT_TIMEOUT_SECONDS` | no | Default `300`, 10 to 3600. Hard limit for one npcapextract run; a hung run is killed and the job retried. |
| `SR_RETENTION_MAX_AGE_DAYS` | no | Default `0` = **never delete automatically** (PCAPs are alert evidence). Set N to prune files older than N days. Disk safety is `SR_MIN_FREE_BYTES`. |
| `SR_RETENTION_MAX_TOTAL_BYTES` | no | Default `0` (disabled); set a byte cap if disk space is tight. |
| `SR_RETENTION_INTERVAL_SECONDS` | no | Default `3600`. How often the worker runs the retention sweep. Like the two retention limits above it is environment-only: a value set on the Configuration page (`config.override.json`) is ignored in 0.4. |
| `SR_LOG_FORMAT` | no | `text` (default) or `json` — set `json` if logs feed a collector. The installer leaves the value alone. |
| `SR_LOG_LEVEL` | no | Default `INFO`; `DEBUG`, `WARNING`, `ERROR` or `CRITICAL`. Both processes and gunicorn; another value stops the api from starting (`invalid configuration` in its log). |
| `SR_JOB_HISTORY_DAYS` | no | Default 30, at least 1. Finished job rows and their history older than this are deleted (rows of persistent jobs are kept); PCAP files are not touched: a pruned job's PCAP is still offered by its link and is not extracted over by a redelivered webhook. |
| `COMPOSE_FILE` | no | Read by compose, not passed to the containers: the compose files a plain `docker compose` uses (top of this document). The installer writes `compose.yaml:compose.ntop.yaml`; on a dist host leave it out or set `compose.yaml:compose.dist.yaml`, never the installer's value. |

Who may reach what (Caddyfile; `GET /healthz` needs neither an allowlist nor the login):

| Path | Allowlist |
|---|---|
| `GET /downloads/*` (legacy file links) | `ALLOWED_IPS` |
| any other `POST` (the webhook, whatever its path) | `ALLOWED_EXTRACT_IPS` |
| everything else: pages, API, `/<alertId>?download=1`, the pages' POST actions | `ALLOWED_UI_IPS` |

The address is checked before the login: a client outside the path's allowlist gets 403 whatever it sends, never a
401 login prompt, so it cannot try passwords; a client inside it gets 401 without the right login.

Set all three in anything but a fully trusted network: each one left out stays open. The installer writes all three
from its "allowed networks" answer, adding Sycope's address (resolved from the Sycope URL; when the name does not
resolve, the address of an earlier run, with a warning) and this host's own address (its checks call the recorder
through `SR_PUBLIC_HOST`), each only when the answered networks do not already contain it. An `ALLOWED_UI_IPS` or
`ALLOWED_EXTRACT_IPS` set by hand (a value the installer did not write) is kept and reported; remove the line to let
the installer set it again.

- [ ] Double check `SR_PUBLIC_HOST` resolves to this host from wherever
      Sycope and download clients sit (DNS or `/etc/hosts`).

## 7. Generate the Basic-auth hash

```bash
docker run --rm caddy:2 caddy hash-password --plaintext 'yourpassword'
```

The hash has Caddy's default bcrypt cost 14: about 0.7 s of CPU to verify. Caddy keeps verified logins in memory,
so that is paid for the first request on each handler after a Caddy start and for every wrong password, not for
every request.

- [ ] Paste the output into `.env` as `BASIC_AUTH_HASH` (step 6) — do this
      before first bring-up, not after, since Caddy reads it at startup.
- [ ] **Single-quote the hash in `.env`**: `BASIC_AUTH_HASH='$2a$10$abc...'`.
      Unquoted, compose interpolates `$name` sequences and silently eats them
      (`The "XklOO..." variable is not set` warnings), leaving a broken hash
      and 401 on every request. Alternative: double every `$` (`$$2a$$10$$...`,
      every one, not just the first; `docker compose config` then prints the
      doubled form, which is normal). The Caddy container now validates the
      format at start and exits with `FATAL: BASIC_AUTH_HASH is not a valid
      bcrypt hash` instead of looping silently.

### Own certificate (bare IP or no internal CA)

If `SR_PUBLIC_HOST` is a bare IP, or clients cannot trust Caddy's internal
CA, supply a certificate instead:

```bash
mkdir -p certs && openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
  -keyout certs/server.key -out certs/server.crt \
  -subj "/CN=$SR_PUBLIC_HOST" -addext "subjectAltName=IP:$SR_PUBLIC_HOST"
```

(`-days`, not `-day`.) Then in `.env`: `SR_SITE_ADDRESS=:443` and
`SR_TLS=/certs/server.crt /certs/server.key`. Put the files in `./certs/`.

`compose.yaml` already mounts `./certs` at `/certs` read-only (an empty
directory is fine when unused). Keep any extra override file hand-maintained;
do not regenerate it from a script on re-runs. If `SR_TLS` points at files that
are not there, Caddy exits with `FATAL: SR_TLS references ... missing`.

## 8. First bring-up

```bash
cd /opt/sycope-recorder
docker compose -f compose.yaml -f compose.dist.yaml up -d
```

Do **not** pass `--build` — the image is already local/pulled; `--build`
would try (and fail, with no source present) to build from `.`.

- [ ] `docker compose ps` — both `api` and `caddy` should be `Up`/`healthy`
      (the `api` healthcheck takes up to `start_period: 10s` to go green).
- [ ] `docker compose logs api` — no repeated tracebacks; a clean gunicorn
      boot line.
- [ ] `docker compose logs caddy` — confirms it obtained/generated its
      internal TLS cert for `SR_PUBLIC_HOST` without error.

## 9. Smoke test

```bash
# Unauthenticated health check
curl -k https://$SR_PUBLIC_HOST/healthz
# expect: {"status":"ok","timeline_dir_present":true,"output_dir_present":true,"db":"ok"}
```

- [ ] Both `*_present` fields are `true` and `db` is `ok` (503 otherwise: the job database cannot be opened). If `timeline_dir_present` is
      `false`, the bind mount from step 5 is wrong or empty — fix that
      before testing extraction.

```bash
curl -k -u "$BASIC_AUTH_USER:yourpassword" -X POST \
  "https://$SR_PUBLIC_HOST/extract?filter=full&before=30&after=30" \
  -H 'Content-Type: application/json' \
  -d '{"id":"smoke-test","clientIp":"10.0.0.10","serverIp":"10.0.0.20","serverPort":443,"protocolName":"tcp","unixTimestamp":<recent-unix-ts>}'
```

- [ ] Response is HTTP 200 with a download URL at once (not an `ERROR:`/`NO BPF FILTER`
      string): the job is queued and the worker extracts later. Use a real recent timestamp/IPs that exist in the
      current rolling window; an empty match is not an answer to this request, it shows up later as `miss` on the
      alert's status page, even on a fully working stack.
- [ ] Follow the returned URL with `-u` credentials: it is the alert's status
      page, not the file (`curl` gets JSON). It answers 202 "being prepared" until
      the window is on disk (window end + chunk + margin, ~5-6 minutes after
      the alert time); that is expected, not an error. Once it answers 200 with
      `"ready": true`, confirm the PCAP downloads with
      `curl -k -OJ -u ... '<returned URL>?download=1'`.

```bash
# Self-check: every seam that failed at the first customer
docker compose -f compose.yaml -f compose.dist.yaml exec api python -m sycope_recorder doctor
# same over HTTP (503 when any check FAILs):
curl -sk -u "$BASIC_AUTH_USER:yourpassword" https://$SR_PUBLIC_HOST/healthz/deep
```

- [ ] `doctor` shows no `FAIL`. `rolling_fresh` FAIL means n2disk is not
      writing (licence, capture interface carrier, wrong path);
      `alerts_visible_to_caddy` FAIL means api and caddy do not share the
      `alerts` volume (step 5); `timezone` WARN means set `TZ` (step 6).

`-k` above is only because Caddy's internal CA is self-signed; production
Sycope/client configs should trust that CA rather than skip verification
long-term.

## 10. Point Sycope at the deployment

- [ ] In Sycope, set the webhook action to
      `POST https://$SR_PUBLIC_HOST/extract?filter=full&before=360&after=360`
      (or your chosen filter/window) with the same Basic-auth credentials
      from step 6/7.
- [ ] If the link goes through **Sycope Passthrough**, the entry's access rules are
      `GET ^/downloads/.*`, `GET ^/([A-Za-z0-9_-]+)?/?$` and `POST ^/.*`. Every path of the recorder except
      `/healthz/deep` (two segments, not covered by these rules) is one
      segment of `[A-Za-z0-9_-]` (the PCAP is `?download=1`), so these three cover the queue, the status pages,
      System, Profiles, Configuration, the log download and the webhook. The Passthrough answers **HTTP 502 to a
      form body (`application/x-www-form-urlencoded`)**; the pages therefore post their actions as JSON from a
      script, so keep JavaScript enabled in the browser that operates the recorder.
- [ ] The webhook returns in milliseconds (the job is queued, the worker extracts later), so Sycope-side
      timeouts do not occur.
- [ ] If clients (Sycope or download consumers) can't be configured to
      trust Caddy's internal CA, they'll need `-k`/insecure-mode equivalents
      — flag this to whoever owns the Sycope config.

## 11. Post-deploy checklist

- [ ] **Persist `caddy_data`/`caddy_config` volumes.** They hold the
      internal CA and cert — losing them on a redeploy forces every client
      to re-trust a new cert. Don't `docker compose down -v` casually.
- [ ] **Confirm `restart: unless-stopped`** took effect (`docker inspect`
      on both containers) so the stack survives a host reboot.
- [ ] **Set a reminder to revisit `ALLOWED_IPS`, `ALLOWED_UI_IPS` and `ALLOWED_EXTRACT_IPS`** if any is
      left at the open default in step 6.
- [ ] **Open the System page** (Menu, `/system`): every check green, and "Rolling buffer history" at least what
      the longest profile needs (3600 s needs about 71 min; the buffer is limited by size, so raise n2disk
      `--disk-limit` if it is shorter).
- [ ] **Decide the switches on purpose**: `SR_QUEUE_EDIT` (edit the queue and profiles), `SR_DEBUG_BUNDLE`
      (log download), `SR_CONFIG_PASSWORD` (download/upload the configuration; a strong password, only in
      `.env`), `SR_SYCOPE_*` (rebuild profiles from Sycope; a read-only account). All are off by default.
- [ ] Record the deployed image tag(s) somewhere (e.g. `docker inspect
      --format '{{.Config.Image}}'`) so a future redeploy/rollback knows
      what's currently running.

## 12. Updating later

```bash
# dist host: after loading/pulling a new image tag and bumping compose.dist.yaml's `image:`
docker compose -f compose.yaml -f compose.dist.yaml up -d

# installer host: run the installer of the new release (it syncs the code, builds and restarts the stack)
sudo tools/install/install.sh
# or by hand, after copying the new release into the install directory
docker compose -f compose.yaml -f compose.ntop.yaml up -d --build
```

Compose recreates only the containers whose config/image changed —
`caddy_data`/`caddy_config`/`rolling`/`alerts`/`state` volumes are untouched. Re-run
the step 9 smoke test after every update before considering it done.

The running release is shown on the System page and in `/stats` (`version`). What lives where across updates:
the job database `jobs.db`, an uploaded profiles file (`profiles.override.json` with its `profiles.override.info.json`) and an uploaded configuration
(`config.override.json`) are in the `state` volume, so they survive an update. A 0.3 `jobs.db` is moved aside on first start and the queue starts empty (below); a 0.4 database
(schema 4 or 5) is migrated in place to schema 6 (the `important` flag becomes `persistent`, the PCAP size, the job's
origin, its parent job and the PCAP content are added, the history stays); one with a newer schema is refused
(`/healthz` 503). A rollback to an older release therefore needs a copy of `jobs.db` taken before the update.
From v0.4b1 to v0.4b2 the update is in place: deploy the new files and
`docker compose -f compose.yaml -f compose.ntop.yaml up -d --build` (a dist host: the new image and the dist command
above); the queue,
the PCAPs and the settings stay. v0.4b2 adds no setting; `SR_SYCOPE_URL` alone now also enables the queue's
"Open in Raw Data" links.
From v0.4b2 to v0.4b3 the update is in place too (no schema change, no new setting). Run the installer once:
it adds the PF_RING kernel module (step `pf_ring`) and rewrites a managed n2disk configuration with 4 MB write
chunks and a 1 GB buffer (a backup is kept, n2disk restarts once). Check its remembered rolling size limit
first: the rewritten configuration uses that answer for `--disk-limit`.
From v0.4b4 to v0.4b5 the update is in place (no schema change, no new setting). Running the installer adds the step
`passthrough`: it creates or corrects the Sycope Passthrough (the Sycope user needs the right to edit Passthrough,
otherwise the step warns and nothing changes). An existing Basic-auth password is kept; a new install gets 48
characters.
From v0.4b5 to v0.4b6 the update is in place (no schema change, no new setting, nothing changes for the recorder
itself). Running the installer asks the new question `profile` (keep `recorder-only` for the same set-up as before),
adds the steps `tuning` and `licence_inbox` and repeats `capture_nic` once without a change. The tuning drop-ins for
n2disk apply at its next start; the installer does not restart it for that.
After v0.4b6: Caddy compresses the pages and JSON answers (zstd or gzip); PCAP and zip downloads are not
compressed. An alert id with characters outside `[A-Za-z0-9_-]`, or longer than 64, gets a link and file name
ending in 12 hex digits; links and files made before keep their names. The installer and Rebuild from Sycope no
longer follow a redirect from Sycope: give the address Sycope answers on (`https://...`).
From v0.4b3 to v0.4b4 the update is in place (no schema change, no new setting). A `profiles.json` in the older
list format keeps working; the Profiles page downloads the new format (format 2, the editable fields with a help
block) and *Rebuild from Sycope* writes it with its `profiles.info.json`. Running the installer again regenerates
the profiles in the new format (step `profiles` version 2). The queue's auto refresh is now off until switched on.
From v0.3b1 to v0.4 the update is a clean install: let the queue empty, `docker compose down`, deploy the new
files, `docker compose -f compose.yaml -f compose.ntop.yaml up -d --build` (a dist host: the new image and the dist
command above). The 0.3 `jobs.db` is moved aside to `jobs.db.0.3-<timestamp>` on first start
(never deleted, never migrated). The api container now runs a web process (user `sr`) and a worker (root) under
supervisord; tools run in it with `docker compose exec api ...`. `docker compose run --rm api <cmd>` (with the
host's compose files, see the top of this document) also works:
the entrypoint does its permission setup and then runs `<cmd>` as root instead of the services (start with
`umask 002;` through `sh -c` when it writes into the state directory). `tools/install/install.sh` does the whole update
including the report of abandoned jobs (section 0).
An uploaded configuration overrides `.env` for the keys it contains: the Configuration page shows each value's
source, and "Remove uploaded configuration" returns to `.env` alone. After an update to a release with ranges or
environment-only settings: an `.env` value outside its range is used as the nearest valid value and an uploaded
value of an environment-only setting (`public_host`, `download_prefix`, `worker_stop_grace_seconds`,
`min_free_bytes`, `probe_url`) is ignored; each is a `WARNING` in the api log and a `settings` WARN in `doctor`.
Put the value you want in `.env` and recreate `api`. A configuration file downloaded before that update contains
those five keys and is refused on upload ("cannot be changed here (locked)"): delete them from the file, or download
it again. On the first start after the update the entrypoint sets `config.override.json`, its `.prev` and the staged
uploads to mode 0600 (they can hold the Sycope password); staged uploads left by earlier versions are removed at the
next upload.

**First update from the September 2026 deployment** (the first customer version, before 0.3): run the installer
from the new release (`sudo tools/install/install.sh`, a `--dry-run` first shows what it would do). It recognises
that host and adopts what it finds:

- **n2disk** that runs from its own unit (`n2disk.service` with `/etc/n2disk/n2disk.conf`) is adopted as it is: the
  installer writes no `n2disk-<nic>.conf`, starts no `n2disk@<nic>`, restarts nothing and does not load PF_RING or
  apply the NIC tuning. The questions take its NIC, directory and file duration as defaults, and the step
  `n2disk_config` checks that the answers agree with it (a mismatch is a failure, so is a second n2disk on the same
  NIC). A unit that would restart forever on an invalid licence is reported. The unit is adopted also when it does
  not record: failed, restarting (an expired licence) or stopped but enabled. The installer still sets up no second
  n2disk and does not start this one; the report says whether the licence is valid and gives the commands
  (`sycope-licence` or `install.sh --licence`, then `systemctl reset-failed n2disk.service && systemctl restart
  n2disk.service`). Before, such a unit was missed and `n2disk@<nic>` was set up beside it on the same NIC and buffer.
- **The stack in `/opt/sycope-recorder`** (no `.deployed`): `.env`, the compose files, `caddy/` and `certs/` are copied
  to `/var/lib/sycope-recorder-installer/stack-backup/<time>/`, the stack is stopped with its own compose files
  (`down`, never `-v`), then this release is deployed in its place. `.env` keeps every key the operator set; an
  unquoted `BASIC_AUTH_HASH` is quoted; a certificate in `caddy/certs` is used from `certs/` (`SR_SITE_ADDRESS=:443`,
  `SR_TLS`). `SR_RETENTION_MAX_AGE_DAYS` and `SR_MAX_CONCURRENT_EXTRACTIONS` from the old `.env` are kept and reported.
  An empty `rolling`/`alerts` Docker volume of the old stack that is not bound to the directories is removed; one that
  holds files stops the install (copy them out first).
- **The password**: the installer asks for the current recorder password (`BASIC_AUTH_PASS`), checks it against the
  new stack and keeps it in `credentials`. Without it a new password is made and put into the Passthrough; a Sycope
  External Destination that posted straight to `https://<recorder>/extract` must then use the Passthrough path.
- **The test**: the step `passthrough` posts the self-test webhook through the Passthrough, and the step `e2e` sends
  a real alert for the busiest address on the capture NIC through it, waits for the extraction and downloads the
  PCAP through it (`done` ok, `miss` a warning). It leaves one job `installer-e2e-<time>`.

The manual steps below are what the installer does; they stay for a host where it cannot run.


1. Back up `.env`, the `state` volume (`jobs.db`), the compose files and any generated profiles.
2. Check that `SR_CHUNK_SECONDS` equals n2disk's `--max-file-duration` and `TZ` is the host's zone.
   `SR_NPCAPEXTRACT_USER` defaults to `root` and needs no line in `.env`; an old `.env` that sets it to another
   user or to empty now takes effect (npcapextract then cannot write to `alerts/`): remove that line. Other settings
   an old `.env` carries (e.g. `SR_LOG_LEVEL`, `SR_DEFAULT_BEFORE`) take effect too: check each one.
3. Set in `.env`: `SR_PROFILES_FILE=/profiles/profiles.json`, `SR_EXPORTER_LAG_SECONDS` (300 to start with; change
   it after measuring the exporter's lag), `SR_DOWNLOAD_URL_BASE` when links go through the Passthrough. Remove
   `SR_MODE` and `SR_LOG_BUFFER_LINES` (the installer does this). Retention values must be in `.env`
   (`SR_RETENTION_*`); a value set only on the Configuration page is ignored and the PCAPs are then kept.
4. Generate the profiles from the customer's Sycope (`tools/profiles/gen_profiles.py --macros`, or the installer)
   into `./profiles/profiles.json` (it writes `profiles.info.json` next to it) and read the macro report: a macro
   that cannot be read gives a wider filter. A `profiles.json` in the older list format keeps working.
5. Widen the Passthrough path rules (section 10) and confirm that `POST /extract` still passes.
6. Let the old queue empty, `docker compose down`, deploy the new files, then
   `docker compose -f compose.yaml -f compose.ntop.yaml up -d --build` and
   `docker compose exec api python -m sycope_recorder doctor` (every check green). `tools/install/install.sh` does
   steps 2, 3 and 6 itself, from any state, and lists the jobs the old release left queued or running.
7. Test: a test webhook, its link, the status page (202, then 200), the download `?download=1`, `miss` for an alert
   without packets and `NO BPF FILTER` for a whole-link aggregate.
8. Turn on deliberately, if wanted: `SR_QUEUE_EDIT`, `SR_DEBUG_BUNDLE`, `SR_CONFIG_PASSWORD` (a strong password,
   only in `.env`), `SR_SYCOPE_*` (a read-only account).
9. On the System page the rolling buffer history must not be shorter than the longest profile needs (3600 s needs
   about 71 minutes); raise n2disk's `--disk-limit` if it is.
10. Rollback: the previous image plus the copy of `jobs.db`. Old `/downloads/<file>` links keep working.

### Sycope Triage beside the recorder (optional)

Answer `triage=yes` (`INSTALL_TRIAGE=yes`). When the package brings a Triage zip in `bundled/`, it is taken without a
question, whatever its file name or version (the answer is stored as `bundled`, so the next package's zip is taken the
same way); otherwise give the path of a Triage release (`TRIAGE_SRC`, the `sycope_clusters` directory or a zip of it;
a sibling of this repository is offered). `TRIAGE_SRC` given explicitly wins over the bundled zip. A zip is unpacked
into a temporary directory for the run. The step `triage` copies it to `/opt/sycope-triage`, writes its
`.env` (Sycope URL and account, `SC_BASE_HREF` on its Passthrough, `SC_RECORDER_PASSTHROUGH`, the recorder's External
Destination when found, `SC_TRIAGE_EDIT=true` when the `.env` does not set it: analysts can acknowledge, mark
false positives and add exceptions; an operator's `SC_TRIAGE_EDIT=false` stays), makes its Basic-auth login (`/opt/sycope-triage/credentials`), caps its memory
(`compose.limits.yaml`, `mem_limit` = `SC_MEMORY_MB`, 2048 by default, `TRIAGE_MEMORY_MB`), starts it on port 8444
(`TRIAGE_PORT`) and creates its Passthrough (`clusters`, `TRIAGE_PASSTHROUGH_NAME`; rules `GET ^/([A-Za-z0-9_-]+)?/?$`,
`POST ^/(scoring-model|pcap-request|action)$`), then reaches it through the Passthrough. It refuses to start Triage
when the host has less than its budget plus 512 MB available: the capture must keep its memory. Triage uses its own
Sycope account if given (`TRIAGE_SYCOPE_USER`, `TRIAGE_SYCOPE_PASS`), else the installer's.

**CPU.** Triage's data library (polars) is built for x86-64-v3 by default (AVX2, FMA, BMI2, ...). A VM with a generic
CPU type (Proxmox `kvm64` or `x86-64-v2-AES`) lacks those instructions: the app dies on its first query and its Caddy
answers 502. The step reads the CPU flags first. A Triage release that handles it (the bundled one) builds polars'
compat runtime by itself (slower, `SC_POLARS_RUNTIME=auto|compat|default`) and the report warns; an older release is
refused before it is built. A CPU type `host` or `x86-64-v3` in the VM settings removes the need, but **check the
n2disk SystemID before and after** (`n2disk --show-system-id`): a hardware change of the VM can change it and void
the licence.

### Uninstalling

`sudo tools/install/uninstall.sh` removes what the installer set up. It first shows what it would remove and what
stays, then asks (`--yes` does not ask, `--dry-run` prints the commands). **It keeps the licences** (`/etc/*.license`,
the backups in `/var/lib/sycope-recorder-installer/licence-backup` and any licence still in the inbox), backs them up
first and checks them at the end, so they can be replaced by hand later or found again by a new installation. **It
keeps the PCAPs**: the rolling buffer and the alerts directory with their contents (delete them yourself if they are no
longer evidence).

Removed: the recorder stack (containers, the images built for it, its Docker volumes; a volume bound to the rolling or
alerts directory only when nothing mounts it, its files stay) and the install directory (except an own certificate
in `certs/`), Triage (containers, volumes, `/opt/sycope-triage`; either directory only when it holds the installer's
`.deployed` record, otherwise it is kept and reported), the Passthrough entries (`PASSTHROUGH_NAME`,
`TRIAGE_PASSTHROUGH_NAME`) and the External Destination (`DESTINATION_NAME`) in Sycope **when they point at this
recorder** (others are left and reported; `--keep-sycope` touches nothing in Sycope), the `n2disk@<nic>` and
`nprobe@<name>` services and the configurations the installer wrote, the capture NIC and tuning units, the IRQ script
and the sysctl file (the NIC and kernel settings stay until a reboot), PF_RING (when nothing uses it), the licence
inbox units, the `sycope-licence` menu and group, the packages `n2disk`, `nprobe`, `pfring-dkms`, `pfring` and the
ntop repository (with `apt-get remove`, never purge, and only when apt would remove nothing else and the package does
not own a licence file), and the installer's answers, passwords and reports. Docker only with `--remove-docker`, and not
while other containers exist; its data (`/var/lib/docker`) stays.

Kept as well: an n2disk that runs outside `n2disk@<nic>` (the adopted `n2disk.service`, with its package and PF_RING),
configurations edited by hand and the `.bak` copies of earlier ones, the base packages. A report of the uninstall is
saved as `/var/lib/sycope-recorder-installer/uninstall-<time>.md`.

## 13. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Download link returns 404, file exists in `alerts/` on the host | `api` and `caddy` see different `alerts` storage (bind mount added to `api` only) | Rebind the named volume (step 5); compare `ls` in both containers |
| `npcapextract failed rc=255 ... Permission denied` creating the output file | npcapextract dropped to `nobody`; `alerts/` not writable by it | Keep `SR_NPCAPEXTRACT_USER=root` (default); do not use `chmod 0777` |
| Caddy restarts with `FATAL: BASIC_AUTH_HASH is not a valid bcrypt hash`, or every request 401 | `$` in the hash eaten by compose | Single-quote the hash in `.env` (step 7) |
| Caddy exits with `FATAL: SR_TLS references ... missing` | Own-cert mode but files not in `./certs/` | Put `server.crt`/`server.key` in `./certs/` (step 7) |
| A job is `failed` with `the worker stopped unexpectedly while this job ran, 3 times in a row` | The worker died (hang watchdog, kill, out of memory) each time this job ran; after the third time it is not queued again | Look in `worker.log` for the exit before each restart; when the cause is gone, Retry the job in the queue |
| Analysts get `Forbidden` (403) on the status page or the download, Sycope's webhook works | `ALLOWED_EXTRACT_IPS` is Sycope-only and `ALLOWED_UI_IPS` is unset, so the pages follow it | Set `ALLOWED_UI_IPS` to the analysts' networks (and Sycope's address if it proxies them) |
| `docker compose up` fails with `failed to bind host port for 0.0.0.0:80 ... address already in use` | Another service (often Apache or nginx) listens on 80 or 443 | `ss -ltnp 'sport = :80'` names it; set `SR_HTTPS_PORT`/`SR_HTTP_PORT` (the installer asks), or stop that service |
| Triage answers **502** through its port or Passthrough; `docker compose logs app` shows `Missing required CPU features ... avx, avx2, fma` from polars | The VM's CPU type has no AVX2 (Proxmox `kvm64`, `x86-64-v2-AES`) and the Triage release uses polars' default runtime | Install the bundled Triage release (it builds the compat runtime), or set `SC_POLARS_RUNTIME=compat` and rebuild; a CPU type `host` also works, but compare the n2disk SystemID before and after |
| Alerts stopped producing jobs; the Passthrough audit shows the recorder's External Destination calls with user `-` and 401 | Sycope's REST client drops the destination's Basic auth after a while (seen on the 2026-11 lab Sycope) | `sudo tools/install/install.sh --update-passthrough` sets the password again (it helps only until it happens again); report it to Sycope |
| `429 Queue full` | More than `SR_QUEUE_MAX` (2000) jobs pending | Check `/stats` queue and `doctor`; usually n2disk/disk trouble stalled the workers |
| An action on a page (Apply, delete, star) answers **502** through Sycope Passthrough but works direct | Passthrough rejects an urlencoded form body | Use the current release (pages post JSON); keep JavaScript on; test through Passthrough, not only direct |
| A button answers `Disabled: set SR_QUEUE_EDIT=true` (403) | Edits are off by default | Set the flag in `.env` and recreate `api` (`docker compose up -d api` with the host's compose files, see the top of this document; `restart` does not read `.env`); deliberately off on read-only installs |
| Configuration download/upload says "disabled" or "Wrong configuration password" | `SR_CONFIG_PASSWORD` empty, or wrong; 5 wrong attempts lock it for 5 minutes | Set it in `.env`, wait out the lock |
| "Rebuild from Sycope" says `cannot reach Sycope` / `certificate verify failed` | Wrong `SR_SYCOPE_URL`, or Sycope's self-signed certificate | Check the URL; `SR_SYCOPE_VERIFY_TLS=false` or trust the CA |
| "Rebuild from Sycope" says `Sycope answered HTTP 30x ... (a redirect, not followed)` | The URL is `http` where Sycope wants `https`, or a wrong host or path; redirects are not followed | Set `SR_SYCOPE_URL` to the address Sycope answers on, usually `https://<address>` |
| "Rebuild from Sycope" says `... is not JSON` or `... is not HTTP` | The URL points at something that is not Sycope's API | Check host and port |
| "Rebuild from Sycope" says `SR_SYCOPE_URL is refused: ...` | A loopback or link-local address, or the recorder's own service name | Use Sycope's real address |
| "Rebuild from Sycope" says `login refused (status N)` | Wrong user or password (Sycope's own message is not shown) | Check `SR_SYCOPE_USER` and `SR_SYCOPE_PASSWORD` |
| Rebuilt profiles list macros "could not be read (HTTP 403)" | The Sycope account cannot read macros | Their profiles keep a broader filter; use an account with that right |
| An uploaded profiles/configuration file is rejected | Validation found errors (structure, a filter that cannot be built, a path that does not exist) | The review lists each error; nothing was changed |
| Alert link answers 403 through Sycope Passthrough | The Passthrough entry only allows `GET ^/downloads/.*` | Add `GET ^/([A-Za-z0-9_-]+)?/?$` to the entry's access rules (alert links, status table and `?download=1`: the query string is not part of the path regex). No trailing space after `$`, and the upstream URL needs its port (`https://host:8443`) |
| Alert link / table shows "Not found" for a fresh alert | The recorder never received that webhook (check the destination and Passthrough), or it was removed from the queue | Check `/queue`, the api log, the alert's destination in Sycope |
| Download shows "PCAP is being prepared" | Job not due yet: window not fully captured | Wait; the page says when. Reload after |
| Download shows "No packets matched ..." | Job ran, zero packets in that window for that flow | Genuine MISS: wrong window/filter mode, or traffic not on the monitored span |
| Download shows "Extraction failed after N attempts: ..." | npcapextract errored every attempt | `docker compose logs api` around the alert id; run `doctor` |
| Webhook answers `ERROR: low disk space` | Free space on `alerts` filesystem below `SR_MIN_FREE_BYTES` | Free disk, or set `SR_RETENTION_MAX_AGE_DAYS` / move `alerts` to a bigger volume; `doctor` shows `output_dir` |
| Jobs stay `queued`, System page says the worker is not running | worker crash-looping or waiting for `worker.lock` | `docker compose exec api supervisorctl status`; `docker compose logs api \| grep '\[worker\]'` |
| Jobs stay `queued`, worker `paused` | an operator paused it | System page: Resume (needs `SR_QUEUE_EDIT=true`) |
| `attempt to write a readonly database` in the web log | a file in the state directory is not group `sr`/writable | `docker compose restart api` (the entrypoint repairs it); never run tools in the container with another umask |
| `/healthz` 503 `<path> has schema N; this release understands 6` | an older image started on a newer database | deploy the newer image again; nothing was changed |
| `docker compose logs api` shows `CHECK ...: FAIL` | The watchdog saw a seam break | It names the cause; `doctor` for current state |
| Job `miss` / `failed: npcapextract failed (see the worker log for rc and stderr)` for fresh alerts | Window not yet written (n2disk chunk still open) or TZ mismatch host vs container | Wait for chunk close; compare `date` in host and container, set `TZ` |
| Job `failed: npcapextract failed (see the worker log for rc and stderr)` and `No space left on device` writing `.idx`/`.pcap` | `/storage` is not a separate mount, or disk full | `df -h /storage/pcaps/rolling`, `df -i`, `lsblk` |
| No files at all in `rolling/` though `n2disk` is `active` | Capture interface has `NO-CARRIER` (cable/SPAN), or invalid licence | `ip -s link show <iface>` twice; `journalctl -u n2disk`; check `/etc/n2disk.license` |
| `Invalid license` and thousands of restarts in `journalctl -u n2disk` | Expired/missing ntop licence | Renew; the unit in `docs/reference/` now stops after 5 failures in 10 min (`reset-failed` after fixing) |
| `/healthz` returns 404 | Typo (`/healtz`) | Use `/healthz` |
