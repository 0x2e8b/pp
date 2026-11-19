# Sycope Traffic Recorder v0.4b6

Alert-triggered PCAP extraction. Sycope fires a webhook, the service builds a
BPF filter from the alert, runs ntop's `npcapextract` against n2disk's rolling
capture, and gives back an HTTPS link to the extracted PCAP. Caddy serves the
files; the API is FastAPI under gunicorn.

Release **v0.4b6** (`pyproject.toml` 0.4.0b6). It is shown on the System page, in `/stats` and in the debug
bundle. What changed between releases: `RELEASES.md`; how to update, also from the September 2026 deployment:
`README_DEPLOY.md` section 12.

Read this file first. Deeper docs:

| File | What it is for |
|---|---|
| `README_DEPLOY.md` | Step-by-step deployment runbook, `.env` reference, troubleshooting table |
| `README_DIST.md` | Building and shipping the images |
| `docs/PROFILES.md` | Per-definition extraction profiles: how a filter and a window are derived from an alert definition |
| `RELEASES.md` | Release notes: v0.4b6 and the earlier v0.4b5, v0.4b4, v0.4b3, v0.4b2, v0.4b1 and v0.3b1 |

## How it works

```
n2disk (host) --> rolling/ (PCAP + timeline index, a closed file every 300 s)
Sycope alert --webhook--> Caddy (TLS, Basic auth) --unix socket--> api
api: parse alert -> validate IPs -> profile of the alert's definition (if any)
     -> BPF from the definition's grouping keys, window [T - range - lag, T + margin]
     -> npcapextract -u root -> PCAP in alerts/ <-- Caddy serves /downloads/*
```

**Per-definition profiles.** An alert payload carries only the bucket-end `timestamp` and the key
fields of one occurrence; what the alert *covers* lives in its Sycope definition (aggregation keys,
pre-filters, `timeRange`). With `SR_PROFILES_FILE` set, the recorder looks the alert's definition up
(`definitionId`) and builds the BPF filter from exactly the keys the definition groups by, and the
window from its `timeRange` plus `SR_EXPORTER_LAG_SECONDS` (exporters report flows late) and a small
margin. Whole-link aggregates (BPS, PPS, flows) have no packet key and answer `NO BPF FILTER`.
Alerts without a profile keep the old `before`/`after`/`filter` behaviour. Profiles are built from
Sycope with `tools/profiles/gen_profiles.py` or on the **Profiles** page (see below); details in
`docs/PROFILES.md`.

**Why a PCAP can be "not there yet".** npcapextract only sees files n2disk has
closed and indexed (every `--max-file-duration`, 300 s in
`docs/reference/n2disk.conf`). An alert for "now" with `after=360` needs data
that does not exist yet. That is the root of most "empty extraction" reports.

**Quiet links.** n2disk keeps the newest packets in memory and writes them out, closing the file,
only when the *next* packet arrives after the rotation time. After a burst of traffic followed by
silence the tail of the capture is not on disk at all (measured: nothing in any file until one
more packet arrived). So a job is also held until a rolling file *starting after the window end*
exists, the proof that the file with the window end is closed. While it waits, the job stays
`queued` (no attempt used), its status page says `waiting: n2disk has not written past the window
end ...`, and it runs by itself once traffic resumes. After `SR_QUIET_WAIT_SECONDS` (6 h) past its
due time it extracts anyway and records whatever that finds (`done` or `miss`). A real link normally has background traffic
(ARP, DHCP, NTP) and never waits. Waiting jobs are checked every `SR_QUIET_POLL_SECONDS` (30 s) against one listing
of the newest rolling directory, shared by all of them and reused for up to 5 s; a job that is still waiting is
not claimed and takes no worker slot.

### Architecture

One container (`api`) runs two processes under supervisord (started by tini):

- **web** (gunicorn, user `sr`): takes Sycope's webhook, plans the extraction (window, BPF), queues a job in
  SQLite (`state/jobs.db`) and answers at once with the alert's link; serves the queue, alert and System pages.
- **worker** (root): claims due jobs, runs npcapextract, retries, and does the housekeeping (self-checks,
  pruning old job rows, optional PCAP retention). `python -m sycope_recorder worker`.

They share nothing but the database. Operator actions (cancel, retry, pause, a configuration apply) are
written there and the worker picks them up within about a second. `docker compose exec api supervisorctl status`
shows both.

`POST /extract` validates, queues one job (`SR_STATE_DIR`, volume `state`) and answers immediately with the
*final* download URL (the legacy blocking mode is gone; the answer is still HTTP 200 with the link in the body).
The worker runs the job once `window_end + SR_CHUNK_SECONDS + SR_READY_MARGIN_SECONDS` has passed, retries up to
`SR_JOB_MAX_ATTEMPTS` times, and survives restarts of either process (interrupted jobs return to the queue; a job
that was running when the worker died, not stopped, three times in a row ends `failed` and is not tried again). One
webhook = one job = one PCAP; the same webhook delivered twice maps to the same job: it answers `exists` while the
job is queued, running, or done with its PCAP on disk, and queues the job again when it ended miss, failed or
cancelled or when its PCAP has been deleted since. A PCAP that is on disk is never extracted over, also after its
job row was pruned. A link clicked before the
file exists shows a "being prepared" page (HTTP 202); a job with no matching packets shows an explanation instead
of a bare 404. Both come from `GET /status/<file>`, reached through Caddy's `handle_errors`.

The web runs as `sr` and the worker as root, both with umask 002 in setgid `root:sr` directories (the state
directory is `root:sr` 2775, deliberately not sticky). On start the entrypoint hands files of an older volume to
`sr`; it skips symbolic links and only warns when a permission cannot be changed. The root side never follows a
link in the state directory. The uploaded configuration (`config.override.json`, its `.prev` and the staged
upload) can hold the Sycope password and is readable by its owner only (0600); the entrypoint sets that on start
too. Staged uploads of the configuration and of profiles are removed when one is applied, when older than 24 h,
and beyond the newest ten. Logs: `docker compose logs api` has both processes (`[web]`/`[worker]`); files are
`state/logs/web.log` and `/var/log/sycope-recorder/worker.log` (inside the container, lost when it is re-created).
Run tools in the running container with `docker compose exec api ...`. `docker compose run --rm api <cmd>` runs
`<cmd>` instead of the services, as root, after the entrypoint's permission setup (use `sh -c 'umask 002; <cmd>'` when
it writes into the state directory).

The `docker compose` commands in this file are run in the deployment directory. `exec`, `logs`, `ps` and `restart`
act on the running containers; `up`, `run` and `pull` need the host's compose files: on a host set up by the installer
`compose.yaml` and `compose.ntop.yaml` (its `.env` selects them with `COMPOSE_FILE`), on a dist host
`-f compose.yaml -f compose.dist.yaml` (`README_DEPLOY.md`, the note at the top).

### The link in the alert

`/extract` answers with a link keyed by the **alert id**, not by file name:

```
https://<base>/<alertId>
  <base> = SR_DOWNLOAD_URL_BASE, e.g. sycope.example/npm/api/v1/passthrough/recorder  (via Sycope Passthrough)
         = SR_PUBLIC_HOST                                                             (direct, otherwise)
```

Opening it always shows the **status page** of that alert (HTML for browsers, JSON for scripts
or with `?format=json`), never the file: jobs, window, due time, attempts, alert details and the
whole history of events. When the PCAP exists the page says so and has a **Download PCAP** button;
the file itself is `<link>?download=1` (same path, an attachment, `application/vnd.tcpdump.pcap`),
so Passthrough rules that allow the link also allow the download. The status code says what is
going on: `200` PCAP ready, `202` still being prepared (page reloads itself, `Retry-After: 30`),
`404` no packets matched or unknown alert, `502` extraction failed, `410` extracted but deleted
since (a redelivered webhook extracts it again while the data is still in the rolling buffer). Only a `done` job
offers a file; for an alert without any job row (rows pruned after `SR_JOB_HISTORY_DAYS`) a matching file in the
alerts directory is shown. `?download=1` for a PCAP that is not available answers with that status and a one-line
text (`PCAP not available (state: miss)`). In JSON: `ready`, `file`, `download`. `<alertId>` is the
Sycope alert id when that is 1 to 64 of `[A-Za-z0-9_-]`. Any other id is reduced to those characters (at most 51)
and followed by `-` and 12 hex digits of its SHA-256, so two ids that reduce alike get different links; the same
form is in the file name. Rows and files made by earlier releases keep the reduced form.

`GET /` (and `GET /queue`) is the **queue**: the history of all PCAP jobs for browsers, in the look of Sycope's alert
view. It lists the whole queue (up to `SR_QUEUE_MAX`, 2000) in pages (`?page=1&size=100`, sizes 50 / 100 / 200 / 500,
set from the gear above the table); page links keep the active filters. A row shows the alert name and id, severity,
state, attempts, alert time, **due time**, last update and the PCAP link; it expands (`<details>`) into the alert
details (the alert's Description is a collapsed item next to Tags), the PCAP job (file, BPF filter, window, links) and
the whole history of events with reasons. `?open=all` expands every row, `?open=<alertId>` one. Every column has an
**(i)** that explains it and a second line with the field's name.

Above the table: **Action** (the bulk actions, see below) at the left and, at the right, a **column selector** (it adds
client and server IP, server port, protocol, profile and the persistent flag), **saved views**, **Search** and a
**gear** (rows per page, expand or collapse all rows). The column choice and the saved views (columns, search, state,
order, rows per page) are kept in the browser only; nothing is stored on the server.

**Search** (`?q=`, for everyone, not only with `SR_QUEUE_EDIT`) is one free-text field like Sycope's. Words are ANDed,
`"in quotes"` is a phrase, matching is case-insensitive substring, there is no `field=value` syntax. It searches the
alert (name, id, severity, MITRE tactic/technique/subtechnique/id, rule type, rule id, definition id), the flow (client
and server IP, server port, protocol), the job (state, the word `persistent`, alert time as `2026-10-13 21:05:00` in
server time, profile, extraction window) and the PCAP size (`1.5MB`, within 5 %). It runs in the database over the whole
queue, together with the state chips, sorting and paging; the state counts follow it. A port is a substring too, so `443`
also finds `4430`.

**Field filters** in Search, like Sycope's filter chips: `clientIp=10.88.*` (`*` is a wildcard), `serverIp=10.0.0.0/8`
(a network, IPv4 or IPv6), `serverPort=443`, `protocol=tcp`, `state=done`, `severity=high`, `profile=...`,
`alertName="a phrase"`, `alertId=...`; `a,b` means either value (not for names). They show as chips next to the search
box: a click opens the editor (field, value, and the most frequent values of the current view with their share, ticked
values are combined with "or"), × removes a chip, + adds one. Clicking a value in the table (an IP, port, protocol,
state, severity or profile) adds it too. The row menu ⋮ has download, status page,
JSON, **Open in Raw Data** (Sycope's Raw Data view of the flow over the job's window, needs `SR_SYCOPE_URL`), copy link
and copy BPF; Action has **Download PCAPs (zip)** for the ticked or all matching finished jobs (up to 500 files, 4 GiB).
The row details show the PCAP's content (packets, first and last packet).

**Time range** (`?t=`, like Sycope's range picker, in the top bar): the histogram above the table counts the matching jobs by alert
time over the whole queue. Pick a preset (15m, 1h, 6h, 24h, 7d, 30d, all), shift the range with the arrows at the
sides, widen it with the minus button, or drag over the bars (or click one) to zoom in; an absolute range is
`t=<from>-<to>` in epoch seconds. The range filters the table, the state counts and "select all matching". Column
order (drag a heading onto another) and widths (drag a heading's right edge, double-click to reset) are kept in the
browser and in saved views.

**Sorting and the order jobs run in.** Click a heading to sort (`?sort=alert|severity|state|client_ip|server_ip|server_port|protocol|attempts|alert_time|due|updated|profile|persistent|pcap`
and `&dir=asc|desc`; a fixed whitelist). The default is alert time, newest first; the `queued` filter
defaults to due time ascending, i.e. the next job to run first. A job is **due** at its window end plus one
n2disk file (`SR_CHUNK_SECONDS`, 300 s) plus a margin, about six minutes after the alert, and jobs run in due
order, not in the order their webhooks arrived. The *Updated* column (arrival for a queued job, completion for
a finished one) is a different clock, which is why sorting by it can look out of order.

**Times** are shown in the viewer's time zone (a small script; UTC without JavaScript). The extraction window
bounds stay in *server time* (the container's `TZ`, which must match n2disk's host).

**Auto refresh** works like Sycope's: next to *Refresh* a chevron opens a switch, a number and Second(s)/Minute(s);
it reloads on a full interval boundary and is remembered per browser. On the queue it is **off** until switched on
(the panel offers 30 s); a pending alert's status page refreshes every 15 s. It waits while rows are ticked, the
re-extract dialog or a menu is open or a field has focus, and expanded rows stay expanded (and the scroll position
kept) across the reload. The profiles and configuration pages have no auto refresh, only the reload button.

**Editing the queue is off by default** (`SR_QUEUE_EDIT=false`; the controls are not rendered and the endpoints
answer 403). With `SR_QUEUE_EDIT=true`:
- **Persistent** star on a row (stored in `jobs.persistent`), also a filter next to `done`, `miss`, `failed`,
  `queued`, `running`. A persistent job keeps its row (skipped by bulk removal and by pruning the history) and
  its PCAP: the retention sweep (`SR_RETENTION_*`) never deletes it. Persistent files still count toward
  `SR_RETENTION_MAX_TOTAL_BYTES`, so with enough of them the cap stays exceeded (logged). If the worker cannot
  read the list of persistent jobs from the database, it skips the sweep.
- **Bulk actions** in the Action menu (Cancel, Retry, Mark/Unmark persistent, Delete) work on the ticked rows or, with
  "Select all N jobs matching the current filter", on every job of the current chip and Search. Cancel and Retry only
  touch jobs they can act on. Delete asks for confirmation, removes only job rows and events from SQLite, **never
  PCAP files** (evidence), and skips running and persistent jobs.
- **Re-extract…** (button next to Retry, row menu ⋮, or Action for the ticked rows with a wider window only): a new
  job for the same alert with the window moved (up to 3600 s a side) and, for one job, a new filter from addresses or
  networks (source, destination or either), ports and protocol. A preview shows the window, the filter and the new
  file (`<name>_r2.pcap`, or the next free `_rN`; a name whose file is still on disk is skipped) before anything is queued; the old file stays and both can be downloaded
  (`?download=1&job=<file>`).
- **Cancel** queued jobs (at once) and running ones (the worker kills npcapextract); **Retry** miss, failed and
  cancelled jobs with fresh attempts; **Pause/Resume** the worker on the System page (no new job starts while
  paused, running ones finish). Each action is recorded in the job history and the log with the client IP.

Requests that change state, and the debug bundle, are refused when they come from another site
(`Sec-Fetch-Site` must be same-origin and an `Origin` header must name this host, `X-Forwarded-Host`,
`SR_DOWNLOAD_URL_BASE` or `SR_PUBLIC_HOST`): a browser would otherwise send the operator's Basic-auth
credentials along.

**Downloading PCAPs from the list**: every finished job has a green `PCAP` link with the size
(`<alertId>?download=1`, an attachment); a job whose file is gone shows `deleted`. Behind Passthrough
(`SR_DOWNLOAD_URL_BASE` set) the pages carry a `<base href>` so links stay on the Passthrough address.
Non-browsers still get the JSON usage help at `/`, and `GET /queue` returns JSON with `counts`, `jobs`
(including `persistent`, `pcap_bytes`), `page`, `pages`, `total`, `sort` and `dir`. The table needs
the job database (it is always on; if it cannot be opened the web stays up and `/healthz` answers 503).

### System, Profiles and Configuration pages

The **Menu** (top right of every page) leads to separate pages:

- **System status** (`/system`): version, time zone, uptime of both processes, last webhook, a Workers table (heartbeat, slot, current job); every self-check grouped by
  module with its status; system information (version, time zone, CPU, memory), uptime and resources (host memory,
  CPU load, disk use) and a **Disk drives** table (used, total and free space of the rolling buffer, alert PCAP and
  state volumes, one row per filesystem); capture and storage (how many minutes of capture the rolling buffer holds
  against what the longest profile needs, alert PCAPs, jobs database); queue counts and outcomes; warnings; the debug
  log bundle (System logs).
- **Profiles** (`/profiles`): two views of the same profiles, with an (i) on each column and a search by name.
  *What gets recorded*: the BPF filter each one builds (`<client>`, `<server>`, `<port>`, `<protocol>` for the
  alert's values, or none), the window ("6 min before, 30 s after") and tags (no pcap, broader, from alerts,
  check). *Sycope settings*: throttling in words ("1 alert per 1 h for each server"), how often Sycope checks it,
  macros, active; none of it changes what is recorded. The search box (as on the queue) filters both views; download the active `profiles.json`; **upload** a candidate, which is validated (structure,
  types, unique ids, ranges, a real filter build per profile), diffed against the active profiles and only then
  applied (atomic, the previous one kept, `Remove uploaded profiles` goes back to the mounted file);
  **Rebuild from Sycope** reads alert definitions and macros through Sycope's API and stages the result for the
  same review (needs `SR_SYCOPE_URL/_USER/_PASSWORD`, a read-only account); **Reload profiles from file**.
  Nothing is applied without confirmation. Needs `SR_QUEUE_EDIT=true`. The same read also refreshes the alert
  descriptions shown (collapsed) on the queue rows and alert pages; they are display-only and are not part of the profiles.
- **Configuration** (`/configuration`): every setting with an (i) and a search box, its default and where the value comes from
  (environment, uploaded, default). With `SR_CONFIG_PASSWORD` set you can download the configuration as JSON,
  edit it and upload it: the upload is validated by building real settings from it and diffed first, then applied
  as an override stored in the state directory (only keys that differ from the environment) and the service
  reloads gracefully. Without the password both actions are disabled; secrets are masked on screen and are only
  in the downloaded file. `state_dir`, the password itself, `npcapextract_path`, `npcapextract_user`, `timeline_dir`, `output_dir`, the
  retention settings (`retention_max_age_days`, `retention_max_total_bytes`, `retention_interval_seconds`),
  `min_free_bytes` and `probe_url` (the root worker acts on them), and `public_host`, `download_prefix` and
  `worker_stop_grace_seconds` (Caddy and supervisord read them only at container start) cannot be changed this way
  (environment only; such a value in an old `config.override.json` is ignored with a warning: set it in `.env`).
  Numeric settings have ranges, the same for `.env` and an upload: an upload outside one is refused, an `.env` value
  outside one is used as the nearest valid value with a warning (`settings` check).
- **Download debug logs** (`SR_DEBUG_BUNDLE=true`, `GET /logs`): a zip with what the api container sees: recent logs of
  both processes (`web.log`, `worker.log`; every npcapextract failure with its output), the job table with history, self-checks, masked settings, disk and
  rolling-capture summary (as the worker last reported it). No host journal, no PCAP content, credentials redacted.

Behind Sycope Passthrough these pages post their forms as JSON: the Passthrough answers HTTP 502 to an
`application/x-www-form-urlencoded` body (JSON, text and an empty body pass), so a script sends them and follows the
redirect. Direct access without JavaScript still works with plain form posts.

Old links of the form `/downloads/<file>.pcap` keep working (Caddy serves the file,
and a 404 there is explained by `/status/<file>`).

**Sycope Passthrough** (`.../passthrough/recorder/<alertId>` and `.../recorder/` for the
queue): the entry's access rules must allow `GET` for these paths and `POST` for the webhook and the pages' actions.
All our paths except `/healthz/deep` are one segment of `[A-Za-z0-9_-]` (the file download is `?download=1`, the profiles file is
`profiles-file`), so suggested rules are `GET ^/downloads/.*`, `GET ^/([A-Za-z0-9_-]+)?/?$` and `POST ^/.*`
(`/healthz/deep` has two segments and is not allowed by them).
Reserved names that are never alert ids: `healthz`, `stats`, `status`, `queue`, `downloads`, `extract`,
`delete`, `persistent`, `logs`, `system`, `profiles`, `configuration`, `reload-profiles`, `profiles-file`,
`profiles-upload`, `profiles-apply`, `profiles-revert`, `profiles-sync`, `configuration-download`,
`configuration-upload`, `configuration-apply`, `configuration-revert`, `queue-cancel`, `queue-retry`, `queue-persistent`, `worker-pause`,
`queue-reextract`, `queue-zip`, `queue-values`.

### What `/extract` returns

HTTP 200 for an extraction outcome, except the two marked below; Sycope reads the body (the contract of the
earlier versions).
The header `X-Outcome` carries the precise result (new since the first version):

| Body | `X-Outcome` | Meaning |
|---|---|---|
| `https://<base>/<alertId>` | `queued` / `exists` | URL (the file appears when the job runs) |
| `NO BPF FILTER` | `no_bpf` | Alert lacks usable (valid) IP fields for the chosen filter mode |
| `ERROR: low disk space` | `disk_low` | below `SR_MIN_FREE_BYTES` on the output filesystem |
| `Queue full` (HTTP 429, `Retry-After: 60`) | `queue_full` | more than `SR_QUEUE_MAX` jobs pending |
| `ERROR: alert id conflict` | `conflict` | The alert's link or file name already belongs to another alert id; nothing is queued |

`miss`, `failed` and `timeout` are outcomes of the *job* (shown on the status page and counted in `/stats`), not
answers to the webhook: the worker runs the extraction later. Non-200: 400/411/413 bad request, 429 (queue full), 500.
The code never returns 401: a 401 you see is Caddy's Basic auth.

A value in the alert that cannot be used counts as absent; it does not make the webhook fail. That holds for an
address that is not a plain IPv4 or IPv6 address (an IPv6 scope id such as `fe80::1%eth0` included), a port outside
1 to 65535, a protocol other than tcp, udp or icmp (by name or number, `"6"` as a string too) and a `definitionId`
that is a list or an object. The alert time is read from `unixTimestamp`, `timestamp_unix`, `time` or a numeric
`timestamp` (seconds, or milli-, micro- or nanoseconds, told apart by size), then from a `timestamp` string in
Sycope's `dd.mm.yy HH:MM:SS` form. A time that is not a finite number, not after 1970 or more than a day ahead is
ignored; an alert without a usable time is stamped with the time of arrival, so a redelivery of it makes a new job.

### Endpoints

| Path | Auth | Purpose |
|---|---|---|
| `POST /extract` (any POST path) | Basic | Sycope webhook |
| `GET /<alertId>` | Basic | Status page (HTML/JSON); `?download=1` = the PCAP |
| `GET /` , `GET /queue` | Basic | Queue: all jobs (HTML for browsers; JSON with page/pages/total/sort/dir) |
| `GET /downloads/<file>` | Basic (+ `ALLOWED_IPS`) | PCAP, served by Caddy |
| `GET /system`, `/profiles`, `/configuration` | Basic | Status, profiles and configuration pages (JSON for non-browsers) |
| `GET /profiles-file` | Basic | The active profiles as a `profiles.json` to edit (format 2: field help and the editable fields; the descriptive ones stay in the info file) |
| `GET /logs` | Basic + `SR_DEBUG_BUNDLE` | Debug bundle (zip) |
| `POST /delete`, `POST /persistent` | Basic + `SR_QUEUE_EDIT` | Bulk delete of job rows (never PCAPs), persistent flag |
| `POST /queue-cancel`, `/queue-retry`, `/queue-persistent`, `/worker-pause` | Basic + `SR_QUEUE_EDIT` | Cancel jobs, retry miss/failed/cancelled jobs, pause or resume the worker |
| `POST /queue-reextract` | Basic + `SR_QUEUE_EDIT` | A new job with another window or filter for an alert (`preview=1` only answers what would run) |
| `POST /queue-zip` | Basic | The selected finished PCAPs as one zip |
| `GET /queue-values?field=` | Basic | The most frequent values of a filter field in the current view (filter editor) |
| `POST /profiles-upload`, `/profiles-apply`, `/profiles-revert`, `/profiles-sync`, `/reload-profiles` | Basic + `SR_QUEUE_EDIT` | Check, apply, revert, rebuild from Sycope, reload profiles |
| `POST /configuration-download`, `/-upload`, `/-apply`, `/-revert` | Basic + `SR_CONFIG_PASSWORD` | Configuration file download/upload with review |
| `GET /healthz` | none | Shallow liveness (reports whether the dirs exist; 503 only when the job database does not open); used by Docker's healthcheck |
| `GET /healthz/deep` | Basic | All self-checks; HTTP 503 if any FAIL |
| `GET /stats` | Basic | Persistent outcome counters (`since`), queue depth, `worker`, `uptime` of both processes, last check results, free disk |
| `GET /status/<file>` | Basic | Legacy: state of one `/downloads/<file>` (Caddy's 404 fallback) |

Besides the login, Caddy admits a client by address: `ALLOWED_IPS` for `/downloads/*`, `ALLOWED_EXTRACT_IPS` for
the webhook (any POST that is not one of the pages' actions), `ALLOWED_UI_IPS` for everything else; `/healthz` is open (README_DEPLOY
section 6). The address is checked first: outside the allowlist the answer is 403, with or without the login.

## Job history

Every state change of a job is recorded in SQLite (`job_events`) and shown on the status pages
(queued, redelivered, running, retry with the reason, done with size, miss, failed): see the
history block in the expanded rows and on the single-alert page. Finished job rows and events older than
`SR_JOB_HISTORY_DAYS` (30) are pruned (except those of persistent jobs); PCAP files are never touched by that. A pruned job's PCAP is still offered by
its link, and a redelivered webhook for it answers `exists` without extracting over it.

Not done on purpose: writing the history into Sycope. The built-in `restAudit` index cannot be
written from outside (`index/inject` answers `Index name not found`), and a custom index with its
own collector/field was tried and removed again. Sycope shows the
answer to the webhook (the link) in `restAudit`; the history lives on the recorder's pages.

## Operating it

```bash
docker compose exec api python -m sycope_recorder doctor        # human-readable
docker compose exec api python -m sycope_recorder doctor --json
curl -sk -u user:pass https://HOST/healthz/deep                  # same checks over HTTP
curl -sk -u user:pass https://HOST/stats
```

The self-checks (`src/sycope_recorder/checks.py`) probe the seams that failed at
the first customer:

| Check | FAIL / WARN when |
|---|---|
| `rolling_fresh` | no file in `rolling/`, or newest file older than `SR_ROLLING_STALE_SECONDS` (900): n2disk is not writing (licence, capture interface `NO-CARRIER`, wrong path) |
| `timezone` | WARN: container TZ disagrees with the host's `YYYY/MM/DD/HH` directory names (extraction windows would be shifted). Detect-only; fix by setting `TZ` |
| `npcapextract` | binary missing or does not run |
| `output_dir` | not writable, or free space below `SR_MIN_FREE_BYTES` (FAIL) / 2x that (WARN) |
| `alerts_visible_to_caddy` | Caddy cannot read a file the api just wrote: the two containers do not share the `alerts` volume (downloads would be 404) |
| `state_dir` | job database directory not writable |
| `state_dir_local` | FAIL: the state directory is on a network filesystem (NFS, CIFS/SMB, sshfs, GlusterFS, Ceph, 9p per `/proc/mounts`); the job database needs a local one |
| `worker` | FAIL: no heartbeat from the worker (never started, crashed, waiting for `worker.lock`, a slot stuck in one step); WARN: paused by an operator |
| `profiles` | WARN: `SR_PROFILES_FILE` (or an uploaded profiles file) is missing, unreadable or empty: alerts use the default window and filter |
| `settings` | WARN: this process replaced a setting outside its range (`.env` or an older uploaded configuration) by the nearest valid value, or ignored an environment-only setting in `config.override.json`; the detail names each one |
| `checks` | WARN: no self-check results in the database yet (the worker writes them); only in `/healthz/deep`, `/stats`, the System page and the debug bundle, not in `doctor` |

A background watchdog runs the same checks every `SR_WATCHDOG_INTERVAL_SECONDS`
and logs only on state changes, e.g. `CHECK rolling_fresh: FAIL - newest file
1900s old ...`. Grep the api log for `CHECK ` to see when something broke.
`SR_SILENCE_WARN_HOURS=N` additionally warns when no webhook arrived for N hours.

Log lines worth knowing: `SUCCESS`, `MISS`, `NO BPF FILTER`, `LOW DISK`,
`job ... attempt n/m failed`, `job ... gave up`, `CHECK ...`.

## Configuration

App settings are `SR_*` env vars (full list with defaults in
`src/sycope_recorder/config.py`); compose passes all of them from `.env` except the
container paths, `SR_PROBE_URL` and `SR_NPCAPEXTRACT_PATH`, which it fixes. See `README_DEPLOY.md`
step 6 for the `.env` table. Auth, TLS and IP allowlists live
in Caddy (`caddy/Caddyfile`), not in the app. Things that matter:

- `SR_NPCAPEXTRACT_USER` (`npcapextract -u`, default `root`). Set to empty, npcapextract drops
  to `nobody` and cannot write to `alerts/` (`Permission denied`).
- `TZ` must equal the n2disk host's timezone (both default UTC).
- `SR_RETENTION_MAX_AGE_DAYS=0`: PCAPs are evidence and are **not** deleted
  automatically. Protection against a full disk is the `SR_MIN_FREE_BYTES` guard
  (5 GiB), which refuses new extractions loudly. Set an age/size cap if you want
  automatic deletion. The PCAP of a persistent job (queue star) is never deleted by it.
- `SR_CHUNK_SECONDS` must equal n2disk's `--max-file-duration` (300): a job waits for window end + chunk +
  margin, because data newer than the last closed file is invisible to npcapextract.
- `SR_EXPORTER_LAG_SECONDS` (default 300) is a per-site value: how late the exporter reports flows. Too small
  and alerts with late flows lose their first packets; the page warns and re-extracts wider.
- The rolling buffer must hold at least the longest profile range + lag + one file (3600 s needs about 71
  minutes). It is limited by size (n2disk `--disk-limit`), so the minutes it holds shrink as traffic grows: the
  System page shows it.
- `api` and `caddy` must share the same `alerts` volume (see Troubleshooting 404).
- gunicorn must stay at **1 worker** (the profile book is in the web's memory); extractions run in the separate
  worker process, never in gunicorn.
- Alert IPs are validated as literal IPv4/IPv6 before they reach the BPF filter;
  anything else counts as absent (prevents widening the capture filter).

New settings since the first customer deployment (all optional, defaults in `config.py`):
`SR_PROFILES_FILE`, `SR_EXPORTER_LAG_SECONDS`, `SR_WINDOW_MARGIN_SECONDS`, `SR_WINDOW_MAX_LAG_SECONDS`,
`SR_WINDOW_WARN_SECONDS`, `SR_QUIET_WAIT_SECONDS`, `SR_QUIET_POLL_SECONDS`, `SR_QUEUE_EDIT`, `SR_DEBUG_BUNDLE`,
`SR_WORKER_STOP_GRACE_SECONDS`, `SR_WORKER_HEARTBEAT_SECONDS`, `SR_WORKER_STALE_SECONDS`, `SR_SYCOPE_URL`, `SR_SYCOPE_USER`, `SR_SYCOPE_PASSWORD`, `SR_SYCOPE_VERIFY_TLS`,
`SR_CONFIG_PASSWORD`. The Configuration page documents every setting with an (i).

Basic-auth hash in `.env`: wrap it in **single quotes**
(`BASIC_AUTH_HASH='$2a$10$...'`) or double every `$`. The Caddy container refuses
to start with a clear `FATAL` message if the hash is malformed.

## Quickstart (Docker)

```bash
cat > .env <<'EOF'
SR_PUBLIC_HOST=recorder.example.com
BASIC_AUTH_USER=sycope
BASIC_AUTH_HASH='<output of: docker run --rm caddy:2 caddy hash-password --plaintext "pw">'
# TZ=Europe/Warsaw          # only if the n2disk host is not UTC
# ALLOWED_IPS=10.0.0.0/8    # who may fetch the legacy /downloads/* file links
# ALLOWED_EXTRACT_IPS=...   # who may call the webhook, any POST (Sycope's address)
# ALLOWED_UI_IPS=...        # pages, API, ?download=1 (default: same as ALLOWED_EXTRACT_IPS; add Sycope for the Passthrough)
EOF
docker compose up -d --build
docker compose exec api python -m sycope_recorder doctor
```

This is `compose.yaml` alone: a demo without a capture. The image has no `npcapextract` and `rolling` is an empty
Docker volume, so `doctor` reports `rolling_fresh` FAIL (no files under the rolling directory; `SR_ROLLING_CHECK=false`
skips it) and `npcapextract` FAIL (not found on PATH), and every job ends `failed`. The pages, the webhook and the
queue work. On a host where n2disk records, add `compose.ntop.yaml` (the image gets ntop's `npcapextract`, and
`rolling`/`alerts` are bound to `SR_ROLLING_DIR`/`SR_ALERTS_DIR`): `docker compose -f compose.yaml -f compose.ntop.yaml
up -d --build`, or let the installer do it (`README_DEPLOY.md` section 0 and its note on compose files at the top).

Production deployment (real `rolling` path, certificates, bare IP): `README_DEPLOY.md`.
Point Sycope's webhook action at `https://$SR_PUBLIC_HOST/extract?filter=full&before=360&after=360`
with the Basic-auth credential.

## The recorder (n2disk)

n2disk is not containerized; it runs on the host. Templates: `docs/reference/`.
The systemd unit caps restarts (`StartLimitBurst=5` per 10 min): an invalid
licence otherwise flaps forever (1.5M restarts were seen). After fixing the
cause run `systemctl reset-failed n2disk && systemctl start n2disk`.

## Installing and checking

`tools/install/` is the interactive installer (`README_DEPLOY.md` section 0). After a deployment run
`docker compose exec api python -m sycope_recorder doctor`. Pages that post to Sycope Passthrough must be checked
through it, not only directly (see the 502 note above). The release was verified end to end in a lab (one real alert
per definition, a coverage matrix of all 69 profiles, queue waves up to 2000, a capture rate sweep and a six-hour soak).

Development checks: run `tools/check.sh` before pushing (lint, tests, shell syntax; `--all` adds the Docker tests
against the real Caddyfile and the compose files). There is no automatic CI, by decision; see `tests/README.md`.

Code map (`src/sycope_recorder/`): `alert.py` parse + validate alert JSON,
`bpf.py` filter, `extraction.py` plan/execute npcapextract and classify,
`store.py` the SQLite job database (all SQL), `jobs.py` one job from claim to final state, `worker.py` the worker
process, `procs.py` process helpers, `pages.py` HTML views, `checks.py` self-checks,
`stats.py` counters,
`retention.py` optional cleanup, `api.py` routes + background tasks,
`config.py` settings, `__main__.py` the `doctor` CLI. Profiles: `profiles.py` (derive filter and window),
`profile_store.py` (validate, diff, stage, apply an uploaded file), `sycope_import.py` (read definitions and
macros from Sycope). Operations pages: `system.py` (data), `config_store.py` and `config_help.py` (configuration
upload and the (i) texts), `bundle.py` (debug zip).
