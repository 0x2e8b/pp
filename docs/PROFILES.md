# Per-definition extraction profiles

An alert payload says little about what the alert covers: its `timestamp` and the key fields of one
occurrence. What the alert *means* (which flows it aggregates, over how long) is in its
definition. A profile is that knowledge, read once from Sycope, so the recorder can build a BPF
filter and a time window per definition without asking Sycope at alert time.

## What was verified (Sycope demo, 2026-10-09)

- An alert with `timestamp` T covers the flows of the bucket `[T - timeRange, T)`: replaying the
  definition's NQL over that range gave the alert's own `_countSessions` for Cleartext
  Application (1m), Frequent Short-Lived Connections (5m), Horizontal Scan, Unauthorized DNS and
  Botnet via DNS. The ranges `[T, T + range)` and `[T - 2 range, T - range)` gave other numbers.
- A flow's packets can be older than its bucket (buckets follow export time). On the demo 33% of
  flows were 130-180 s early (idle timeout), 1% started over 29 minutes earlier. This is a
  property of the flow exporter, not of the alert: it is the one setting you tune
  (`SR_EXPORTER_LAG_SECONDS`, default 300 since the lag sweep, see below).
- `alertKey` is not the grouping: Unauthorized DNS has `alertKey=[serverIp]` but groups by client,
  server, port and protocol, and the alert row carries all four. Profiles use the grouping.

- The webhook's `unixTimestamp` is the alert's `timestamp` (the bucket end): for 5 real alerts
  from the demo Sycope the recorder's `alertTime` equalled the `alerts` stream `timestamp`
  exactly (minute-aligned). Live webhooks arrived 97-161 s after it (detection delay); manual
  `callAction` replays arrive much later and keep the original `timestamp`.

## Generate

```bash
export SYCOPE_URL=https://sycope SYCOPE_USER=admin SYCOPE_PASS=...
python tools/profiles/gen_profiles.py -o profiles/profiles.json     # JSON for the recorder
python tools/profiles/gen_profiles.py --table                       # to read it
```

Read-only (`GET alert-defs`), stdlib only, active definitions by default (`--all` for
templates), `--macros` reads and expands the `$MACRO$`s. TLS verification is off unless `--verify` is given (Sycope
ships a self-signed certificate). Re-run when definitions change. A committed sample is
`docs/examples/profiles.sycope-demo.json`. Then set
`SR_PROFILES_FILE=/profiles/profiles.json` (compose mounts `./profiles` read-only) and check `doctor` (`profiles`).

## The profiles file (format 2, since 2026-10-16)

`profiles.json` holds only the fields that change an extraction, with a `_help` block on top that says what each
one does:

```json
{
  "_help": {"time_range_s": "CHANGES THE WINDOW. ...", "packet_dims": "CHANGES THE BPF FILTER. ...", "...": "..."},
  "format": 2,
  "profiles": [
    {"def_id": "67137668-...", "rule_id": "Lateral Movement_009", "name": "Rogue RDP Access", "time_range_s": 60,
     "packet_dims": [{"field": "clientIp", "alias": "clientIp"}, {"field": "serverIp", "alias": "serverIp"}],
     "static": {"serverPort": [3389]}}
  ]
}
```

- `def_id` (and `rule_id`) find the profile, `name` is shown next to the job;
- `time_range_s` sets the window, `packet_dims` and `static` the BPF filter.

What the generator read from Sycope besides that (`shape`, `stream`, `active`, `interval_s`, `throttling_min`,
`alert_key`, `macros`, `lists`, `unfilterable`, `notes`) is written to a sidecar next to it,
`profiles.info.json` (`{"definitions": {"<def_id>": {...}}}`). The Profiles page shows it; nothing in it reaches a
filter or a window, and every rebuild rewrites it. Without the sidecar the profiles work the same, the page only
shows less.

The older format (one JSON list, every field in each profile) is still read and accepted on upload; the download
always gives format 2. A descriptive key put into a format 2 profile is ignored with a warning.

## Managing profiles on the Profiles page (v0.3b1)

The Menu leads to `/profiles`, two views of the same rows. *What gets recorded*: the BPF filter of each profile
(`<client>`, `<server>`, `<port>`, `<protocol>` for the alert's values, or none), the window it cuts (time range +
lag before, margin after) and tags from the generator's notes. *Sycope settings* (from the info file): throttling
(`throttling_min` per `alert_key`, in words), interval, macros, active. They decide how often Sycope alerts, not
which packets an alert covers.

With `SR_QUEUE_EDIT=true` three ways to change the active profiles, none of which applies anything unreviewed:

- **Upload** a `profiles.json` (download the active one first, edit, upload). The file is validated: format 2
  object or the older list, unique non-empty `def_id`, `time_range_s` from 1 s to 7 days, `packet_dims` with `field` in clientIp/serverIp/
  serverPort/protocol, `static` only serverPort/protocol with integers, and a real filter build for every profile.
  An empty list or any error cannot be applied. The review lists added, removed and changed profiles, separating
  changes that alter behaviour from changes to labels. **Apply** writes `profiles.override.json` in the state
  directory (the previous one is kept as `.prev`) and its sidecar `profiles.override.info.json` (an upload keeps
  what the page showed; a rebuild brings its own) and reloads without a restart; **Remove uploaded profiles** goes
  back to the mounted file. A corrupt override falls back to the mounted file.
- **Rebuild from Sycope**: the recorder logs in to Sycope (`SR_SYCOPE_URL/_USER/_PASSWORD`, a read-only account;
  no redirect is followed and Sycope's answer is never shown, a failure gives a short reason, see the
  troubleshooting table of `README_DEPLOY.md`),
  reads the definitions, macros and lookups, builds the profiles exactly like `gen_profiles.py` and stages them for
  the same review. Use it after changing a definition or a macro in Sycope. The review lists every macro and
  whether it could be read; an unreadable macro keeps a broader filter.
- **Reload profiles from file** after replacing the mounted file by hand. The mounted file is not validated like
  an upload. When it is loaded, inf and NaN become null (a `time_range_s` then uses the default window), `static`
  and `packet_dims` entries the filter cannot use are dropped (a broader filter), descriptive fields of the wrong
  type are dropped, and a profile whose `def_id` or `rule_id` is a list or object, or whose `packet_dims` is not a
  list, is skipped. Each change is a warning in the log.

The active source (uploaded file or mounted file), its hash and its modification time are shown above the table.

## What a profile does

For an alert whose payload names its definition (`definitionId`, `alertDefId`, `alertDefinitionId`
or `defId`; else a `ruleId`/`alertRuleId` that belongs to exactly one profile):

- **Window:** `[T - timeRange - SR_EXPORTER_LAG_SECONDS, T + SR_WINDOW_MARGIN_SECONDS]`. It ends
  earlier than the default (30 s instead of 360 s after), so the PCAP is ready sooner.
- **Filter:** only the dimensions the definition groups by (`clientIp`, `serverIp`, `serverPort`,
  `protocol`). A dimension not in the grouping is left out even when the payload has it (the alert
  stands for all of that host's traffic); one the payload lacks is left out too (broader, never
  wrong). Constant pre-filters (`serverPort = 53`) fill in when the port is not a grouping key. Only
  conditions every match must satisfy count: nothing is taken from an OR branch (one field's OR chain
  `serverPort = 53 or serverPort = 853` excepted), from a negation (`not`, `!`) or from a term after a
  negation in the same conjunction; a parenthesised AND term counts like any other; a key set twice
  keeps the values both allow (none left: not derived). Field names must be spelt as in Sycope
  (`serverPort`, `protocol`), keywords in any case. `!=` and `not in` give nothing.
  Country, AS, host name, DNS query, JA3 are enrichment and never reach BPF.
- **No filter** for whole-link aggregates (`netflowTotalAggr`: bytes, BPS, PPS, flows): there is
  nothing to filter on, `profile_bpf` builds none and the answer is `NO BPF FILTER`. Alerts built
  from other alerts (Suspicious Host) group by a host, so
  they get `host <client>` over their 15 min range (shape `alerts:clientIp`).
- **Partial filter:** some definitions list values with `join(..., limit=10)` (Horizontal Scan
  lists 10 servers, Botnet via DNS 10 clients). The filter is then the grouping host only
  (`host <client>`), not the truncated list; the generator marks these in `notes`.
- An alert whose definition has no profile, or no profile file at all, behaves exactly as before
  (`before`/`after`/`filter`). With a profile, those query parameters are ignored for that alert.

## Macros (`$DNS$`, `$DMZ$`, ...)

Definitions use macros. `gen_profiles.py --macros` reads each one
(`GET /npm/api/v1/pipeline/macro/<name>`), expands it before the filters are derived (the macro's text replaces `$NAME$` in place, so nothing is
derived after a `not $NAME$`; a macro may
carry a port or protocol: `serverPort = 53`) and writes a YAML report (`--macros-out`). Conditions
on addresses, locations or roles are not packet-level and never enter the BPF filter.

A macro can also test a lookup, e.g. `$DMZ$` =
`any(lookup("hosts & subnets", "trafficPolicy", {"cidr": serverIp}), ["DMZ"])`. The tool then reads
that lookup (`config-element-lookup/<type>/<id>`) and lists in the report which networks satisfy
the macro (`networks`). Lab tooling uses that to pick test addresses that really match, and an
empty list means "this instance does not define it" (alerts using it cannot fire there). Nothing
here stops the run: an unreadable macro (HTTP 403 seen on one instance), a missing lookup or an
unrecognised row format is reported with its reason and the profile notes it.

## Safety nets around the lag (since the sweep)

- Default lag is **300 s**.
- A `miss` is retried (3 attempts, 120 s apart) with a wider window: lag x2, then x4, capped by
  `SR_WINDOW_MAX_LAG_SECONDS` (900). The stored window is unchanged; each widening is a `window`
  event in the job history.
- A finished PCAP whose first packet is within `SR_WINDOW_WARN_SECONDS` (30) of the window start
  triggers a second extraction with twice the look-back (up to the cap); the larger file is kept
  and a `window` event says so. If the cap is reached or nothing more is found, the job keeps
  `warning: ...` as its detail (status page, JSON `warning`). The warning also fires near the
  edge when the PCAP was complete; the cost is one extra extraction, and a wider window may add
  earlier traffic of the same hosts (excess). Treat a persistent warning as "raise the lag".

## Choosing `SR_EXPORTER_LAG_SECONDS` (measured)

Rule: lag >= (exporter inactive timeout) + (longest flow duration you want covered) + a margin.
The lab sweep (2026-10-09, Cleartext) showed full coverage up to a delay of 120 s, 33% at 180 s and none
at 240 s with lag 180: the cliff sits exactly at `lag`. Too small a lag gives a partial PCAP that
looks like a success. Cost of a larger lag: a longer window, so more of the same hosts' unrelated
traffic in the file (excess), not slower extraction (the index makes it cheap).

## Open points

- The lag is global. A per-exporter lag, or a measured one (first/last packet of each PCAP against
  its window), is the next step; so is a miss-rate per profile in `/stats`.
- Long flows (active timeout, minutes to days) start before any reasonable lag. Not covered.
