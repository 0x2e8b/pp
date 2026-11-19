"""One explanation per setting, shown as (i) on the Configuration page.

Each text says what the setting does, its unit and default, and what it affects. A test requires
an entry for every field of Settings, so a new setting cannot ship undocumented.
"""

CONFIG_HELP: dict[str, str] = {
    "public_host": "The host name or IP the recorder is reached at (Caddy's TLS name and the default host in "
                   "returned links). Required. Example: 192.0.2.10 or recorder.example.com. Environment only "
                   "(SR_PUBLIC_HOST), not changeable from this page: Caddy reads it at container start.",
    "download_prefix": "URL path under which finished PCAPs are served (default \"downloads\"). The status page "
                       "link is <base>/<alertId>; the file is <base>/<alertId>?download=1. Environment only "
                       "(SR_DOWNLOAD_PREFIX), not changeable from this page: Caddy serves the files under it and "
                       "reads it at container start.",
    "timeline_dir": "Directory with the rolling n2disk capture that npcapextract reads (default "
                    "/storage/pcaps/rolling). Mounted read-only into the container. Changing it needs a matching mount.",
    "output_dir": "Directory where extracted alert PCAPs are written and served from (default /storage/pcaps/alerts).",
    "default_filter": "Filter used when an alert has no profile: full (client IP, server IP and server port), "
                      "hosts (client and server IP), client, server, or port (server IP and port). "
                      "Alerts WITH a profile ignore it. Default full.",
    "default_before": "Seconds before the alert timestamp to extract when there is no profile (default 360).",
    "default_after": "Seconds after the alert timestamp to extract when there is no profile (default 360).",
    "max_concurrent_extractions": "How many npcapextract runs may be active at once, 1 to 16. 1 = strictly one at a "
                                  "time (default in code; compose sets 4). More is faster for bursts but multiplies "
                                  "disk and CPU load.",
    "extract_timeout_seconds": "Hard limit for one npcapextract run, in seconds (default 300, 10 to 3600). A longer "
                               "run is killed and retried; the worker enforces it, the web does not wait for "
                               "extractions.",
    "download_url_base": "Address used in the link returned to Sycope when it differs from public_host, for example the "
                         "Sycope Passthrough path \"sycope.example/npm/api/v1/passthrough/recorder\" (no https://). "
                         "Empty = public_host. Also the address the pages use for redirects.",
    "npcapextract_path": "Command or path of the npcapextract binary (default \"npcapextract\", found on PATH).",
    "npcapextract_user": "User npcapextract drops to before writing the file (-u). Default root, because the api "
                         "container runs as root; empty uses npcapextract's own default (nobody).",
    "retention_max_age_days": "Delete alert PCAPs older than this many days. 0 = never (default): PCAPs are evidence, "
                              "disk is protected by min_free_bytes instead. The PCAP of a job marked persistent is never "
                              "deleted by this. Environment only (SR_RETENTION_MAX_AGE_DAYS), not changeable "
                              "from this page.",
    "retention_max_total_bytes": "Delete the oldest alert PCAPs when the folder exceeds this many bytes. 0 = no cap "
                                 "(default). Persistent PCAPs count toward the total but are never deleted, so the cap may stay "
                                 "exceeded. Environment only (SR_RETENTION_MAX_TOTAL_BYTES), not changeable from this page.",
    "retention_interval_seconds": "How often the retention sweep runs, in seconds (default 3600). Environment only "
                                  "(SR_RETENTION_INTERVAL_SECONDS), not changeable from this page.",
    "log_level": "Log verbosity: DEBUG, INFO (default), WARNING, ERROR, CRITICAL. The debug bundle contains the "
                 "recent log. gunicorn's own messages keep the level of SR_LOG_LEVEL: it reads it only at container "
                 "start.",
    "log_format": "text (default, readable) or json (one JSON object per line, for log collectors).",
    "state_dir": "Where the job database (jobs.db) and uploaded profiles/configuration live. LOCKED: not changeable "
                 "here, because the uploaded configuration itself is stored in it.",
    "queue_max": "Maximum number of waiting jobs (default 2000). Beyond it a webhook gets HTTP 429 Queue full.",
    "job_max_attempts": "How many times a job is tried before it is marked failed or miss (default 3).",
    "job_retry_delay_seconds": "Seconds between retries (default 120). A miss retry also looks further back "
                               "(see exporter_lag_seconds).",
    "job_history_days": "How long finished job rows stay in the table, in days (default 30, at least 1). The PCAP "
                        "files are not touched by this.",
    "worker_stop_grace_seconds": "When the worker stops or reloads (configuration applied), running extractions may "
                                 "finish for this many seconds; then they are killed and the jobs go back to the queue "
                                 "without using an attempt (default 30, 1 to 60). Environment only "
                                 "(SR_WORKER_STOP_GRACE_SECONDS), not changeable from this page: supervisord's wait "
                                 "for the worker is derived from it at container start.",
    "worker_heartbeat_seconds": "How often the worker writes its heartbeat to the job database (default 5). The "
                                "System page and /healthz/deep read it.",
    "worker_stale_seconds": "Heartbeat age after which the worker is reported dead on the System page, the queue page "
                            "and /healthz/deep (default 60).",
    "chunk_seconds": "Length of one n2disk file (--max-file-duration, default 300). MUST equal the n2disk setting: a job "
                     "waits for window end + chunk_seconds + ready_margin_seconds before it runs, because data newer "
                     "than the last closed file is invisible to npcapextract.",
    "ready_margin_seconds": "Extra seconds to wait after the chunk has closed before extracting (default 30).",
    "profiles_file": "Path of the profiles file inside the container (default empty = no profiles; with compose "
                     "set /profiles/profiles.json). An uploaded profiles file on the Profiles page takes precedence.",
    "exporter_lag_seconds": "How much earlier than its minute bucket a flow's packets can be, in seconds (default 300): "
                            "the exporter's idle/active timeout plus the longest flow to cover. The window starts "
                            "range + lag before the alert. Too small = alerts with late flows lose their first packets "
                            "(a measured cliff at the lag value); too large = bigger PCAPs.",
    "window_margin_seconds": "Seconds added after the alert timestamp (default 30), for clock skew and a timestamp "
                             "taken slightly after the bucket.",
    "window_max_lag_seconds": "The widest lag a retry after a miss may reach, in seconds (default 900). Each retry "
                              "doubles the lag up to this value.",
    "window_warn_seconds": "If the first packet of a PCAP is within this many seconds of the window start (default 30), "
                           "the page warns that the window may have cut the beginning, and the job re-extracts wider.",
    "quiet_wait_seconds": "On a quiet link n2disk closes a file only when the next packet arrives. After this many "
                          "seconds past the due time the job extracts anyway (default 21600 = 6 h).",
    "quiet_poll_seconds": "How often a waiting job checks whether the file with the window end is closed, in seconds "
                          "(default 30).",
    "queue_edit": "false (default): the queue page is read-only. true: row checkboxes, delete, the persistent star, "
                  "cancel, retry, re-extract, pausing the worker and the profile upload/apply/revert/reload/"
                  "rebuild actions are enabled. Requests from other sites are refused.",
    "debug_bundle": "false (default). true: the \"Download debug logs\" menu item and GET /logs (a zip with recent log, "
                    "job table, checks and masked settings).",
    "sycope_url": "Sycope address for \"Rebuild from Sycope\" and the queue's \"Open in Raw Data\" links, e.g. "
                  "https://sycope.example. Empty disables both.",
    "sycope_user": "Sycope account used to read alert definitions and macros. Use a read-only account.",
    "sycope_password": "Password of that account. Secret: masked on every page and in the debug bundle; included in the "
                       "downloaded configuration file (that is why the download needs the configuration password).",
    "sycope_verify_tls": "Verify Sycope's TLS certificate (default true). Sycope ships a self-signed certificate: set "
                         "false, or install a trusted CA.",
    "min_free_bytes": "Extractions are refused when the output filesystem has less free space than this (default "
                      "5 GiB = 5368709120). The disk guard that protects the recorder when retention is off. "
                      "Environment only (SR_MIN_FREE_BYTES), not changeable from this page.",
    "rolling_check": "Check that the rolling capture is fresh (default true). false for hosts without a capture (demo "
                     "with a fake npcapextract): the check then reports OK/skipped.",
    "watchdog_interval_seconds": "How often the background self-check runs, in seconds (default 60).",
    "rolling_stale_seconds": "The newest rolling file older than this (default 900 s) means n2disk is not writing: the "
                             "rolling_fresh check fails.",
    "silence_warn_hours": "Warn when no webhook arrived for this many hours (default 0 = never).",
    "probe_url": "Internal Caddy listener used to prove Caddy serves the same alerts storage as the api (e.g. "
                 "http://caddy:8081). Empty disables that check. Not changeable from this page: compose fixes it.",
    "config_password": "The password that protects downloading and uploading the configuration. LOCKED: set only in the "
                       "environment (SR_CONFIG_PASSWORD), never part of the file.",
}
