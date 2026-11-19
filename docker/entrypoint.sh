#!/bin/sh
# Prepare what the two processes share, then hand over to supervisord.
# The web runs as `sr`, the worker as root. Shared files are group `sr` and group-writable: setgid
# directories plus umask 002 in both programs. Only the state directory, its logs directory and the
# socket directory are touched; never the alerts (PCAP) directory and never recursively.
# The web can write these directories, so root never follows a symlink it finds there: a directory
# that is a link is skipped, so is a file that is a link, and files are changed with `-h`/no-deref.
# The root worker never writes into a directory the web can write: its log goes to
# /var/log/sycope-recorder (root:sr 2750; the web only reads it for the debug bundle). The web's own
# log stays in state/logs. The state directory is NOT sticky (2775): with fs.protected_regular=2 (many kernels) root's open(O_CREAT) of a
# file owned by sr in a sticky directory fails with EACCES, and SQLite and the lock files need exactly
# that. The state files belong to sr anyway (below); the worker never follows links there (O_NOFOLLOW,
# link checks), so a sticky bit would add nothing. Only state/logs is sticky (3775).
# A directory that refuses chown/chmod (NFS root_squash, ...) is a warning, never a stop.
set -u
warn() { echo "entrypoint: $*" >&2; }
STATE="${SR_STATE_DIR:-/var/lib/sycope-recorder}"
mkdir -p "$STATE" "$STATE/logs" /run/api 2>/dev/null || warn "cannot create the state/socket directories"
WORKER_LOG=/var/log/sycope-recorder
mkdir -p "$WORKER_LOG" 2>/dev/null || warn "cannot create $WORKER_LOG"
for d in "$STATE:2775" "$STATE/logs:3775" "/run/api:2775" "$WORKER_LOG:2750"; do
  dir="${d%:*}"; mode="${d##*:}"
  if [ -L "$dir" ]; then
    warn "$dir is a symbolic link: not touching it"
    continue
  fi
  chown root:sr "$dir" || warn "cannot chown $dir"
  chmod "$mode" "$dir" || warn "cannot chmod $dir"
done
# Files left by an earlier start or by `docker compose exec` as root must stay usable by the web.
# Regular files only: a link planted by the web would otherwise make root change its target.
# Top level of the state directory: the web owns these (it replaces them on configuration/profile
# apply); files from a 0.3 volume or from
# `docker compose exec` as root become sr's. logs/: group repair only, root keeps its worker.log.
if [ ! -L "$STATE" ]; then   # also keeps the glob from listing a link's target
  for f in "$STATE"/*; do
    [ -L "$f" ] && { warn "$f is a symbolic link: skipped"; continue; }
    if [ -d "$f" ]; then
      # config.staged/, profiles.staged/ of a 0.3 volume (root-owned): the web stages uploads there.
      # One level down only; logs/ is handled below and keeps its owner.
      [ "$f" = "$STATE/logs" ] && continue
      chown -h sr:sr "$f" || warn "cannot chown $f"
      chmod g+rwx "$f" || warn "cannot chmod $f"
      for g in "$f"/*; do
        [ -L "$g" ] && { warn "$g is a symbolic link: skipped"; continue; }
        [ -f "$g" ] || continue
        chown -h sr:sr "$g" || warn "cannot chown $g"
        # a staged configuration can hold sycope_password: owner only (S-12; config_store.SECRET_MODE)
        [ "$f" = "$STATE/config.staged" ] && { chmod 600 "$g" || warn "cannot chmod $g"; }
      done
      continue
    fi
    [ -f "$f" ] || continue
    chown -h sr:sr "$f" || warn "cannot chown $f"
    case "${f##*/}" in
      # can hold sycope_password (with .prev and a temporary left by a crash): owner only, as the web
      # writes it since S-12; the root worker reads it as root. An older version left it 0664.
      config.override.json|config.override.json.*) chmod 600 "$f" || warn "cannot chmod $f" ;;
      *) chmod g+rw "$f" || warn "cannot chmod $f" ;;
    esac
  done
fi
if [ ! -L "$STATE/logs" ]; then
  for f in "$STATE"/logs/*; do
    [ -L "$f" ] && { warn "$f is a symbolic link: skipped"; continue; }
    [ -f "$f" ] || continue
    chgrp -h sr "$f" || warn "cannot chgrp $f"
    chmod g+rw "$f" || warn "cannot chmod $f"
  done
fi
GRACE="${SR_WORKER_STOP_GRACE_SECONDS:-30}"
case "$GRACE" in ''|*[!0-9]*) GRACE=30 ;; esac
GRACE=$(printf '%s' "$GRACE" | sed 's/^0*//')
# The worker uses the same bounds, 1 to 60 (config.BOUNDS): an .env value outside them is used as the
# nearest one. worker_stop_grace_seconds cannot be uploaded (config.LOCKED), so this stays right
# until the container is recreated with a new .env.
[ -n "$GRACE" ] || GRACE=1
[ "${#GRACE}" -le 2 ] || GRACE=60
[ "$GRACE" -le 60 ] || GRACE=60
SR_WORKER_STOPWAIT=$((GRACE + 15))
export SR_WORKER_STOPWAIT
# `docker compose run api <cmd>`: after the permission setup above, run the command instead of the
# services (as root, umask as the caller's: put `umask 002;` in front when it writes into the state dir).
if [ "$#" -gt 0 ]; then
  exec "$@"
fi
exec supervisord -c /app/docker/supervisord.conf
