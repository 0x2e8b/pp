#!/bin/sh
# Fail fast, with a readable reason, on the two misconfigurations that cost the
# most time in the field, instead of a silent crash loop or a bare 401:
#  1. BASIC_AUTH_HASH mangled by compose's $-interpolation
#  2. SR_TLS pointing at certificate files that are not mounted
set -eu

if ! printf '%s' "${BASIC_AUTH_HASH:-}" | grep -Eq '^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$'; then
	echo "FATAL: BASIC_AUTH_HASH is not a valid bcrypt hash (60 chars, \$2a\$14\$...)." >&2
	echo "       Compose eats unescaped \$ signs. In .env wrap the hash in SINGLE quotes:" >&2
	echo "       BASIC_AUTH_HASH='\$2a\$14\$...'  (or double every \$ as \$\$)." >&2
	exit 1
fi

case "${SR_TLS:-internal}" in
internal) ;;
*)
	for f in ${SR_TLS}; do
		if [ ! -r "$f" ]; then
			echo "FATAL: SR_TLS references $f which is missing/unreadable inside the caddy container." >&2
			echo "       Mount your cert directory at /certs (compose: ./certs:/certs:ro)." >&2
			exit 1
		fi
	done
	;;
esac

exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
