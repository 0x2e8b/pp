#!/usr/bin/env bash
# Launcher for the recorder uninstaller (tools/install/uninstall.py). See that file for the options.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 2; }
python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' || {
    echo "python3 $(python3 -V 2>&1 | cut -d" " -f2) is too old: the installer needs 3.8 or newer (Ubuntu 20.04+, Debian 11+)" >&2; exit 2; }
exec python3 "$here/uninstall.py" "$@"
