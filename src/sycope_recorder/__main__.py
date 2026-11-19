"""`python -m sycope_recorder doctor [--json]` runs the self-checks once; `... worker` runs the worker.

Typical use on a deployed host:

    docker compose exec api python -m sycope_recorder doctor

Exit status of doctor is 1 if any check FAILs (warnings do not fail). Both read the same SR_*
environment as the service. umask 002: files this creates in the state directory (the database's
-wal/-shm when doctor opens it as root) stay writable for the web (group sr, setgid directory).
"""

from __future__ import annotations

import json
import os
import sys

from sycope_recorder import checks
from sycope_recorder.config import get_settings

_MARK = {checks.OK: "OK  ", checks.WARN: "WARN", checks.FAIL: "FAIL"}


def _doctor(argv: list[str]) -> int:
    import time

    from sycope_recorder.store import JobStore, db_path

    settings = get_settings()
    results = checks.run_checks(settings)
    if os.path.exists(db_path(settings.state_dir)):
        store = JobStore(db_path(settings.state_dir))
        try:
            results.append(checks.check_worker(store.workers(), store.paused(), settings, time.time()))
        finally:
            store.close()
    status = checks.overall(results)
    if "--json" in argv:
        print(json.dumps({"status": status, "checks": [
            {"name": c.name, "status": c.status, "detail": c.detail} for c in results]}, indent=2))
    else:
        for c in results:
            print(f"[{_MARK[c.status]}] {c.name}: {c.detail}")
        print(f"\noverall: {status.upper()}")
    return 1 if status == checks.FAIL else 0


def main(argv: list[str]) -> int:
    """Dispatch the subcommand."""
    os.umask(0o002)
    if argv and argv[0] == "doctor":
        return _doctor(argv[1:])
    if argv and argv[0] == "worker":
        from sycope_recorder.worker import main as worker_main

        return worker_main()
    print("usage: python -m sycope_recorder doctor [--json] | worker", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
