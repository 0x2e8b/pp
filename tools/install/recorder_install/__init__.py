"""Interactive installer for the Sycope Traffic Recorder host.

Layout: ui (prompts and output), state (answers, secrets, per-step results), system (probing and
running commands), sycope (read-only checks of the Sycope instance), steps (one function per
installation step, each both an inspection and, when asked, the change), report, wizard (the
orchestration and the command line).
"""

VERSION = "1"
