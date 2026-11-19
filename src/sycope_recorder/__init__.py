"""Sycope Traffic Recorder: alert-triggered PCAP extraction service.

Sycope calls POST /extract with an alert; this package builds a BPF
filter from it, queues the job and answers at once with the alert's link
(its status page; the PCAP itself is that link with ?download=1). The
worker runs npcapextract against the n2disk rolling capture later.
"""

# The release shown on the pages, in /stats and in the debug bundle. pyproject.toml carries the same
# release in PEP 440 form (0.4.0b6).
__version__ = "v0.4b6"
