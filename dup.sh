#!/bin/bash
# Duplicate / loop finder on a capture NIC.
# usage: bash dup.sh <iface> [packets]   e.g. bash dup.sh eno2np1 50000
# Same packet seen N times: same TTL      -> duplicated by mirroring (SPAN on several ports/VLANs) or an L2 loop
#                           TTL decreasing -> L3 routing loop (the packet goes around until TTL runs out)
set -u
IF=${1:?iface}; N=${2:-50000}; D=/tmp/dup.$$; mkdir -p $D
if [ -f "$IF" ]; then cp "$IF" $D/s.pcap   # a pcap file instead of an interface
else echo "capturing $N packets on $IF ..."; timeout 60 tcpdump -nni "$IF" -c "$N" -w $D/s.pcap ip 2>/dev/null; fi
# one line per packet: time, src MAC > dst MAC, ttl, the rest (ids, seq, ...)
tcpdump -nn -e -v -r $D/s.pcap 2>/dev/null |
  awk '/^[0-9][0-9]:/{if(h!="")print h; h=$0; next}{h=h" "$0} END{if(h!="")print h}' > $D/s.txt
TOTAL=$(wc -l < $D/s.txt)
awk -v total="$TOTAL" '
{
  line=$0
  ttl="?"; if (match(line, /ttl [0-9]+/)) ttl=substr(line, RSTART+4, RLENGTH-4)
  mac=""; if (match(line, /[0-9a-f:]{17} > [0-9a-f:]{17}/)) mac=substr(line, RSTART, RLENGTH)
  pair=""; if (match(line, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)? > [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?/)) pair=substr(line, RSTART, RLENGTH)
  k=line
  sub(/^[0-9:.]+ /, "", k)                     # time
  gsub(/[0-9a-f:]{17} > [0-9a-f:]{17}[^,]*, /, "", k)  # MACs (differ after a router hop)
  gsub(/ttl [0-9]+, /, "", k)                  # TTL (drops by 1 per router hop)
  gsub(/, cksum 0x[0-9a-f]+[^)]*\)/, ")", k)   # IP checksum changes with TTL
  c[k]++; t[k]=t[k] " " ttl; m[k]=m[k] "|" mac; p[k]=pair
}
END {
  dup=0; l2=0; l3=0
  for (k in c) if (c[k] > 1) {
    dup += c[k]-1
    split(t[k], a, " "); same=1; for (i in a) if (a[i]!=a[1]) same=0
    if (same) { l2++; kind="SAME-TTL" } else { l3++; kind="TTL-DROPS" }
    hosts[p[k]] += c[k]-1; kinds[p[k]]=kind
    if (shown++ < 15) printf "%3dx %-9s ttl:%s  %s\n", c[k], kind, t[k], p[k] > "/dev/stderr"
  }
  printf "\npackets %d, extra copies %d (%.1f%%); duplicated packets: same TTL %d, TTL dropping %d\n", total, dup, total?100*dup/total:0, l2, l3
  print "\ntop pairs by extra copies (src > dst):"
  for (h in hosts) printf "%8d  %-9s %s\n", hosts[h], kinds[h], h | "sort -rn | head -20"
}' $D/s.txt
echo; echo "files: $D/s.pcap  $D/s.txt  (tcpdump -nn -e -v -r $D/s.pcap host X)"
