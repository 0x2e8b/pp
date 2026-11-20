#!/bin/bash
# Duplicate / loop / broadcast-storm finder on a capture NIC (mirror/SPAN/TAP).
# usage: bash dup.sh <iface|file.pcap> [packets]   e.g. bash dup.sh eno2np1 200000
# The same packet seen N times:
#   SAME-TTL  identical copies          -> mirror duplication (SPAN on several ports/VLANs, rx+tx) or an L2 loop
#   ROUTED    2 copies, TTL differs by 1 -> mirror sees it before and after one router hop (SPAN of both VLANs)
#   LOOP      3+ different TTLs falling -> L3 routing loop (goes around until TTL runs out)
#   L2-SAME   non-IP (ARP...) copies    -> mirror duplication or an L2 loop / broadcast storm
set -u
IF=${1:?iface}; N=${2:-100000}; D=/tmp/dup.$$; mkdir -p $D
if [ -f "$IF" ]; then cp "$IF" $D/s.pcap
else echo "capturing $N packets on $IF (max 60 s) ..."; timeout 60 tcpdump -nni "$IF" -c "$N" -w $D/s.pcap 2>/dev/null; fi
tcpdump -nn -e -v -r $D/s.pcap 2>/dev/null |
  awk '/^[0-9][0-9]:/{if(h!="")print h; h=$0; next}{h=h" "$0} END{if(h!="")print h}' > $D/s.txt
TOTAL=$(wc -l < $D/s.txt)
awk -v total="$TOTAL" '
{
  line=$0
  ttl="-"; if (match(line, /(ttl|hlim) [0-9]+/)) { split(substr(line, RSTART, RLENGTH), q, " "); ttl=q[2] }
  vl="-";  if (match(line, /vlan [0-9]+/)) vl=substr(line, RSTART+5, RLENGTH-5)
  smac=""; dmac=""
  if (match(line, /[0-9a-f:]{17} > [0-9a-f:]{17}/)) { split(substr(line, RSTART, RLENGTH), mm, " > "); smac=mm[1]; dmac=mm[2] }
  pair=""
  if (match(line, /[0-9a-f.:]+ > [0-9a-f.:]+: /) && index(substr(line,RSTART,RLENGTH), ".") ) pair=substr(line, RSTART, RLENGTH-2)
  if (line ~ /ethertype ARP/ && match(line, /(Request who-has|Reply) [0-9.]+( is-at [0-9a-f:]+)?( tell [0-9.]+)?/)) pair="ARP " substr(line, RSTART, RLENGTH)
  if (pair=="") pair=smac " > " dmac
  # broadcast / multicast share and top senders
  if (dmac=="ff:ff:ff:ff:ff:ff") { bc++; bsrc[smac]++ }
  else if (substr(dmac,2,1) ~ /[13579bdf]/) mc++
  k=line
  sub(/^[0-9:.]+ /, "", k)                                  # time
  sub(/[0-9a-f:]{17} > [0-9a-f:]{17}, /, "", k)             # MACs (change after a router hop)
  gsub(/ethertype 802\.1Q(-QinQ)? \(0x[0-9a-f]+\), /, "", k) # VLAN tag ...
  gsub(/vlan [0-9]+, p [0-9]+, /, "", k)                    # ... and id (copies from several VLANs)
  sub(/length [0-9]+: /, "", k)                             # frame length (+4 with a tag)
  gsub(/(ttl|hlim) [0-9]+, /, "", k)                        # TTL / hop limit
  gsub(/, cksum 0x[0-9a-f]+[^)]*\)/, ")", k)                # IP checksum changes with TTL
  c[k]++; t[k]=t[k] " " ttl; p[k]=pair
  if (index(v[k], " " vl " ")==0) v[k]=v[k] " " vl " "
}
END {
  dup=0
  for (k in c) if (c[k] > 1) {
    dup += c[k]-1
    n=split(t[k], a, " "); delete u; nu=0; mn=999; mx=-1
    for (i=1;i<=n;i++) { if (!(a[i] in u)) { u[a[i]]=1; nu++ } if (a[i]!="-") { if (a[i]+0<mn) mn=a[i]+0; if (a[i]+0>mx) mx=a[i]+0 } }
    if (a[1]=="-") kind="L2-SAME"
    else if (nu==1) kind="SAME-TTL"
    else if (nu==2 && mx-mn==1) kind="ROUTED"
    else kind="LOOP"
    kc[kind]++
    hosts[p[k]] += c[k]-1; kinds[p[k]]=kind; vls[p[k]]=v[k]
    if (shown++ < 15) { vv=v[k]; gsub(/  +/, ",", vv); gsub(/^ | $/, "", vv)
      printf "%4dx %-8s ttl:%s  vlan:%s  %s\n", c[k], kind, substr(t[k],1,36), vv, p[k] }
  }
  printf "\npackets %d, extra copies %d (%.1f%%)\n", total, dup, total?100*dup/total:0
  printf "duplicated packets: SAME-TTL %d, ROUTED %d, LOOP %d, L2-SAME %d\n", kc["SAME-TTL"], kc["ROUTED"], kc["LOOP"], kc["L2-SAME"]
  printf "broadcast %d (%.1f%%), multicast %d (%.1f%%)\n", bc, total?100*bc/total:0, mc, total?100*mc/total:0
  print "\ntop pairs by extra copies (copies, kind, vlans, src > dst):"
  for (h in hosts) { vv=vls[h]; gsub(/  +/, ",", vv); gsub(/^ | $/, "", vv)
    printf "%8d  %-8s %-10s %s\n", hosts[h], kinds[h], vv, h | "sort -rn | head -20" }
  close("sort -rn | head -20")
  print "\ntop broadcast senders (src MAC):"
  for (s in bsrc) printf "%8d  %s\n", bsrc[s], s | "sort -rn | head -10"
}' $D/s.txt
echo; echo "files: $D/s.pcap  $D/s.txt   details: tcpdump -nn -e -v -r $D/s.pcap host X"
