#!/bin/bash
# Capture host diagnosis: where the CPU goes and why packets are lost. READ-ONLY, changes nothing.
#   bash diag.sh                 auto-detect capture NICs (n2disk.conf, else promisc without IP)
#   NICS="eno1np0 eno2np1" bash diag.sh
#   S=10 DUP=0 PERF=0 bash diag.sh   sample seconds, skip duplicate check, skip perf
# Prints FINDINGS with a proposed fix at the end; full report in /root/diag/.
set -u
SYS=${SYS:-/sys/class/net}; PROC=${PROC:-/proc}; CPUDIR=${CPUDIR:-/sys/devices/system/cpu}
NODEDIR=${NODEDIR:-/sys/devices/system/node}; N2CONF=${N2CONF:-/etc/n2disk/n2disk.conf}
S=${S:-5}; DUP=${DUP:-1}; PERF=${PERF:-1}; HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-/root/diag}; mkdir -p $OUT; REP=$OUT/diag-$(date +%Y%m%d-%H%M%S).txt
exec > >(tee $REP) 2>&1
have() { command -v $1 >/dev/null 2>&1; }
h()    { echo; echo "=== $*"; }
F=(); fnd() { F+=("$1|$2|$3"); }       # severity (1 crit, 2 warn, 3 info) | finding | fix
pct()  { awk -v a=$1 -v b=$2 'BEGIN{printf "%.1f", (b>0?100*a/b:0)}'; }
expand() { tr , '\n' | while IFS=- read a b; do [ -n "$a" ] && seq $a ${b:-$a}; done; }

# ---------- capture NICs ----------
n2ifs()  { [ -r $N2CONF ] && sed -n 's/^ *-i[= ]*//p' $N2CONF | tr ',' ' '; }
if [ -z "${NICS:-}" ]; then
  NICS=$(n2ifs)
  [ -z "$NICS" ] && for i in $(ls $SYS); do [ -e $SYS/$i/device ] || continue
    (( $(cat $SYS/$i/flags) & 0x100 )) || continue
    have ip && [ -n "$(ip -o -4 addr show dev $i 2>/dev/null)" ] && continue; NICS="$NICS $i"; done
fi
NICS=$(echo $NICS)
[ -z "$NICS" ] && { echo "no capture NIC found: NICS=\"eth1 eth2\" bash diag.sh"; exit 1; }
cnt() { local v=""; have ethtool && v=$(ethtool -S $1 2>/dev/null | awk -v k="$2" '$1==k":"{print $2; exit}')
        [ -z "$v" ] && [ -r $SYS/$1/statistics/$2 ] && v=$(cat $SYS/$1/statistics/$2); echo "${v:-}"; }
node()  { local n; n=$(cat $SYS/$1/device/numa_node 2>/dev/null); echo ${n:--1}; }
cpunode() { local d; d=$(ls -d $CPUDIR/cpu$1/node* 2>/dev/null | head -1); [ -n "$d" ] && echo ${d##*node} || echo -1; }
irqs()  { grep -E "[^a-z0-9]$1([^0-9a-z]|$)" $PROC/interrupts 2>/dev/null | cut -d: -f1 | tr -d ' '; }

# PF_RING rings: file|pid|appl|devices|cluster|packets|lost
rings() { for f in $PROC/net/pf_ring/[0-9]*-*; do [ -r "$f" ] || continue
  awk -v f="${f##*/}" -F: '{k=$1; sub(/^ +| +$/,"",k); v=substr($0,index($0,":")+1); gsub(/^ +| +$/,"",v); a[k]=v}
    END{split(f,p,"-"); printf "%s|%s|%s|%s|%s|%s|%s\n", f, p[1], a["Appl. Name"], a["Bound Device(s)"], (a["Cluster Id"]==""?0:a["Cluster Id"]), a["Tot Packets"]+0, a["Tot Pkt Lost"]+0}' "$f"; done; }
cpustat() { grep -E '^cpu[0-9]+ ' $PROC/stat; }
diskdev() { local s; s=$(findmnt -n -o SOURCE -T "$1" 2>/dev/null); s=$(readlink -f "$s" 2>/dev/null); basename "${s:-?}"; }
ioticks() { awk -v d=$1 '$3==d{print $13}' $PROC/diskstats; }
DIR=$( [ -r $N2CONF ] && sed -n 's/^ *\(-o\|--dump-directory\)[= ]*//p' $N2CONF | head -1 )
DDEV=""; [ -n "$DIR" ] && DDEV=$(diskdev $DIR)

# ---------- sample everything at once ----------
echo "diag $(date '+%F %T')  host $(hostname)  NICs: $NICS  sampling ${S}s (read-only)"
declare -A P0 M0 P1 M1 RP0 RL0 RP1 RL1
for i in $NICS; do P0[$i]=$(cnt $i rx_packets); M0[$i]=$(cnt $i rx_missed_errors); done
ST0=$(cpustat); IN0=$(cat $PROC/interrupts); RG0=$(rings); IO0=$([ -n "$DDEV" ] && ioticks $DDEV)
QS0=$(for i in $NICS; do have ethtool && ethtool -S $i 2>/dev/null | awk -v i=$i -F: '$1~/^ *rx[-_]?(queue_)?[0-9]+[._]packets$/{gsub(/ /,"",$1); gsub(/ /,"",$2); print i, $1, $2}'; done)
sleep $S
for i in $NICS; do P1[$i]=$(cnt $i rx_packets); M1[$i]=$(cnt $i rx_missed_errors); done
ST1=$(cpustat); IN1=$(cat $PROC/interrupts); RG1=$(rings); IO1=$([ -n "$DDEV" ] && ioticks $DDEV)
QS1=$(for i in $NICS; do have ethtool && ethtool -S $i 2>/dev/null | awk -v i=$i -F: '$1~/^ *rx[-_]?(queue_)?[0-9]+[._]packets$/{gsub(/ /,"",$1); gsub(/ /,"",$2); print i, $1, $2}'; done)

# ---------- host / CPU ----------
h "CPU"
NCPU=$(echo "$ST1" | wc -l)
SI=$(paste <(echo "$ST0") <(echo "$ST1") | awk -v n=$NCPU '{ t0=0; for(i=2;i<=11;i++) t0+=$i; t1=0; for(i=13;i<=22;i++) t1+=$i
        d=t1-t0; s=$19-$8; if(d>0){p=100*s/d; if(p>50) b50++; if(p>90) b90++}; ts+=s; tt+=d }
        END{printf "%d %d %.1f %d", b50, b90, tt?100*ts/tt:0, ts}')
read B50 B90 SIP SIJ <<< "$SI"
GOV=$(cat $CPUDIR/cpu*/cpufreq/scaling_governor 2>/dev/null | sort | uniq -c | tr '\n' ' ')
NODES=$(ls -d $NODEDIR/node[0-9]* 2>/dev/null | wc -l)
echo "cpus $NCPU, numa nodes $NODES, load $(cut -d' ' -f1-3 $PROC/loadavg)"
echo "softirq: ${SIP}% of all CPU time, cpus >50% softirq: $B50, >90%: $B90"
echo "governor: ${GOV:-n/a}"
[ $B90 -gt 4 ] && fnd 1 "$B90 CPUs spend >90% in softirq (packet handling in the kernel)" "see the per-packet cost and PF_RING copies below: the work is already spread, it is too expensive per packet"
[ -n "$GOV" ] && echo "$GOV" | grep -qvE '^ *[0-9]+ performance *$' && fnd 2 "CPU governor is not 'performance' ($GOV)" "cpupower frequency-set -g performance  (or set it in BIOS: max performance, C-states limited)"

# ---------- NICs ----------
TOTPPS=0
for i in $NICS; do
  h "NIC $i"
  n=$(node $i); drv=$(have ethtool && ethtool -i $i 2>/dev/null | awk -F': ' '/^driver|^version|^firmware/{printf "%s %s  ", $1, $2}')
  echo "$drv numa_node $n  speed $(cat $SYS/$i/speed 2>/dev/null)  $(cat $SYS/$i/operstate 2>/dev/null)"
  if [ -n "${P0[$i]}" ] && [ -n "${P1[$i]}" ]; then
    dp=$(( P1[$i] - P0[$i] )); dm=0; [ -n "${M0[$i]}" ] && [ -n "${M1[$i]}" ] && dm=$(( M1[$i] - M0[$i] ))
    pps=$(( (dp + dm) / S )); TOTPPS=$(( TOTPPS + pps )); loss=$(pct $dm $((dp+dm)))
    echo "arriving $pps pps, received $(( dp / S )) pps, missed $(( dm / S )) pps  => NIC loss ${loss}%"
    awk -v l=$loss 'BEGIN{exit !(l>1)}' && fnd 1 "$i loses ${loss}% of packets at the NIC (rx_missed: the host does not empty the RX ring fast enough)" "symptom: the causes are the other findings; quick help: bash nic.sh (bigger ring, IRQs on own cores)"
    [ -z "${M0[$i]}" ] && echo "driver has no rx_missed_errors counter: NIC loss unknown"
  fi
  crc=$(cnt $i rx_crc_errors); [ -n "$crc" ] && [ "$crc" -gt 0 ] && echo "rx_crc_errors total $crc (optics/cabling, only if growing)"
  r=$(have ethtool && ethtool -g $i 2>/dev/null | awk '/maximums/{m=1} /Current/{m=0;c=1} /^RX:/{if(m)mx=$2; else if(c)cu=$2} END{print cu" "mx}')
  read rc rm <<< "${r:-x x}"; q=$(have ethtool && ethtool -l $i 2>/dev/null | awk '/Current/{c=1} c&&/^Combined:/{print $2; exit}')
  gro=$(have ethtool && ethtool -k $i 2>/dev/null | awk '$1=="generic-receive-offload:"{print $2}')
  echo "rx ring $rc (max $rm), queues ${q:-?}, gro ${gro:-?}"
  [[ $rc =~ ^[0-9]+$ ]] && [[ $rm =~ ^[0-9]+$ ]] && [ $rc -lt $rm ] && fnd 2 "$i RX ring $rc of max $rm" "bash nic.sh -> apply (link resets for a few seconds)"
  [ "${gro:-}" = on ] && fnd 3 "$i GRO on (useless work for capture)" "bash nic.sh -> apply turns it off"
  # queue balance
  qb=$(paste <(echo "$QS0" | awk -v i=$i '$1==i') <(echo "$QS1" | awk -v i=$i '$1==i') | awk '{d=$6-$3; if(d>0){q[$2]=d; t+=d; n++}} END{m=0; for(k in q) if(q[k]>m){m=q[k]; mk=k}; if(t>0) printf "%d %.0f %s", n, 100*m/t, mk}')
  if [ -n "$qb" ]; then read qn qp qk <<< "$qb"; echo "queues with traffic $qn, busiest $qk ${qp}%"
    [ $qn -ge 2 ] && [ $qp -gt $(( 300 / qn )) ] && [ $qp -gt 25 ] && fnd 2 "$i traffic sits in few queues (busiest $qp% of packets)" "bash nic.sh -> rss (hash UDP on ports); if it stays: the mirror carries a few big flows or a tunnel (GRE/VXLAN/ERSPAN)"
  fi
  # IRQ spread: which CPUs took this NIC's interrupts during the sample
  il=$(irqs $i | tr '\n' ' ')
  if [ -n "$il" ]; then
    sp=$(awk -v L=" $il " -v nc=$NCPU 'FNR==1{f++; next} { k=$1; sub(":","",k); if (index(L," "k" ")==0) next; for(c=0;c<nc;c++) v[f,k,c]=$(c+2) }
          END{ for(c=0;c<nc;c++){ s=0; for(x in v){ split(x,y,SUBSEP); if(y[1]==2 && y[3]==c) s+=v[x]-v[1,y[2],c] } if(s>0) printf "%d ", c } }' <(echo "$IN0") <(echo "$IN1"))
    nsp=$(echo $sp | wc -w); off=0; for c in $sp; do [ "$n" != -1 ] && [ "$(cpunode $c)" != "$n" ] && off=$((off+1)); done
    [ $nsp -eq 0 ] && echo "IRQs: $(echo $il | wc -w), no interrupts during the sample (busy polling or idle)" ||
    echo "IRQs: $(echo $il | wc -w), active on $nsp CPUs$([ $off -gt 0 ] && echo ", $off of them on another NUMA node")"
    [ $off -gt 0 ] && fnd 2 "$i interrupts handled on $off CPUs of another NUMA node than the NIC (node $n)" "bash nic.sh -> apply (IRQs on the NIC's own node)"
  fi
  # RPS / bridge
  rps=$(cat $SYS/$i/queues/rx-*/rps_cpus 2>/dev/null | tr -d ',0\n')
  [ -n "$rps" ] && { echo "RPS on"; fnd 2 "$i has RPS on (packets bounced to other CPUs)" "for f in /sys/class/net/$i/queues/rx-*/rps_cpus; do echo 0 > \$f; done"; }
  if [ -e $SYS/$i/master ]; then m=$(basename $(readlink $SYS/$i/master)); echo "member of $m"
    fnd 1 "$i is in bridge/bond $m: the kernel forwards/processes every mirrored packet" "take $i out of $m (netplan/docker config); a capture NIC must be standalone, no IP"; fi
  have ip && [ -n "$(ip -o -4 addr show dev $i 2>/dev/null)" ] && fnd 3 "$i has an IP address" "a capture NIC should have no IP (no stack processing)"
done
[ $TOTPPS -gt 100000 ] && [ ${SIJ:-0} -gt 0 ] && {
  US=$(awk -v j=$SIJ -v s=$S -v p=$TOTPPS -v hz=$(getconf CLK_TCK 2>/dev/null || echo 100) 'BEGIN{printf "%.2f", (j/hz)*1e6/(p*s)}')
  echo; echo "per-packet kernel cost: ${US} us of softirq CPU per arriving packet ($TOTPPS pps on all capture NICs)"
  awk -v u=$US 'BEGIN{exit !(u>2)}' && fnd 1 "each packet costs ${US} us of kernel CPU (normal non-ZC PF_RING: ~0.3-1 us per consumer)" "the cost is multiplied by PF_RING copies / other sockets / stack processing - see those findings; if all clean: PF_RING ZC + zbalance_ipc"; }

# ---------- PF_RING ----------
h "PF_RING"
if [ -r $PROC/net/pf_ring/info ]; then
  grep -E 'PF_RING Version|Total rings|Ring slots|Slot version|ZC' $PROC/net/pf_ring/info | sed 's/^/  /'
  printf "  %-26s %-8s %-22s %-18s %8s %12s %7s\n" ring pid appl device cluster packets/s lost%
  join -t'|' <(echo "$RG0" | sort) <(echo "$RG1" | sort) | awk -F'|' -v s=$S '{dp=$12-$6; dl=$13-$7; printf "  %-26s %-8s %-22s %-18s %8s %12d %6.1f%%\n", $1, $2, substr($3,1,22), $4, $5, dp/s, ((dp+dl)>0?100*dl/(dp+dl):0)}'
  for i in $NICS; do
    cp=$(echo "$RG1" | awk -F'|' -v i=$i '{n=split($4,d,","); for(k=1;k<=n;k++) if(d[k]==i){ if($5==0) c++; else cl[$5]=1 }} END{for(k in cl) c++; print c+0}')
    apps=$(echo "$RG1" | awk -F'|' -v i=$i '$4~i{print $3}' | sort | uniq -c | awk '{printf "%s x%d  ", $2, $1}')
    echo "  $i: every packet is copied to $cp PF_RING consumer(s): $apps"
    [ $cp -eq 0 ] && fnd 1 "$i: no PF_RING consumer reads it (n2disk/nprobe do not capture this NIC)" "check n2disk.conf -i and the nprobe interfaces; with -i=a,b n2disk must show a ring bound to each NIC"
    [ $cp -gt 2 ] && fnd 1 "$i: every packet is copied $cp times by PF_RING (rings without a common cluster: $apps)" "run the multi-threaded consumer (nprobe) as one PF_RING cluster (--cluster-id) or feed both n2disk and nprobe from zbalance_ipc; target: 1 copy per application"
  done
  # ring loss since start, worst ring per application and device
  echo "$RG1" | awk -F'|' '($6+$7)>0{k=$3"|"$4; l=100*$7/($6+$7); n[k]++; if(l>m[k]) m[k]=l} END{for(k in m) if(m[k]>1) printf "%s|%d|%.1f\n", k, n[k], m[k]}' |
  while IFS='|' read ap dev nr lp; do
    case $ap in
      n2disk*) fx="pin n2disk reader/writer/indexer to free cores of the NIC's node (-c -w -z in n2disk.conf), own fast disk, bigger -b buffer";;
      nprobe*) fx="more nprobe threads sharing one PF_RING cluster, nprobe on the NIC's NUMA node";;
      *) fx="the application reads too slowly: more threads / cores on the NIC's node";;
    esac
    echo "$ap|$dev|$nr|$lp|$fx"; done > $OUT/.rl
  while IFS='|' read ap dev nr lp fx; do fnd 2 "PF_RING: $ap on $dev lost up to $lp% since start ($nr ring(s)): the application does not read fast enough" "$fx"; done < $OUT/.rl; rm -f $OUT/.rl
else echo "PF_RING module not loaded ($PROC/net/pf_ring/info missing)"; fi

# ---------- other packet sockets (libpcap/tcpdump/...) ----------
h "Other packet receivers (AF_PACKET)"
declare -A IDX; for i in $NICS; do IDX[$(cat $SYS/$i/ifindex 2>/dev/null)]=$i; done
pk=$(awk 'NR>1{print $5}' $PROC/net/packet 2>/dev/null | sort | uniq -c | while read c ix; do
  [ "$ix" = 0 ] && echo "$c on ALL interfaces" || { [ -n "${IDX[$ix]:-}" ] && echo "$c on ${IDX[$ix]}"; }; done)
echo "${pk:-none on the capture NICs}"
have ss && ss -0 -p 2>/dev/null | grep -E "$(echo $NICS | tr ' ' '|')|\*:\*|\*  " | awk '{print "  " $0}' | head -10
[ -n "$pk" ] && fnd 2 "AF_PACKET sockets see capture traffic ($(echo $pk | tr '\n' ',')): each gets its own kernel copy" "stop what is not needed (tcpdump, old recorder, a pcap-based tool, 'any' captures); see the ss lines in the report"

# ---------- applications ----------
h "Capture applications"
ps -eo pid,pcpu,etime,comm,args --sort=-pcpu 2>/dev/null | awk 'NR==1 || $4~/^(n2disk|nprobe|suricata|zeek|tcpdump|zbalance|ntopng|cento|pfcount)/' | cut -c1-200 | head -12

# ---------- disk ----------
if [ -n "$DIR" ]; then
  h "n2disk storage $DIR"
  df -h $DIR 2>/dev/null | tail -1
  root=$(diskdev /)
  [ "$DDEV" = "$root" ] && fnd 2 "n2disk writes to the root filesystem ($DDEV)" "a dedicated disk/array for $DIR (sequential write >= capture rate, e.g. 10G = 1.25 GB/s)"
  if [ -n "$IO0" ] && [ -n "$IO1" ]; then u=$(pct $(( IO1 - IO0 )) $(( S * 1000 ))); echo "disk $DDEV busy ${u}%"
    awk -v x=$u 'BEGIN{exit !(x>80)}' && fnd 1 "disk $DDEV of n2disk is ${u}% busy" "faster/dedicated storage; n2disk -b bigger buffer"; fi
fi

# ---------- duplicates ----------
if [ "$DUP" = 1 ] && [ -r $HERE/dup.sh ] && have tcpdump; then
  h "Duplicates (20000 packets per NIC)"
  for i in $NICS; do
    d=$(bash $HERE/dup.sh $i 20000 2>/dev/null | grep -E '^packets|^duplicated|^broadcast')
    echo "$i: $d" | tr '\n' ' '; echo
    dp=$(echo "$d" | sed -n 's/.*extra copies [0-9]* (\([0-9.]*\)%).*/\1/p')
    [ -n "$dp" ] && awk -v x=$dp 'BEGIN{exit !(x>5)}' && fnd 1 "$i: ${dp}% of packets are extra copies of the same packet (mirror duplication or loop)" "fix the SPAN/mirror (one source per traffic, not rx+tx on both ends / several VLANs); details: bash dup.sh $i"
  done
fi

# ---------- perf ----------
h "Kernel profile"
if [ "$PERF" = 1 ] && have perf && perf --version >/dev/null 2>&1; then
  timeout 30 perf record -a -F 99 -o $OUT/perf.data -- sleep 5 >/dev/null 2>&1
  perf report -i $OUT/perf.data --stdio --sort sym 2>/dev/null | grep -E '^ +[0-9.]+%' | head -15 | tee $OUT/perf.top
  awk '{v=$1; sub("%","",v); s=$NF} s~/pf_ring|ring_|copy_|memcpy|skb_copy|add_skb/{a+=v} s~/ip_rcv|nf_|br_|netif_receive|packet_rcv|tpacket|ipt_|conntrack/{b+=v} s~/i40e|ixgbe|ice_|mlx5|napi|bnxt/{c+=v}
       END{printf "pfring-copy %.0f%%  stack/af_packet %.0f%%  driver %.0f%%\n", a, b, c}' $OUT/perf.top | tee $OUT/perf.cat
  read _ pa _ pb _ pc < <(tr -d '%' < $OUT/perf.cat)
  [ "${pb:-0}" -gt 15 ] && fnd 1 "kernel profile: ${pb}% in the network stack / AF_PACKET (packets go up the stack)" "find who: bridge, IP on the NIC, AF_PACKET sockets, iptables/conntrack on the NIC (see above)"
  [ "${pa:-0}" -gt 15 ] && fnd 2 "kernel profile: ${pa}% copying packets into PF_RING rings" "fewer copies (clusters / zbalance_ipc) or ZC"
else
  echo "perf not available: install linux-tools-$(uname -r) for the kernel profile (or PERF=0 to skip)"
fi

# ---------- findings ----------
h "FINDINGS (most important first)"
if [ ${#F[@]} -eq 0 ]; then echo "nothing obvious; send the report"; else
  printf '%s\n' "${F[@]}" | sort -t'|' -k1,1n | awk -F'|' '{t=($1==1?"CRIT":($1==2?"WARN":"INFO")); printf "%2d. [%s] %s\n      fix: %s\n", NR, t, $2, $3}'
fi
DRV=$(basename "$(readlink $SYS/$(set -- $NICS; echo $1)/device/driver 2>/dev/null)" 2>/dev/null)
[ $TOTPPS -gt 0 ] && echo && echo "If the findings are clean and loss stays: PF_RING ZC driver (${DRV:-NIC driver}-zc) + zbalance_ipc (one read of the NIC, n2disk and nprobe from shared memory, licence needed)."
echo; echo "report: $REP"
