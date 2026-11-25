#!/bin/bash
# Capture NIC RX tuning, all steps in one script.
#   bash nic.sh check     save the original settings (once), show state + plan, measure loss
#   bash nic.sh apply     max RX ring, Q queues, GRO/LRO off, irqbalance off, IRQs on the NIC's NUMA node; then measure
#   bash nic.sh measure   loss % over 10 s (rx_missed_errors vs rx_packets), logged to /root/nic/measure.log
#   bash nic.sh rss       hash UDP also on ports (only if traffic sits in 1-2 queues)
#   bash nic.sh persist   keep it after reboot (systemd unit nic-tune.service)
#   bash nic.sh revert    back to the saved original settings, irqbalance on, unit removed
#   bash nic.sh status    current state only
# Env: NICS="eno1np0 eno2np1"  Q=16  SECS=10
# apply/rss/revert reset the link for a few seconds (probe and n2disk lose traffic briefly).
set -u
NICS=${NICS:-"eno1np0 eno2np1"}; Q=${Q:-16}; SECS=${SECS:-10}
SYS=${SYS:-/sys/class/net}; PROC=${PROC:-/proc}; ST=${ST:-/root/nic}
UNIT=${UNIT:-/etc/systemd/system/nic-tune.service}; SELF=${SELF:-/usr/local/sbin/nic.sh}
mkdir -p $ST

cpus()  { tr , '\n' < $SYS/$1/device/local_cpulist | while IFS=- read a b; do seq $a ${b:-$a}; done; }
node()  { cat $SYS/$1/device/numa_node; }
ring()  { ethtool -g $1 | awk -v s="$2" '$0~s{f=1} f&&/^RX:/{print $2; exit}'; }   # s = maximums|Current
chans() { ethtool -l $1 | awk -v s="$2" '$0~s{f=1} f&&/^Combined:/{print $2; exit}'; }
feat()  { ethtool -k $1 | awk -v k="$2" '$1==k":"{print $2; exit}'; }
irqs()  { grep -E "$1-TxRx" $PROC/interrupts | cut -d: -f1 | tr -d ' '; }
udph()  { ethtool -n $1 rx-flow-hash udp4 2>/dev/null | awk '/IP SA/{s=s"s"} /IP DA/{s=s"d"} /bytes 0 & 1/{s=s"f"} /bytes 2 & 3/{s=s"n"} END{print s}'; }
cnt()   { ethtool -S $1 | awk -v k="$2" '$1==k":"{print $2; exit}'; }

# CPU offset per NIC: NICs on the same NUMA node get different CPUs
declare -A OFF; declare -A USED
for I in $NICS; do n=$(node $I); OFF[$I]=${USED[$n]:-0}; USED[$n]=$(( ${USED[$n]:-0} + Q )); done
pick() { cpus $1 | tail -n +$(( ${OFF[$1]} + 1 )) | head -n $Q; }

save() {
  for I in $NICS; do
    [ -f $ST/$I.before ] && { echo "$I: original already saved ($ST/$I.before), not overwritten"; continue; }
    echo "RX=$(ring $I Current) COMB=$(chans $I Current) GRO=$(feat $I generic-receive-offload) LRO=$(feat $I large-receive-offload) UDP=$(udph $I)" > $ST/$I.before
    echo "$I: saved $(cat $ST/$I.before)"
  done
  [ -f $ST/irqbalance.before ] || echo "$(systemctl is-enabled irqbalance 2>/dev/null)" > $ST/irqbalance.before
}

show() {
  for I in $NICS; do
    echo "== $I  node $(node $I)  $(cpus $I | wc -l) cpus ($(cpus $I | head -1)..$(cpus $I | tail -1))"
    echo "   rx ring $(ring $I Current) (max $(ring $I maximums))   queues $(chans $I Current) (max $(chans $I maximums))   gro $(feat $I generic-receive-offload)"
    ethtool -S $I | awk -F: '/rx-[0-9]+\.packets/{gsub(/ /,"",$1); gsub(/ /,"",$2); q[$1]=$2; t+=$2} END{n=0; for(k in q) n++; m=""; for(k in q) if(m==""||q[k]>q[m]) m=k;
      if(t>0) printf "   queues in use %d, busiest %s = %.0f%% of packets%s\n", n, m, 100*q[m]/t, (100*q[m]/t > 3*100/n && n>2) ? "  <-- uneven: try  bash nic.sh rss" : ""}'
    echo -n "   irq cpus:"; for q in $(irqs $I); do echo -n " $(cat $PROC/irq/$q/smp_affinity_list)"; done; echo
    echo "   plan: IRQs on cpus $(pick $I | tr '\n' ' ')"
  done
  echo "irqbalance $(systemctl is-active irqbalance 2>/dev/null)   persist unit $( [ -f $UNIT ] && echo yes || echo no)"
  F=$(for I in $NICS; do cpus $I | tail -n +$(( ${USED[$(node $I)]} + 1 )); done | sort -n | uniq | head -3 | tr '\n' ' ')
  set -- $F; [ $# -eq 3 ] && echo "free cpus for n2disk (manual, /etc/n2disk/n2disk.conf): -c=$1 -w=$2 -z=$3"
}

measure() {
  declare -A P M
  for I in $NICS; do P[$I]=$(cnt $I rx_packets); M[$I]=$(cnt $I rx_missed_errors); done
  echo "measuring $SECS s ..."; sleep $SECS
  for I in $NICS; do
    dp=$(( $(cnt $I rx_packets) - ${P[$I]} )); dm=$(( $(cnt $I rx_missed_errors) - ${M[$I]} ))
    l=$(awk -v p=$dp -v m=$dm 'BEGIN{printf "%.1f", (p+m)?100*m/(p+m):0}')
    pps=$(( (dp + dm) / SECS ))
    line="$(date '+%F %T') ${1:-measure} $I loss $l%  arriving $pps pps  missed +$dm  received +$dp"
    echo "$line"; echo "$line" >> $ST/measure.log
  done
}

apply() {
  systemctl disable --now irqbalance >/dev/null 2>&1
  for I in $NICS; do
    ethtool -G $I rx $(ring $I maximums) 2>/dev/null
    ethtool -L $I combined $Q
    ethtool -K $I gro off lro off 2>/dev/null
  done
  sleep 3
  for I in $NICS; do
    C=($(pick $I)); n=0
    for q in $(irqs $I); do echo ${C[$(( n++ % ${#C[@]} ))]} > $PROC/irq/$q/smp_affinity_list; done
    [ -f $ST/rss ] && ethtool -N $I rx-flow-hash udp4 sdfn
    echo "$I: rx ring $(ring $I Current), queues $(chans $I Current), $n IRQs on cpus ${C[*]}"
  done
}

case ${1:-} in
  check)   save; show; measure before ;;
  apply)   [ -f $ST/$(set -- $NICS; echo $1).before ] || save; apply; show; measure after ;;
  boot)    apply ;;
  measure) measure ;;
  status)  show ;;
  rss)     for I in $NICS; do ethtool -N $I rx-flow-hash udp4 sdfn && echo "$I: udp4 hash on ports"; done; touch $ST/rss; sleep 5; show ;;
  persist)
    cp "$0" $SELF; chmod 755 $SELF
    printf '%s\n' "[Unit]" "Description=Capture NIC RX tuning" "After=network.target" "Before=n2disk.service" \
      "[Service]" "Type=oneshot" "RemainAfterExit=yes" "Environment=\"NICS=$NICS\" Q=$Q" "ExecStart=$SELF boot" \
      "[Install]" "WantedBy=multi-user.target" > $UNIT
    systemctl daemon-reload; systemctl enable nic-tune && echo "persisted: $UNIT -> $SELF boot" ;;
  revert)
    for I in $NICS; do
      [ -f $ST/$I.before ] || { echo "$I: no saved original in $ST"; continue; }
      . $ST/$I.before
      ethtool -G $I rx $RX; ethtool -L $I combined $COMB; ethtool -K $I gro $GRO 2>/dev/null; ethtool -K $I lro $LRO 2>/dev/null
      [ -f $ST/rss ] && [ -n "${UDP:-}" ] && ethtool -N $I rx-flow-hash udp4 $UDP
      echo "$I: back to rx $RX, queues $COMB, gro $GRO, lro $LRO"
    done
    rm -f $ST/rss
    [ "$(cat $ST/irqbalance.before 2>/dev/null)" = enabled ] && systemctl enable --now irqbalance && echo "irqbalance on"
    [ -f $UNIT ] && { systemctl disable nic-tune; rm -f $UNIT; systemctl daemon-reload; echo "unit removed"; }
    sleep 3; show ;;
  *) sed -n '2,11p' "$0" ;;
esac
