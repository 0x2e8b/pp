#!/bin/bash
# Capture NIC RX tuning (PF_RING non-ZC, n2disk/nprobe). Interactive: bash nic.sh
# Finds the NICs, proposes the capture ones, then a menu: check / apply / measure / rss / persist / revert.
# Non-interactive: NICS="eno1np0 eno2np1" bash nic.sh check|apply|measure|rss|persist|revert|status
# apply/rss/revert reset the link of the chosen NICs for a few seconds.
set -u
SYS=${SYS:-/sys/class/net}; PROC=${PROC:-/proc}; CPUON=${CPUON:-/sys/devices/system/cpu/online}
ST=${ST:-/root/nic}; UNIT=${UNIT:-/etc/systemd/system/nic-tune.service}; SELF=${SELF:-/usr/local/sbin/nic.sh}
N2CONF=${N2CONF:-/etc/n2disk/n2disk.conf}; QWANT=${Q:-16}; SECS=${SECS:-10}
mkdir -p $ST
have() { command -v $1 >/dev/null 2>&1; }
say()  { echo "$*"; }
warn() { echo "  ! $*"; }
ask()  { local a; read -rp "$1 " a; echo "${a:-$2}"; }
yes()  { local a; read -rp "$1 [y/N] " a; [[ $a =~ ^[yYtT] ]]; }

# ---------- reading the NIC (every reader returns "" when the driver lacks it) ----------
expand() { tr , '\n' | while IFS=- read a b; do [ -n "$a" ] && seq $a ${b:-$a}; done; }
node()   { local n; n=$(cat $SYS/$1/device/numa_node 2>/dev/null); echo ${n:--1}; }
cpus()   { local f=$SYS/$1/device/local_cpulist
           if [ "$(node $1)" != -1 ] && [ -s $f ]; then expand < $f; else expand < $CPUON; fi; }
ring()   { have ethtool && ethtool -g $1 2>/dev/null | awk -v s="$2" '$0~s{f=1} f&&/^RX:/{print $2; exit}'; }
chans()  { have ethtool && ethtool -l $1 2>/dev/null | awk -v s="$2" '$0~s{f=1} f&&/^Combined:/{print $2; exit}'; }
feat()   { have ethtool && ethtool -k $1 2>/dev/null | awk -v k="$2" '$1==k":"{print $2; exit}'; }
udph()   { have ethtool && ethtool -n $1 rx-flow-hash udp4 2>/dev/null | awk '/IP SA/{s=s"s"} /IP DA/{s=s"d"} /bytes 0 & 1/{s=s"f"} /bytes 2 & 3/{s=s"n"} END{print s}'; }
driver() { basename "$(readlink $SYS/$1/device/driver 2>/dev/null)" 2>/dev/null; }
# counter: ethtool name first, then the kernel's standard statistics
cnt() { local v=""; have ethtool && v=$(ethtool -S $1 2>/dev/null | awk -v k="$2" '$1==k":"{print $2; exit}')
        [ -z "$v" ] && [ -r $SYS/$1/statistics/$2 ] && v=$(cat $SYS/$1/statistics/$2); echo "$v"; }
# queue IRQs: names with the NIC name (i40e TxRx, vmxnet3 rxtx, ixgbe, ...), else all MSI IRQs of the PCI device
irqs() { local l; l=$(grep -E "[^a-z0-9]$1([^0-9a-z]|$)" $PROC/interrupts 2>/dev/null | grep -viE 'link|misc|other|fdir|async|cmd|event' | cut -d: -f1 | tr -d ' ')
         [ -z "$l" ] && [ -d $SYS/$1/device/msi_irqs ] && l=$(ls $SYS/$1/device/msi_irqs | sort -n)
         echo $l; }
qstats() { have ethtool && ethtool -S $1 2>/dev/null | awk -F: '$1~/^ *rx[-_]?(queue_)?[0-9]+[._]packets$/{gsub(/ /,"",$1); gsub(/ /,"",$2); q[$1]=$2; t+=$2}
             END{n=0; for(k in q) n++; if(!n||!t){print "   per-queue counters: not available on this driver"; exit}
             m=""; for(k in q) if(m==""||q[k]>q[m]) m=k; p=100*q[m]/t
             printf "   queues in use %d, busiest %s = %.0f%% of packets%s\n", n, m, p, (n>2 && p>3*100/n) ? "   <-- uneven: menu rss" : ""}'; }

# ---------- choosing NICs ----------
n2ifs() { [ -r $N2CONF ] && sed -n 's/^ *-i[= ]*//p' $N2CONF | tr ',' ' '; }
list_nics() {
  local i flags tags ip
  for i in $(ls $SYS); do
    [ -e $SYS/$i/device ] || continue                        # physical/PCI only (no lo, docker, bridges, vlans)
    flags=$(( $(cat $SYS/$i/flags) )); tags=""
    ip=$(have ip && ip -o -4 addr show dev $i 2>/dev/null | awk '{print $4}' | head -1)
    [[ " $(n2ifs) " == *" $i "* ]] && tags="$tags n2disk"
    (( flags & 0x100 )) && tags="$tags promisc"
    [ "$(cat $SYS/$i/operstate 2>/dev/null)" = up ] || tags="$tags DOWN"
    [ -n "$ip" ] && tags="$tags ip=$ip" || tags="$tags no-ip"
    printf "%s|%s|%s|%s\n" "$i" "$(driver $i)" "$(cat $SYS/$i/speed 2>/dev/null || echo ?)" "$tags"
  done
}
propose() {   # n2disk ifaces, else promisc without IP, else up without IP
  local p; p=$(n2ifs); [ -n "$p" ] && { echo $p; return; }
  p=$(list_nics | awk -F'|' '$4~/promisc/ && $4~/no-ip/ && $4!~/DOWN/{print $1}'); [ -n "$p" ] && { echo $p; return; }
  list_nics | awk -F'|' '$4~/no-ip/ && $4!~/DOWN/{print $1}'
}
choose() {
  [ -n "${NICS:-}" ] && return
  [ -s $ST/nics ] && { NICS=$(cat $ST/nics); say "NICs from the last run ($ST/nics): $NICS"; [ -t 0 ] || return; yes "Keep them?" && return; }
  say "Physical NICs:"; list_nics | awk -F'|' '{printf "  %-12s %-10s %6s Mb/s %s\n", $1, $2, $3, $4}'
  local p; p=$(propose | tr '\n' ' ' | sed 's/ *$//')
  NICS=$(ask "Capture NICs, space separated [$p]:" "$p")
  [ -z "$NICS" ] && { warn "no NIC chosen"; exit 1; }
  for i in $NICS; do [ -e $SYS/$i ] || { warn "$i does not exist"; exit 1; }
    list_nics | grep -q "^$i|.*ip=" && warn "$i has an IP address - management NIC? tuning it resets its link"; done
  echo "$NICS" > $ST/nics
}

# ---------- plan: queues and CPUs per NIC (NICs sharing a node share its CPUs) ----------
declare -A OFF QN USED CNT
plan() {
  local i n per mx q
  for i in $NICS; do n=$(node $i); CNT[$n]=$(( ${CNT[$n]:-0} + 1 )); done
  for i in $NICS; do
    n=$(node $i); per=$(( $(cpus $i | wc -l) / ${CNT[$n]} )); mx=$(chans $i maximums)
    q=$QWANT; [[ $mx =~ ^[0-9]+$ ]] && [ $mx -lt $q ] && q=$mx; [ $per -lt $q ] && q=$per; [ $q -lt 1 ] && q=1
    QN[$i]=$q; OFF[$i]=${USED[$n]:-0}; USED[$n]=$(( ${USED[$n]:-0} + q ))
  done
}
pick() { cpus $1 | tail -n +$(( ${OFF[$1]} + 1 )) | head -n ${QN[$1]}; }

save() {
  for i in $NICS; do
    [ -f $ST/$i.before ] && { say "$i: original already saved, kept ($(cat $ST/$i.before))"; continue; }
    echo "RX=$(ring $i Current) COMB=$(chans $i Current) GRO=$(feat $i generic-receive-offload) LRO=$(feat $i large-receive-offload) UDP=$(udph $i)" > $ST/$i.before
    say "$i: original saved ($(cat $ST/$i.before))"
  done
  [ -f $ST/irqbalance.before ] || (systemctl is-enabled irqbalance 2>/dev/null || echo none) > $ST/irqbalance.before
}

show() {
  local i n l q x f
  for i in $NICS; do
    n=$(node $i); l=$(cpus $i)
    say "== $i  driver $(driver $i)  node $n$([ $n = -1 ] && echo ' (unknown: using all CPUs)')  $(echo "$l" | wc -l) cpus ($(echo "$l" | head -1)..$(echo "$l" | tail -1))"
    say "   rx ring $(ring $i Current) (max $(ring $i maximums))   queues $(chans $i Current) (max $(chans $i maximums))   gro $(feat $i generic-receive-offload)"
    qstats $i
    q=$(irqs $i); [ -z "$q" ] && warn "no queue IRQs found for $i: affinity will be skipped"
    echo -n "   irq cpus:"; for x in $q; do echo -n " $(cat $PROC/irq/$x/smp_affinity_list 2>/dev/null)"; done; echo
    say "   plan: ${QN[$i]} queues, IRQs on cpus $(pick $i | tr '\n' ' ')"
  done
  say "irqbalance $(systemctl is-active irqbalance 2>/dev/null || echo none)   persisted: $([ -f $UNIT ] && echo yes || echo no)   rss: $([ -f $ST/rss ] && echo on || echo off)"
  f=""; for i in $NICS; do f="$f $(cpus $i | tail -n +$(( ${USED[$(node $i)]} + 1 )))"; done
  set -- $(echo $f | tr ' ' '\n' | sort -nu | head -3)
  [ $# -eq 3 ] && say "free cpus for n2disk (by hand in $N2CONF): -c=$1 -w=$2 -z=$3"
}

measure() {
  local i dp dm l line; declare -A P M
  for i in $NICS; do P[$i]=$(cnt $i rx_packets); M[$i]=$(cnt $i rx_missed_errors); done
  say "measuring $SECS s ..."; sleep $SECS
  for i in $NICS; do
    [ -z "${P[$i]}" ] && { warn "$i: no rx_packets counter"; continue; }
    dp=$(( $(cnt $i rx_packets) - ${P[$i]} ))
    if [ -n "${M[$i]}" ]; then dm=$(( $(cnt $i rx_missed_errors) - ${M[$i]} )); else dm=0; warn "$i: driver has no rx_missed_errors, loss unknown"; fi
    l=$(awk -v p=$dp -v m=$dm 'BEGIN{printf "%.1f", (p+m)?100*m/(p+m):0}')
    line="$(date '+%F %T') ${1:-measure} $i loss $l%  arriving $(( (dp+dm)/SECS )) pps  missed +$dm  received +$dp"
    say "$line"; echo "$line" >> $ST/measure.log
  done
}

apply() {
  local i r c n x bad cl
  have ethtool || warn "ethtool missing: only IRQ affinity can be set"
  if systemctl is-active irqbalance >/dev/null 2>&1; then systemctl disable --now irqbalance >/dev/null 2>&1 && say "irqbalance stopped and disabled"; fi
  for i in $NICS; do
    r=$(ring $i maximums); c=$(ring $i Current)
    if [[ $r =~ ^[0-9]+$ ]] && [ "$r" != "$c" ]; then ethtool -G $i rx $r 2>/dev/null || warn "$i: rx ring not changed"; fi
    c=$(chans $i Current)
    if [[ $c =~ ^[0-9]+$ ]] && [ "$c" != "${QN[$i]}" ]; then ethtool -L $i combined ${QN[$i]} 2>/dev/null || warn "$i: queues not changed (driver refuses)"; fi
    ethtool -K $i gro off 2>/dev/null; ethtool -K $i lro off 2>/dev/null
    [ -f $ST/rss ] && { ethtool -N $i rx-flow-hash udp4 sdfn 2>/dev/null || warn "$i: rss hash not supported"; }
  done
  sleep 3   # IRQs are recreated after -L
  for i in $NICS; do
    cl=($(pick $i)); n=0; bad=0
    [ ${#cl[@]} -eq 0 ] && { warn "$i: no CPUs left for it, IRQs not pinned"; continue; }
    for x in $(irqs $i); do echo ${cl[$(( n++ % ${#cl[@]} ))]} > $PROC/irq/$x/smp_affinity_list 2>/dev/null || bad=$((bad+1)); done
    say "$i: rx ring $(ring $i Current), queues $(chans $i Current), $n IRQs on cpus ${cl[*]}"
    [ $bad -gt 0 ] && warn "$i: $bad IRQs refused a CPU (kernel-managed IRQs), left as they are"
  done
}

revert() {
  local i RX COMB GRO LRO UDP
  for i in $NICS; do
    [ -f $ST/$i.before ] || { warn "$i: nothing saved, skipped"; continue; }
    RX=""; COMB=""; GRO=""; LRO=""; UDP=""; . $ST/$i.before
    [ -n "$RX" ] && ethtool -G $i rx $RX 2>/dev/null; [ -n "$COMB" ] && ethtool -L $i combined $COMB 2>/dev/null
    [ -n "$GRO" ] && ethtool -K $i gro $GRO 2>/dev/null; [ -n "$LRO" ] && ethtool -K $i lro $LRO 2>/dev/null
    [ -f $ST/rss ] && [ -n "$UDP" ] && ethtool -N $i rx-flow-hash udp4 $UDP 2>/dev/null
    say "$i: back to rx $RX, queues $COMB, gro $GRO, lro $LRO"
  done
  rm -f $ST/rss
  [ "$(cat $ST/irqbalance.before 2>/dev/null)" = enabled ] && systemctl enable --now irqbalance >/dev/null 2>&1 && say "irqbalance on again"
  [ -f $UNIT ] && { systemctl disable nic-tune >/dev/null 2>&1; rm -f $UNIT; systemctl daemon-reload; say "boot unit removed"; }
}

persist() {
  cp "$0" $SELF && chmod 755 $SELF
  printf '%s\n' "[Unit]" "Description=Capture NIC RX tuning" "After=network.target" "Before=n2disk.service" \
    "[Service]" "Type=oneshot" "RemainAfterExit=yes" "Environment=\"NICS=$NICS\" Q=$QWANT ST=$ST" "ExecStart=$SELF boot" \
    "[Install]" "WantedBy=multi-user.target" > $UNIT
  systemctl daemon-reload; systemctl enable nic-tune >/dev/null 2>&1 && say "persisted: runs at boot before n2disk ($UNIT)"
}

run() {
  case $1 in
    check)   save; show; measure before ;;
    apply)   save; apply; show; measure after ;;
    boot)    apply ;;
    measure) measure ;;
    status)  show ;;
    rss)     touch $ST/rss; for i in $NICS; do ethtool -N $i rx-flow-hash udp4 sdfn 2>/dev/null && say "$i: UDP hashed on ports too" || warn "$i: not supported"; done; sleep 3; show ;;
    persist) persist ;;
    revert)  revert; show ;;
    *) sed -n '2,5p' "$0"; return 1 ;;
  esac
}

# ---------- main ----------
[ $(id -u) -eq 0 ] || [ -n "${NOROOT:-}" ] || { echo "run as root (sudo su -)"; exit 1; }
have ethtool || warn "ethtool not installed: ring/queue changes and some counters unavailable"
choose; plan
if [ $# -gt 0 ]; then run $1; exit; fi
while :; do
  echo; say "NICs: $NICS"
  say " 1 check    state, plan, loss now (saves the original once)"
  say " 2 apply    max ring, queues, IRQs on own CPUs, irqbalance off   (link resets!)"
  say " 3 measure  loss over $SECS s"
  say " 4 rss      spread UDP over queues by ports                       (link resets!)"
  say " 5 persist  keep after reboot"
  say " 6 revert   back to the original                                  (link resets!)"
  say " 7 status   state only"
  say " 8 change NICs      0 quit"
  case $(ask ">" "") in
    1) run check ;;
    2) yes "Links of $NICS go down for a few seconds. Apply?" && run apply ;;
    3) run measure ;;
    4) yes "Links reset. Hash UDP on ports?" && run rss ;;
    5) yes "Run at every boot?" && run persist ;;
    6) yes "Back to the original settings?" && run revert ;;
    7) run status ;;
    8) rm -f $ST/nics; NICS=""; choose; OFF=(); QN=(); USED=(); CNT=(); plan ;;
    0|q) exit 0 ;;
  esac
done
