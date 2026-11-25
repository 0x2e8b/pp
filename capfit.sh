#!/bin/bash
# capfit - fit a Linux host for packet capture: what the NIC does to packets, kernel buffers and
# write-back, priority of the capture applications. Interactive: bash capfit.sh
# Non-interactive: NICS="eno1np0 eno2np1" SKIP="rxvlan vm.swappiness" bash capfit.sh check|offloads|kernel|priority|all|persist|revert
# Interactive: asks before EVERY single change (e.g. keep the VLAN stripping, change the rest).
# Non-interactive: applies everything except the names in SKIP (offload, kernel key or application).
# Every change is saved first (once) and undone by revert. Nothing restarts n2disk or nprobe.
set -u
SYS=${SYS:-/sys/class/net}; PROC=${PROC:-/proc}; ST=${ST:-/root/capfit}
SYSCTLF=${SYSCTLF:-/etc/sysctl.d/60-capfit.conf}; UNITDIR=${UNITDIR:-/etc/systemd/system}
UNIT=$UNITDIR/capfit.service; SELF=${SELF:-/usr/local/sbin/capfit.sh}; N2CONF=${N2CONF:-/etc/n2disk/n2disk.conf}
mkdir -p $ST
have() { command -v $1 >/dev/null 2>&1; }
warn() { echo "  ! $*"; }
yes()  { local a; read -rp "$1 [y/N] " a; [[ $a =~ ^[yYtT] ]]; }
SKIP=" ${SKIP:-} "
# one change: interactive -> ask with the reason; otherwise apply unless the name is in SKIP
confirm() { local name=$1; shift
  [[ $SKIP == *" $name "* ]] && { echo "  skipped $name (SKIP)"; return 1; }
  [ -t 0 ] || return 0
  echo "  - $name: $*"; yes "    change it?" || { echo "    kept"; return 1; }; }
WHY_gro="the NIC merges packets of a flow (GRO): the recording no longer matches the wire"
WHY_lro="the NIC merges TCP segments in hardware (LRO): same problem, bigger packets"
WHY_tso="segmentation offload on transmit (TSO): no effect on a pure capture NIC, off for consistency"
WHY_gso="generic segmentation (GSO): no effect on a pure capture NIC, off for consistency"
WHY_rxvlan="the NIC strips the 802.1Q tag (rxvlan): packets are recorded WITHOUT their VLAN. Keep it on only if the VLAN tag must not reach the applications"
WHY_net_core_netdev_max_backlog="queue for bursts the softirq cannot drain at once"
WHY_net_core_rmem_max="largest socket receive buffer an application may ask for"
WHY_net_core_rmem_default="default socket receive buffer (libpcap/AF_PACKET users)"
WHY_vm_dirty_background_bytes="start writing captured data to disk early, in small portions"
WHY_vm_dirty_bytes="cap on unwritten data: avoids stalls of n2disk's writer on a huge flush"
WHY_vm_swappiness="keep the capture buffers in RAM, swap only as a last resort"
why() { local v=WHY_${1//./_}; echo "${!v:-}"; }
ok()   { printf "  %-34s %-14s %-14s %s\n" "$1" "$2" "$3" "$4"; }

# ---------- what is checked ----------
# NIC features that change packets: merged (GRO/LRO), split (TSO/GSO) or with the VLAN tag removed (rxvlan:
# n2disk would record packets without their VLAN, filters on VLAN stop matching).
OFFL="gro:generic-receive-offload lro:large-receive-offload tso:tcp-segmentation-offload gso:generic-segmentation-offload rxvlan:rx-vlan-offload"
# kernel: key, recommended, rule (min = at least, max = at most, eq = exactly)
KERN="net.core.netdev_max_backlog:250000:min net.core.rmem_max:268435456:min net.core.rmem_default:33554432:min
vm.dirty_background_bytes:268435456:eq vm.dirty_bytes:1073741824:eq vm.swappiness:1:max"
# applications: name, nice (at most), oom_score_adj (at most)
APPS="n2disk:-10:-900 nprobe:-5:-500"

# ---------- NICs (same choice as nic.sh: n2disk.conf, else promisc without IP) ----------
n2ifs() { [ -r $N2CONF ] && sed -n 's/^ *-i[= ]*//p' $N2CONF | tr ',' ' '; }
choose() {
  [ -n "${NICS:-}" ] && return
  [ -s $ST/nics ] && { NICS=$(cat $ST/nics); return; }
  local p; p=$(n2ifs)
  [ -z "$p" ] && for i in $(ls $SYS); do [ -e $SYS/$i/device ] || continue; (( $(cat $SYS/$i/flags) & 0x100 )) || continue
    have ip && [ -n "$(ip -o -4 addr show dev $i 2>/dev/null)" ] && continue; p="$p $i"; done
  p=$(echo $p)
  if [ -t 0 ]; then echo "Physical NICs: $(for i in $(ls $SYS); do [ -e $SYS/$i/device ] && echo -n "$i "; done)"
    read -rp "Capture NICs [$p]: " NICS; NICS=${NICS:-$p}; else NICS=$p; fi
  [ -z "$NICS" ] && { echo "no capture NIC: NICS=\"eth1\" bash capfit.sh"; exit 1; }
  echo "$NICS" > $ST/nics
}
feat()  { ethtool -k $1 2>/dev/null | awk -v k="$2" '$1==k":"{print $2 ($3=="[fixed]"?" fixed":""); exit}'; }
pids()  { if have pgrep; then pgrep -x $1; else ps -eo pid,comm | awk -v c=$1 '$2==c{print $1}'; fi; }
nicev() { ps -o ni= -p $1 2>/dev/null | tr -d ' '; }
oomv()  { cat $PROC/$1/oom_score_adj 2>/dev/null; }
mlock() { awk '/Max locked memory/{print $4; exit}' $PROC/$1/limits 2>/dev/null; }
units() { systemctl list-units --type=service --all --plain --no-legend "$1*" 2>/dev/null | awk '{print $1}' | grep -E "^$1" ; }

# ---------- check ----------
check() {
  local i k s f now rec rule v bad=0 a n o p u
  echo "== NIC features that change packets (want: off)"
  for i in $NICS; do for k in $OFFL; do s=${k%%:*}; f=${k#*:}; now=$(feat $i $f)
    case "$now" in "") ok "$i $s" "n/a" "off" "-";; off*) ok "$i $s" "$now" "off" "OK";;
      *fixed*) ok "$i $s" "$now" "off" "cannot change (driver)";; *) ok "$i $s" "$now" "off" "CHANGE"; bad=1;; esac; done; done
  echo "== Kernel"
  echo "$KERN" | tr ' ' '\n' | while IFS=: read k rec rule; do [ -z "$k" ] && continue
    now=$(sysctl -n $k 2>/dev/null); [ -z "$now" ] && { ok "$k" "n/a" "$rec" "-"; continue; }
    case $rule in min) [ "$now" -ge "$rec" ] && v=OK || v=CHANGE;; max) [ "$now" -le "$rec" ] && v=OK || v=CHANGE;; eq) [ "$now" = "$rec" ] && v=OK || v=CHANGE;; esac
    ok "$k" "$now" "$rec ($rule)" "$v"; done
  echo "== Capture applications (running processes, drop-in for the next start)"
  for a in $APPS; do IFS=: read n rec o <<< "$a"; p=$(pids $n | head -1)
    if [ -z "$p" ]; then ok "$n" "not running" "" "-"; else
      now=$(nicev $p); [[ $now =~ ^-?[0-9]+$ ]] && [ $now -le $rec ] && v=OK || v=CHANGE; ok "$n nice (pid $p)" "$now" "<= $rec" "$v"
      now=$(oomv $p); [[ $now =~ ^-?[0-9]+$ ]] && [ $now -le $o ] && v=OK || v=CHANGE; ok "$n oom_score_adj" "$now" "<= $o" "$v"
      now=$(mlock $p); [ "$now" = unlimited ] && v=OK || v=CHANGE; ok "$n locked memory" "$now" "unlimited" "$v"; fi
    for u in $(units $n); do [ -f $UNITDIR/$u.d/60-capfit.conf ] && v=present || v=none; ok "  unit $u drop-in" "$v" "present" "$([ $v = present ] && echo OK || echo CHANGE)"; done
  done
  echo "boot unit (offloads after reboot): $([ -f $UNIT ] && echo yes || echo no)"
}

# ---------- save the original once ----------
save() {
  local i k s f now
  for i in $NICS; do [ -f $ST/offl.$i ] && continue
    for k in $OFFL; do s=${k%%:*}; f=${k#*:}; now=$(feat $i $f); [ -n "$now" ] && echo "$s ${now%% *}"; done > $ST/offl.$i; done
  [ -f $ST/sysctl.before ] || echo "$KERN" | tr ' ' '\n' | while IFS=: read k _ _; do [ -n "$k" ] && echo "$k=$(sysctl -n $k 2>/dev/null)"; done > $ST/sysctl.before
}

offloads() {
  local i k s f on
  for k in $OFFL; do s=${k%%:*}; f=${k#*:}; on=""
    for i in $NICS; do [ "$(feat $i $f)" = on ] && on="$on $i"; done
    [ -z "$on" ] && continue
    if [ "${MODE:-}" = boot ] || confirm $s "$(why $s) - now on:$on"; then
      for i in $on; do ethtool -K $i $s off 2>/dev/null && echo "    $i: $s off" || warn "$i: $s refused by the driver"; done
      sed -i "/^$s\$/d" $ST/offl.off 2>/dev/null; echo $s >> $ST/offl.off
    fi
  done
}

kernel() {
  local k rec rule now v x
  for x in $KERN; do IFS=: read k rec rule <<< "$x"
    now=$(sysctl -n $k 2>/dev/null); [ -z "$now" ] && continue
    case $rule in min) [ "$now" -ge "$rec" ] && continue;; max) [ "$now" -le "$rec" ] && continue;; eq) [ "$now" = "$rec" ] && continue;; esac
    confirm $k "$(why $k) - now $now, set $rec" || continue
    [ -f $SYSCTLF ] || echo "# capfit: capture host kernel settings (bash capfit.sh revert removes this file)" > $SYSCTLF
    sed -i "/^$k = /d" $SYSCTLF; echo "$k = $rec" >> $SYSCTLF
    sysctl -w "$k=$rec" >/dev/null && echo "    $k = $rec (in $SYSCTLF)"
  done
}

priority() {
  local a n rec o p u d
  for a in $APPS; do IFS=: read n rec o <<< "$a"
    p=$(pids $n); u=$(units $n)
    [ -z "$p$u" ] && continue
    confirm $n "nice $rec, OOM protection $o, unlimited locked memory: the capture keeps its CPU and is the last process the kernel kills; running process now (pid $(echo $p)) + drop-in for ${u:-no unit} used from its next start" || continue
    for p in $p; do
      [ -f $ST/prio.$p ] || echo "$(nicev $p) $(oomv $p)" > $ST/prio.$p
      renice -n $rec -p $p >/dev/null 2>&1; echo $o > $PROC/$p/oom_score_adj 2>/dev/null
      have prlimit && prlimit --memlock=unlimited:unlimited --pid $p 2>/dev/null
      echo "    $n pid $p: nice $(nicev $p), oom_score_adj $(oomv $p), locked memory $(mlock $p)"
    done
    for u in $u; do d=$UNITDIR/$u.d; mkdir -p $d
      printf '%s\n' "# capfit: priority of $n (bash capfit.sh revert removes this file)" "[Service]" "Nice=$rec" "OOMScoreAdjust=$o" \
        "LimitMEMLOCK=infinity" "LimitNOFILE=65535" > $d/60-capfit.conf; echo "    $u: drop-in $d/60-capfit.conf (used from its next start)"; done
  done
  systemctl daemon-reload 2>/dev/null
}

persist() {
  cp "$0" $SELF && chmod 755 $SELF
  printf '%s\n' "[Unit]" "Description=capfit: capture NIC offloads off" "After=network.target" "Before=n2disk.service" \
    "[Service]" "Type=oneshot" "RemainAfterExit=yes" "Environment=\"NICS=$NICS\" ST=$ST" "ExecStart=$SELF boot" \
    "[Install]" "WantedBy=multi-user.target" > $UNIT
  systemctl daemon-reload; systemctl enable capfit >/dev/null 2>&1 && echo "offloads set at every boot ($UNIT); kernel and priorities persist on their own"
}

revert() {
  local i s v f p
  for i in $NICS; do [ -f $ST/offl.$i ] || continue
    while read s v; do [ "$v" = on ] && grep -qx $s $ST/offl.off 2>/dev/null && ethtool -K $i $s on 2>/dev/null && echo "$i: $s on again"; done < $ST/offl.$i; rm -f $ST/offl.$i; done; rm -f $ST/offl.off
  if [ -f $SYSCTLF ]; then rm -f $SYSCTLF
    while IFS== read k v; do [ -n "$v" ] && sysctl -w "$k=$v" >/dev/null 2>&1; done < $ST/sysctl.before
    echo "kernel: $SYSCTLF removed, original values back"; fi
  rm -f $ST/sysctl.before
  for f in $ST/prio.*; do [ -f "$f" ] || continue; p=${f##*.}
    if [ -d $PROC/$p ]; then read v o < $f; renice -n $v -p $p >/dev/null 2>&1; echo $o > $PROC/$p/oom_score_adj 2>/dev/null; echo "pid $p: nice $v, oom_score_adj $o again"; fi
    rm -f $f; done
  for f in $UNITDIR/*.service.d/60-capfit.conf; do [ -f "$f" ] && rm -f "$f" && echo "removed $f" && rmdir --ignore-fail-on-non-empty "${f%/*}"; done
  [ -f $UNIT ] && { systemctl disable capfit >/dev/null 2>&1; rm -f $UNIT; echo "boot unit removed"; }
  systemctl daemon-reload 2>/dev/null
}

run() {
  case $1 in
    check)    check ;;
    offloads) save; offloads ;;
    kernel)   save; kernel ;;
    priority) priority ;;
    all)      save; offloads; kernel; priority ;;
    boot)     MODE=boot; OFFL=$(for k in $OFFL; do grep -qx "${k%%:*}" $ST/offl.off 2>/dev/null && echo $k; done); offloads ;;
    persist)  persist ;;
    revert)   revert ;;
    *) sed -n '2,5p' "$0"; return 1 ;;
  esac
}

[ $(id -u) -eq 0 ] || [ -n "${NOROOT:-}" ] || { echo "run as root (sudo su -)"; exit 1; }
have ethtool || warn "ethtool missing: NIC features cannot be checked"
choose
[ $# -gt 0 ] && { run $1; exit; }
while :; do
  echo; echo "capfit  NICs: $NICS"
  echo " 1 check     what is not capture-friendly (changes nothing)"
  echo " 2 offloads  NIC: GRO/LRO/TSO/GSO, VLAN stripping   (asks for each; link may blink)"
  echo " 3 kernel    backlog, socket buffers, steady disk write-back, swappiness"
  echo " 4 priority  n2disk/nprobe: nice, OOM protection, locked memory (live + drop-in, no restart)"
  echo " 5 all       2 + 3 + 4, still one question per change"
  echo " 6 persist   the offloads you turned off, again after reboot"
  echo " 7 revert    everything back to the original"
  echo " 8 change NICs      0 quit"
  read -rp "> " c
  case $c in
    1) run check ;;
    2) run offloads ;;
    3) run kernel ;;
    4) run priority ;;
    5) run all ;;
    6) yes "Set offloads at every boot?" && run persist ;;
    7) yes "Undo everything capfit changed?" && run revert ;;
    8) rm -f $ST/nics; NICS=""; choose ;;
    0|q) exit 0 ;;
  esac
done
