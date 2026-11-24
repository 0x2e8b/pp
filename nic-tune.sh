#!/bin/bash
# RX tuning of a capture NIC (i40e, PF_RING non-ZC): ring size, queues, IRQs on the NIC's own NUMA node.
# Default is a dry run that only shows the state and the plan.
#   bash nic-tune.sh eno1np0                  # show
#   Q=16 SKIP=0 APPLY=1 bash nic-tune.sh eno1np0
#   Q=16 SKIP=16 APPLY=1 bash nic-tune.sh eno2np1   # second NIC on the same node: next 16 CPUs
# APPLY resets the link for a moment (ethtool -G/-L): the probe and n2disk lose a few seconds.
set -u
IF=${1:?iface}; Q=${Q:-16}; SKIP=${SKIP:-0}; APPLY=${APPLY:-0}
DEV=/sys/class/net/$IF/device
NODE=$(cat $DEV/numa_node); LCL=$(cat $DEV/local_cpulist)
ALL=$(echo "$LCL" | tr ',' '\n' | while IFS=- read a b; do seq $a ${b:-$a}; done)
PICK=$(echo "$ALL" | tail -n +$((SKIP+1)) | head -n $Q)
RXMAX=$(ethtool -g $IF | awk '/maximums/{m=1} m&&/^RX:/{print $2; exit}')
RXCUR=$(ethtool -g $IF | awk '/Current/{c=1} c&&/^RX:/{print $2; exit}')
QMAX=$(ethtool -l $IF | awk '/maximums/{m=1} m&&/Combined/{print $2; exit}')
QCUR=$(ethtool -l $IF | awk '/Current/{c=1} c&&/Combined/{print $2; exit}')
echo "$IF  numa_node=$NODE  local cpus=$LCL"
echo "rx ring  $RXCUR (max $RXMAX)    queues $QCUR (max $QMAX)    irqbalance $(systemctl is-active irqbalance)"
echo "busiest queues (packets):"
ethtool -S $IF | grep -E 'rx-[0-9]+\.packets' | sort -t: -k2 -rn | head -5
echo "plan: rx ring $RXMAX, $Q queues, IRQs on CPUs: $(echo $PICK)"
echo "      free for n2disk/nprobe on this node: $(echo "$ALL" | grep -vxF "$(echo "$PICK")" | head -8 | tr '\n' ' ')..."
[ "$APPLY" = 1 ] || { echo "dry run; APPLY=1 to apply"; exit 0; }
systemctl stop irqbalance; systemctl disable irqbalance
ethtool -G $IF rx $RXMAX
ethtool -L $IF combined $Q
ethtool -K $IF gro off lro off 2>/dev/null
sleep 2
set -- $PICK; i=0
for irq in $(grep -E "$IF-TxRx" /proc/interrupts | awk -F: '{print $1}'); do
  [ $# -eq 0 ] && set -- $PICK
  echo $1 > /proc/irq/$irq/smp_affinity_list; echo "irq $irq -> cpu $1"; shift
done
ethtool -g $IF | grep -A5 Current | grep RX:; ethtool -l $IF | grep -A5 Current | grep Combined
