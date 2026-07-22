#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 apply|clear <interface> [delay-ms] [loss-percent]"
  echo "example: sudo $0 apply eth0 100 3"
}

if [[ $# -lt 2 || $# -gt 4 ]]; then
  usage
  exit 2
fi

action="$1"
interface="$2"
delay_ms="${3:-100}"
loss_percent="${4:-0}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "netem changes require root" >&2
  exit 1
fi
if ! ip link show dev "${interface}" >/dev/null 2>&1; then
  echo "interface not found: ${interface}" >&2
  exit 1
fi

case "${action}" in
  apply)
    if ! [[ "${delay_ms}" =~ ^[0-9]+$ ]] ||
       ! [[ "${loss_percent}" =~ ^([0-9]+([.][0-9]+)?)$ ]]; then
      echo "delay and loss must be non-negative numbers" >&2
      exit 2
    fi
    tc qdisc replace dev "${interface}" root netem \
      delay "${delay_ms}ms" 10ms distribution normal \
      loss random "${loss_percent}%"
    tc qdisc show dev "${interface}"
    ;;
  clear)
    tc qdisc del dev "${interface}" root 2>/dev/null || true
    ;;
  *)
    usage
    exit 2
    ;;
esac
