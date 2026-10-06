#!/usr/bin/env bash
# Sample switch load on S3 into CSV: active calls and CPU of each switch.
#
#   ./collect.sh results/switch-$(date +%s).csv [interval_s]
# Works with the docker-compose deployment or native installs.
set -uo pipefail
out=${1:?usage: collect.sh <out.csv> [interval]}; iv=${2:-5}
mkdir -p "$(dirname "$out")"
run() { # $1 container  $2.. command
  local c=$1; shift
  if command -v docker >/dev/null && docker inspect "$c" >/dev/null 2>&1; then docker exec "$c" "$@"; else "$@"; fi
}
fs_calls()  { run freeswitch fs_cli -x 'show calls count' 2>/dev/null | awk '/total/ {print $1; exit}'; }
ast_calls() { run asterisk asterisk -rx 'core show channels count' 2>/dev/null | awk '/active call/ {print $1; exit}'; }
cpu() { # summed %CPU of processes named $1
  ps -C "$1" -o %cpu= 2>/dev/null | awk '{s+=$1} END {printf "%.0f", s+0}'
}
[[ -s $out ]] || echo "ts,fs_calls,fs_cpu_pct,ast_calls,ast_cpu_pct,load1" >"$out"
while sleep "$iv"; do
  echo "$(date +%s),$(fs_calls),$(cpu freeswitch),$(ast_calls),$(cpu asterisk),$(cut -d' ' -f1 /proc/loadavg)" >>"$out"
done
