#!/usr/bin/env bash
# Sample FreeSBC and host counters on S2 into one CSV row per interval.
#
#   ./collect.sh results/sbc-$(date +%s).csv [interval_s]
#
# Reads sbc.env (admin address and password, the two bind IPs). Gauges are
# written as is; counters are written raw (diff them in analysis), except
# CPU and per-NIC packets, which are rates over the interval.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/sbc.env"
out=${1:?usage: collect.sh <out.csv> [interval]}
iv=${2:-5}
mkdir -p "$(dirname "$out")"

ifname() { ip -o -4 addr show | awk -v a="$1" '{split($4,p,"/"); if (p[1]==a) print $2}' | head -1; }
pub_if=$(ifname "$SBC_PUBLIC_BIND"); priv_if=$(ifname "$SBC_PRIVATE_IP")
[[ -n $pub_if && -n $priv_if ]] || { echo "cannot find interfaces for $SBC_PUBLIC_BIND / $SBC_PRIVATE_IP" >&2; exit 1; }
hz=$(getconf CLK_TCK)

nic() { echo "$(cat /sys/class/net/"$1"/statistics/rx_packets) $(cat /sys/class/net/"$1"/statistics/tx_packets)"; }
udp() { # InDatagrams NoPorts InErrors RcvbufErrors SndbufErrors, matched by name
  awk '/^Udp:/ { n++; if (n == 1) for (i = 2; i <= NF; i++) col[$i] = i; else
         print $col["InDatagrams"], $col["NoPorts"], $col["InErrors"], $col["RcvbufErrors"], $col["SndbufErrors"] }' /proc/net/snmp
}
cpu_ticks() { awk '{print $14+$15}' "/proc/$1/stat"; }

metrics_keys=(
  freesbc_active_calls freesbc_active_sip_dialogs freesbc_active_media_sessions
  freesbc_active_registrations freesbc_media_ports_in_use freesbc_media_ports_total
  'freesbc_sip_requests_total' 'freesbc_sip_responses_total{class="4xx"}'
  'freesbc_sip_responses_total{class="5xx"}' 'freesbc_shield_drops_total{reason="rate"}'
  'freesbc_shield_drops_total{reason="scanner"}' 'freesbc_shield_drops_total{reason="banned"}'
  'freesbc_edge_admission_drops_total{reason="invite_not_admitted"}'
  'freesbc_edge_admission_drops_total{reason="register_enumeration"}'
  freesbc_media_port_allocation_failure_total freesbc_sip_handler_panics_total
  freesbc_rtp_packets_rx_total freesbc_rtp_packets_tx_total
  go_goroutines go_memstats_heap_inuse_bytes
)
# A key without labels sums every series of that name (requests over methods).
scrape() {
  curl -fsS -u "admin:$SBC_ADMIN_PASSWORD" "http://$SBC_ADMIN/metrics" | awk -v keys="${metrics_keys[*]}" '
    BEGIN { n = split(keys, k, " ") }
    /^#/ { next }
    { name = $1; base = name; sub(/\{.*/, "", base)
      for (i = 1; i <= n; i++) if (k[i] == name || (k[i] == base && index(k[i], "{") == 0)) v[i] += $2 }
    END { for (i = 1; i <= n; i++) printf "%s%s", (i > 1 ? "," : ""), (i in v ? v[i] : 0); print "" }'
}

hdr="ts,cpu_pct,rss_kb"
for k in "${metrics_keys[@]}"; do hdr+=",$(echo "$k" | tr -d '"{}' | tr '=' '_')"; done
hdr+=",udp_in,udp_noports,udp_inerr,udp_rcvbuf_err,udp_sndbuf_err,pub_rx_pps,pub_tx_pps,priv_rx_pps,priv_tx_pps"
[[ -s $out ]] || echo "$hdr" >"$out"

pid=$(pgrep -xo freesbc)
prev_t=$(cpu_ticks "$pid"); read -r prx ptx < <(nic "$pub_if"); read -r vrx vtx < <(nic "$priv_if")
while sleep "$iv"; do
  pid=$(pgrep -xo freesbc) || { echo "$(date +%s),freesbc not running" >>"$out"; continue; }
  t=$(cpu_ticks "$pid"); rss=$(awk '/VmRSS/ {print $2}' "/proc/$pid/status")
  read -r arx atx < <(nic "$pub_if"); read -r brx btx < <(nic "$priv_if")
  m=$(scrape || echo "scrape-failed")
  echo "$(date +%s),$(( (t - prev_t) * 100 / hz / iv )),$rss,$m,$(udp | tr ' ' ','),$(( (arx - prx) / iv )),$(( (atx - ptx) / iv )),$(( (brx - vrx) / iv )),$(( (btx - vtx) / iv ))" >>"$out"
  prev_t=$t prx=$arx ptx=$atx vrx=$brx vtx=$btx
done
