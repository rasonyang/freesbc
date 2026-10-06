#!/usr/bin/env bash
# Summarise RTP quality in a capture taken on S1 (audio FreeSBC sent to SIPp).
#
#   ./rtp_report.sh results/<run>/rtp.pcap
#
# Prints tshark's per-stream table, then one line: streams, packets, lost %,
# worst max-delta and the 99th percentile of per-stream max jitter. With the
# switch echoing (T1/T3) this is the round trip SIPp -> FreeSBC -> switch ->
# FreeSBC -> SIPp; with a bridge (T2/T4) it is one direction of the call.
# Streams cut by the capture window show as short, not as loss.
set -euo pipefail
pcap=${1:?usage: rtp_report.sh <pcap>}
table=$(tshark -r "$pcap" -q -n -o rtp.heuristic_rtp:TRUE -z rtp,streams)
echo "$table"
# Data rows: ... Payload Pkts Lost (pct%) MinDelta MeanDelta MaxDelta MinJitter MeanJitter MaxJitter
rows=$(echo "$table" | awk '
  { for (i = 1; i <= NF; i++) if ($i ~ /^\(-?[0-9.]+%\)$/) { li = i; break }
    if (li && NF >= li + 6) print $(li - 2), $(li - 1), $(li + 3), $(li + 6); li = 0 }')
[[ -n $rows ]] || { echo "no RTP streams found"; exit 1; }
n=$(wc -l <<<"$rows")
p99=$(awk '{print $4}' <<<"$rows" | sort -n | awk -v n="$n" 'NR == (int(0.99 * n) > 0 ? int(0.99 * n) : 1)')
awk -v p99="$p99" '
  { n++; pk += $1; lost += ($2 > 0 ? $2 : 0); if ($3 > md) md = $3 }
  END { printf "streams=%d packets=%d lost=%d (%.4f%%) worst_max_delta_ms=%.1f p99_max_jitter_ms=%.2f\n",
        n, pk, lost, (pk ? 100 * lost / (pk + lost) : 0), md, p99 }' <<<"$rows"
