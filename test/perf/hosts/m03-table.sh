#!/bin/bash
# Side-by-side table for one finished M03 run directory (written by m03.sh):
#
#   test/perf/hosts/m03-table.sh RUN_DIR
#
# Competitor column: its published figures (Xeon X5670 6C/12T 2.93 GHz, 8 GB, Debian 10, kernel 4.19):
# 50 CPS, 1000 concurrent, 600 s, Used Memory 1730M, "CPU Load 26%". How it defined CPU is not
# stated; here two definitions are given, both averaged over the plateau (calls >= 90% of peak):
# whole-host CPU% (100 = all vCPUs busy, from hostmon on B) and the load average.
set -u
d=${1:?usage: m03-table.sh RUN_DIR}
[ -f "$d/m03.tag" ] && [ -f "$d/summary.txt" ] || { echo "m03-table.sh: $d is not a finished M03 run" >&2; exit 2; }
tag=$(cat "$d/m03.tag")
sum=$d/summary.txt
kv() { grep -o "$1=[^ ]*" "$sum" | head -1 | cut -d= -f2; }
mainv() { awk -v k="$1" '/^--- SIPp main/ {on=1; next} /^--- / {on=0} on { for (i=1;i<=NF;i++) if (index($i, k "=")==1) { sub(/^[^=]*=/, "", $i); print $i; exit } }' "$sum"; }
read -r w0 w1 < <(awk -F, 'NR==1 {for(i=1;i<=NF;i++)c[$i]=i; next} {n++; t[n]=$c["ts"]; a[n]=$c["active_calls"]+0; if(a[n]>p)p=a[n]} END {for(i=1;i<=n;i++) if(a[i]>=0.9*p){if(!s)s=t[i]; e=t[i]} print s+0, e+0}' "$d/metrics.csv")
host=$(awk -F, -v s="$w0" -v e="$w1" 'NR==1 {for(i=1;i<=NF;i++)c[$i]=i; next} $c["ts"]>=s && $c["ts"]<=e {n++; cpu+=$c["cpu_pct"]; l1+=$c["load1"]; if($c["mem_used_mb"]>m)m=$c["mem_used_mb"]; if($c["cpu_max_core_pct"]>mc)mc=$c["cpu_max_core_pct"]; l5=$c["load5"]; l15=$c["load15"]; } END {if(n) printf "%.1f %.2f %.2f %.2f %d %.0f", cpu/n, l1/n, l5, l15, m, mc; else print "n/a n/a n/a n/a n/a n/a"}' "$d/hostmon-sbc.csv" 2>/dev/null)
read -r hcpu hl1 hl5 hl15 hmem hmaxc <<<"$host"
probe=$(cat "$d"/probe-*.log 2>/dev/null | awk '/^RESULT rtp_sent=/ { for(i=2;i<=NF;i++){split($i,a,"="); v[a[1]]+=a[2]; if(a[1]=="jitter_p99_ms"&&a[2]>mx)mx=a[2]; if(a[1]=="rtt_p50_ms"&&a[2]>rt)rt=a[2]} n++ } END { if(n) printf "loss %.3f%% (sent %d, echoed %d, seq gaps %d); jitter mean %.2f ms, worst-batch p99 %.2f ms; rtt p50 %.1f ms", (v["rtp_sent"]? (v["rtp_sent"]-v["rtp_echoed"])/v["rtp_sent"]*100:0), v["rtp_sent"], v["rtp_echoed"], v["seq_gap_lost"], v["jitter_mean_ms"]/n, mx, rt; else print "no probe results" }')
echo "### M03 competitor scenario ($tag)"
echo
echo "| | Competitor (X5670 6C/12T, 8 GB, Debian 10) | FreeSBC (this run) |"
echo "|---|---|---|"
echo "| Offered CPS | 50 | 50 (SIPp cps_max $(mainv cps_max)); the cap holds the rest |"
echo "| Concurrent calls | 1000 | plateau avg $(kv plateau_calls_avg), peak $(kv active_calls_peak) |"
echo "| Call duration | 600 s | 600 s (G.711 both ways, both legs) |"
echo "| Memory | Used Memory 1730M | FreeSBC RSS max $(kv plateau_rss_max_mb) MB; whole host used max $hmem MB (hostmon, plateau) |"
echo "| CPU | \"CPU Load 26%\" (definition not stated) | whole host $hcpu% avg over plateau (100 = all vCPUs; busiest core max $hmaxc%); FreeSBC process $(kv plateau_cpu_avg_pct)% (100 = one core) |"
echo "| Load average | not published | 1 min avg $hl1 over plateau; at plateau end 5 min $hl5, 15 min $hl15 |"
echo "| Failed calls | not published | $(mainv calls_failed) of $(mainv calls_created) ($(mainv failed_pct)%) |"
echo "| INVITE to 200 p95 | not published | $(mainv rt_p95_bucket_ms) (SIPp bucket upper bound) |"
echo "| RTP loss / jitter | not published | FreeSBC tx/rx $(kv plateau_tx_over_rx), udp_rcvbuf_errors $(kv udp_rcvbuf_errors); probe: $probe |"
echo
echo "FreeSBC cores: $(head -c 200 "$d/sbc-cores.txt" 2>/dev/null | sed -n 1p). B: $(tr '\n' ';' <"$d/sbc-lscpu.txt" 2>/dev/null)"
echo
echo "Setting: B has 4 vCPU (2 cores + Hyper-Threading), well below the competitor's X5670 with 6 cores / 12 threads, so this is a harder setting than theirs. OS differs: this rig runs Ubuntu 24.04 (kernel as above), the competitor Debian 10 with kernel 4.19 (EOL, so not used here)."
