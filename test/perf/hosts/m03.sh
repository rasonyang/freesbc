#!/bin/bash
# M03, the competitor scenario, as one reproducible command. Run it on the loadgen host (A)
# under nohup or tmux (it takes about 31 minutes), from /opt/freesbc:
#
#   nohup test/perf/hosts/m03.sh CORES SWITCH > /opt/freesbc/results/m03-CORES-SWITCH.log 2>&1 &
#
#   CORES   all | 2 | 1 | ...   FreeSBC CPU limit (all = the 4 vCPU of B) (ssh sbc sbc-cores), restarts freesbc
#   SWITCH  sipp | fs           the switch behind FreeSBC (fs = real FreeSWITCH)
#
# The competitor's published test: 50 calls per second offered, 1000 concurrent, each call 600 s.
# run.sh -r 50 -c 900 -H 600 -t 40 -u 2000 call does this: SIPp offers 50 CPS, its concurrency cap
# is 900 + 10% + 10 = 1000 (run.sh adds that margin to -c), so the 1000 calls are up after about
# 20 s; then new calls start only as old ones end (about 1.7 CPS) until 2000 calls were made,
# which keeps the plateau at 1000 for two holds (about 1200 s). G.711 media both ways on both legs
# (the SIPp pcap is generated for the 600 s hold). A run is about 1820 s.
# Beside it: hostmon on B (whole host), A and C (is the generator or the switch the limit?), and
# three 120 s webrtcload probe batches (20 calls each) inside the plateau for loss and jitter
# (SIPp does not measure received RTP). The run directory gets m03.tag, probe-N.log/.csv and
# hostmon-{sbc,loadgen,switch}.csv; daily-report.sh and m03-table.sh read them.
set -u
cores=${1:-}; sw=${2:-}
case $sw in sipp | fs) ;; *) sed -n '2,/^set -u/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 2 ;; esac
[ -n "$cores" ] || exit 2
cd /opt/freesbc || exit 1
HOSTS=/opt/freesbc/test/perf/hosts
# shellcheck disable=SC1091
. "$HOSTS/env.sh" "$sw" || exit 1
say() { echo "[$(date +%H:%M:%S)] $*"; }

say "FreeSBC cores=$cores switch=$sw"
ssh sbc sudo sbc-cores "$cores" || exit 1
ssh sbc freesbc-use "$([ "$sw" = fs ] && echo fs || echo sipp)" || exit 1
[ "$sw" != fs ] || ssh switch 'sudo fs_cli -x "sofia profile perf flush_inbound_reg"' >/dev/null
tag=$(date +%H%M%S)
ssh sbc "nohup $HOSTS/hostmon.sh /tmp/m03-$tag.csv 5 freesbc >/dev/null 2>&1 </dev/null &"
nohup "$HOSTS/hostmon.sh" "/tmp/m03-$tag.csv" 5 sipp,webrtcload >/dev/null 2>&1 </dev/null &
ssh switch "nohup $HOSTS/hostmon.sh /tmp/m03-$tag.csv 5 sipp,freeswitch >/dev/null 2>&1 </dev/null &"
sleep 6

t0=$(date +%s)
test/perf/run.sh -r 50 -c 900 -H 600 -t 40 -u 2000 call &
rp=$!
for _ in $(seq 60); do
	run=$(ls -dt test/perf/out/*-call 2>/dev/null | head -1)
	[ -n "$run" ] && [ "$(stat -c %Y "$run")" -ge "$t0" ] && break
	sleep 2
done
say "run dir $run"
# probes inside the plateau: 300 s, 700 s and 1000 s after the run started
(
	n=0
	for off in 300 700 1000; do
		n=$((n + 1))
		sleep $((t0 + off - $(date +%s)))
		say "probe $n"
		webrtcload -target "ws://$SBC_PUBLIC:8080" -users 20 -conns 2 -rate 5 -calls 20 -hold 120s \
			-out "$run/probe-$n.csv" >"$run/probe-$n.log" 2>&1
	done
) &
pp=$!
wait $rp
wait $pp
say "run finished"
pkill -f "^python3 -I - /tmp/m03-$tag\.csv" || true
ssh sbc "pkill -f '^python3 -I - /tmp/m03-$tag\.csv'" || true
ssh switch "pkill -f '^python3 -I - /tmp/m03-$tag\.csv'" || true
sleep 1
scp -q "sbc:/tmp/m03-$tag.csv" "$run/hostmon-sbc.csv"
scp -q "switch:/tmp/m03-$tag.csv" "$run/hostmon-switch.csv"
cp "/tmp/m03-$tag.csv" "$run/hostmon-loadgen.csv"
ssh sbc sbc-cores show >"$run/sbc-cores.txt" 2>&1
ssh sbc 'lscpu | grep -E "Model name|^CPU\(s\)|Thread|MHz"; grep -E "MemTotal" /proc/meminfo; uname -r' >"$run/sbc-lscpu.txt" 2>&1
printf 'cores=%s switch=%s rate=50 cap=1000 hold=600\n' "$cores" "$sw" >"$run/m03.tag"
say "done: $run"
"$HOSTS/runcheck.sh" "$run"
"$HOSTS/rigcheck.sh" "$run"
"$HOSTS/m03-table.sh" "$run"
