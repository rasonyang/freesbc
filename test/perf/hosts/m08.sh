#!/bin/bash
# M08: the soak. Run on A from /opt/freesbc under nohup or tmux:
#
#   . test/perf/hosts/env.sh sipp
#   nohup test/perf/hosts/m08.sh CALLS [HOURS] > results/m08.log 2>&1 &     # CALLS = 70% of the M02 maximum
#   test/perf/hosts/m08.sh --report RUN_DIR                                  # after it ended: soak-report.md
#
# Starts FreeSBC clean on the sbc host (all cores), hostmon on B (60 s), then
#   run.sh -i 30 -c CALLS -H 240 -t HOURS*3600 -u CALLS call
# (hold 240 s, under the 300 s the pcap/silence-watchdog pair is good for; metrics every 30 s),
# and an hourly goroutine and heap snapshot from the admin API into results/<date>/soak/. When the run
# ends it writes soak-report.md in the run directory (soakcheck.sh, runcheck.sh, call-end
# reasons). Pass: no growth over 5% between the first and last quarter of goroutines, RSS,
# open fds and ports in use, ports back to 0, failed calls under 0.1%, no aborted SIPp.
# Default HOURS is 8.
set -u
HOSTS=/opt/freesbc/test/perf/hosts
report() { # RUN_DIR
	local run=$1 f=$1/soak-report.md
	{
		echo "## M08 soak report"
		echo
		echo '```'
		head -3 "$run/summary.txt" | sed -n 1,3p
		grep -E '^(calls_created|elapsed_s|cpu_avg_pct|rss_|goroutines_|open_fds_|media_ports|active_calls_peak|invite_rejects|admission_drops|udp_rcvbuf_errors|port_alloc|plateau_)' "$run/summary.txt" | head -30
		echo '```'
		echo
		echo "Growth check (first quarter vs last quarter, 10 min ramp skipped):"
		echo '```'
		"$HOSTS/soakcheck.sh" "$run" 10
		echo '```'
		echo
		echo "Generator and switch CPU (rigcheck):"
		echo '```'
		"$HOSTS/rigcheck.sh" "$run" 2>&1 || true
		echo '```'
		echo
		echo "Run verdict:"
		echo '```'
		"$HOSTS/runcheck.sh" "$run"
		echo '```'
		[ ! -f "$run/soak-ended.txt" ] || { echo; echo "Calls ended, by reason, and refusals at the end:"; echo '```'; cat "$run/soak-ended.txt"; echo '```'; }
	} >"$f"
	echo "$f"
}
if [ "${1:-}" = --report ]; then report "${2:?RUN_DIR}"; exit 0; fi
calls=${1:?usage: m08.sh CALLS [HOURS] | --report RUN_DIR}
hours=${2:-8}
[ -n "${TOPOLOGY:-}" ] || { echo "source test/perf/hosts/env.sh sipp first" >&2; exit 2; }
cd /opt/freesbc || exit 1
say() { echo "[$(date +%H:%M:%S)] $*"; }
d=results/$(date +%F)/soak
mkdir -p "$d"
ssh sbc sudo sbc-cores all >/dev/null
ssh sbc freesbc-use sipp >/dev/null
tag=$(date +%H%M%S)
ssh sbc "nohup $HOSTS/hostmon.sh /tmp/m08-$tag.csv 60 freesbc >/dev/null 2>&1 </dev/null &"
(
	# hourly snapshots; ends with the run
	while sleep 3600; do
		s=$(date +%H%M)
		ssh sbc "curl -s -u admin:perf 'localhost:8081/debug/pprof/goroutine?debug=1'" | head -40 >"$d/goroutine-$s.txt"
		ssh sbc "curl -s -u admin:perf -o /tmp/heap-$s.pb.gz 'localhost:8081/debug/pprof/heap'" && scp -q "sbc:/tmp/heap-$s.pb.gz" "$d/heap-$s.pb.gz"
	done
) &
snap=$!
say "soak: $calls concurrent calls, hold 240 s, $hours h"
t0=$(date +%s)
test/perf/run.sh -i 30 -c "$calls" -H 240 -t $((hours * 3600)) -u "$calls" call
say "run.sh ended after $(( $(date +%s) - t0 )) s"
kill "$snap" 2>/dev/null
run=$(ls -dt test/perf/out/*-call/ | head -1); run=${run%/}
ssh sbc "pkill -f '^python3 -I - /tmp/m08-$tag\.csv'" || true
scp -q "sbc:/tmp/m08-$tag.csv" "$run/hostmon-sbc.csv" || true
ssh sbc "curl -s -u admin:perf localhost:8081/metrics | grep -E '^freesbc_edge_(calls_ended|invite_rejects|admission_drops)_total'" >"$run/soak-ended.txt" 2>&1
cp "$d"/* "$run"/ 2>/dev/null || true
printf 'calls=%s hours=%s hold=240\n' "$calls" "$hours" >"$run/m08.tag"
report "$run"
