#!/bin/bash
# Step a load up one run at a time until a limit is hit. Run it on the loadgen host (A) from
# /opt/freesbc, in a shell where `. test/perf/hosts/env.sh sipp|fs` was sourced, under nohup/tmux:
#
#   nohup test/perf/hosts/ladder.sh NAME "RUN_ARGS" N1 N2 N3 ... > results/ladder-NAME.log 2>&1 &
#
#   NAME      label of the ladder, for example m02
#   RUN_ARGS  run.sh arguments; every @N@ is replaced by the current value, for example
#             "-c @N@ -H 60 -t 180 -u @N@ call"
#
# For each value: FreeSBC is restarted with the config of the sourced env (clean RSS, bans,
# bindings; FreeSWITCH registrations flushed), run.sh runs, runcheck.sh judges it, and the plateau
# CPU and RTP tx/rx are read from summary.txt. A value passes when runcheck has no FAIL, the
# plateau CPU of FreeSBC is under CPU_LIMIT_PCT (default 80% of the sbc host's vCPUs x 100, or of
# CORES x 100 when you limited FreeSBC with sbc-cores) and plateau tx/rx is at least 0.999
# (added RTP loss under 0.1%), and rigcheck.sh does not call the run INVALID (generator or switch saturated;
# needs hostmon running on A and C, MEASURE.md). The ladder stops at the first value that does not pass. One line
# per value goes to results/ladder-NAME-<time>.txt, with the run directory, so M02, M05 and M06
# quote the last passing value as the maximum.
set -u
[ $# -ge 3 ] || { sed -n '2,/^set -u/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 2; }
[ -n "${TOPOLOGY:-}" ] && [ -n "${REHEARSAL_SWITCH:-}" ] || { echo "source test/perf/hosts/env.sh sipp|fs first" >&2; exit 2; }
name=$1; args=$2; shift 2
cd /opt/freesbc || exit 1
HOSTS=test/perf/hosts
cores=${CORES:-$(ssh sbc nproc --all)}
limit=${CPU_LIMIT_PCT:-$((cores * 80))}
res=results/ladder-$name-$(date +%H%M).txt
echo "# $name: run.sh $args ; values: $* ; CPU limit ${limit}% (100 = one core) ; switch $REHEARSAL_SWITCH" | tee "$res"
best=none
for n in "$@"; do
	ssh sbc freesbc-use "$([ "$REHEARSAL_SWITCH" = fs ] && echo fs || echo sipp)" >/dev/null || exit 1
	[ "$REHEARSAL_SWITCH" != fs ] || ssh switch 'sudo fs_cli -x "sofia profile perf flush_inbound_reg"' >/dev/null
	a=${args//@N@/$n}
	echo "[$(date +%H:%M:%S)] $name value $n: run.sh $a"
	# shellcheck disable=SC2086
	test/perf/run.sh $a >"results/ladder-$name-$n.log" 2>&1
	run=$(ls -dt test/perf/out/*/ | head -1); run=${run%/}
	verdict=pass
	chk=$("$HOSTS/runcheck.sh" "$run" 2>&1) || verdict=FAIL-run
	cpu=$(grep -o 'plateau_cpu_avg_pct=[0-9]*' "$run/summary.txt" | head -1 | cut -d= -f2)
	txrx=$(grep -o 'plateau_tx_over_rx=[0-9.]*' "$run/summary.txt" | head -1 | cut -d= -f2)
	calls=$(grep -o 'plateau_calls_avg=[0-9]*' "$run/summary.txt" | head -1 | cut -d= -f2)
	[ -n "$cpu" ] || cpu=$(grep -o '^cpu_avg_pct=[0-9.]*' "$run/summary.txt" | head -1 | cut -d= -f2 | sed 's/\..*//')   # no plateau block: whole-run average
	rig=$("$HOSTS/rigcheck.sh" "$run" "$limit" 2>&1) || verdict=FAIL-rig
	if [ "$verdict" = pass ]; then
		[ -n "$cpu" ] || verdict=FAIL-nocpu
		[ "${cpu:-0}" -lt "$limit" ] || verdict=FAIL-cpu
		awk -v x="${txrx:-1}" 'BEGIN { exit !(x + 0 < 0.999) }' && verdict=FAIL-loss
	fi
	echo "$n $verdict plateau_calls=${calls:-?} cpu_avg_pct=${cpu:-?} tx_over_rx=${txrx:-?} run=$run" | tee -a "$res"
	[ "$verdict" = pass ] || { printf '%s\n%s\n' "$rig" "$chk" | grep -E '^(FAIL|WARN|INVALID)' | sed 's/^/  /' | tee -a "$res"; break; }
	best=$n
done
echo "max passing value: $best" | tee -a "$res"
