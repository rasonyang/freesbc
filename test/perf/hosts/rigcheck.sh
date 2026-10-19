#!/bin/bash
# "The generator is not the bottleneck" check for one finished run (MEASURE.md, section 0):
#
#   test/perf/hosts/rigcheck.sh RUN_DIR [LIMIT_PCT]      run on A; LIMIT_PCT = FreeSBC's 80% limit, default 80 x nproc of B
#
# Reads the hostmon csv files of A and C for the run's time window (RUN_DIR/hostmon-loadgen.csv and
# hostmon-switch.csv from m03.sh, else the day files /var/tmp/day-loadgen.csv on A and /var/tmp/day-switch.csv
# on C). Prints per host: peak total CPU (100 = all vCPUs), and the peak CPU of the busiest sipp /
# webrtcload process (100 = one core) and freeswitch. The run is INVALID (exit 1) when
#   - any single sipp or webrtcload process reaches 90% of one core (SIPp is mostly single-threaded: a CPS knee
#     above about 1 to 2k CPS may be SIPp's, not FreeSBC's), or
#   - total CPU of A or C exceeds 80% while FreeSBC itself stayed below its limit (plateau or whole-run
#     cpu_avg_pct from summary.txt).
# INVALID means: do not quote it as FreeSBC's figure. Spread the load over more SIPp instances / source IPs
# (run.sh starts one generator process; see MEASURE.md) or use a lower step, and say so in the report.
set -u
d=${1:?usage: rigcheck.sh RUN_DIR [LIMIT_PCT]}
limit=${2:-$(( $(ssh sbc nproc --all 2>/dev/null || echo 4) * 80 ))}
[ -f "$d/metrics.csv" ] || { echo "no $d/metrics.csv" >&2; exit 2; }
t0=$(awk -F, 'NR==2 {print $1; exit}' "$d/metrics.csv"); t1=$(awk -F, 'END {print $1}' "$d/metrics.csv")
sbc=$(grep -o 'plateau_cpu_avg_pct=[0-9]*' "$d/summary.txt" 2>/dev/null | head -1 | cut -d= -f2)
[ -n "$sbc" ] || sbc=$(grep -o '^cpu_avg_pct=[0-9.]*' "$d/summary.txt" 2>/dev/null | head -1 | cut -d= -f2 | sed 's/\..*//')
sbc=${sbc:-0}
rc=0
tmp=$(mktemp)
for h in loadgen switch; do
	f=$d/hostmon-$h.csv
	if [ ! -f "$f" ]; then
		if [ "$h" = loadgen ]; then cp /var/tmp/day-loadgen.csv "$tmp" 2>/dev/null || { echo "WARN  $h: no hostmon csv"; continue; }
		else ssh switch cat /var/tmp/day-switch.csv >"$tmp" 2>/dev/null || { echo "WARN  $h: no hostmon csv"; continue; }; fi
		f=$tmp
	fi
	out=$(awk -F, -v a="$t0" -v b="$t1" -v h="$h" -v sbc="$sbc" -v lim="$limit" '
		NR==1 { for (i=1;i<=NF;i++) c[$i]=i; next }
		$1>=a && $1<=b { n++; if ($c["cpu_pct"]>tot) tot=$c["cpu_pct"]
			for (k in c) if (k ~ /_maxproc_cpu_pct$/ && $c[k]+0 > mp[k]) mp[k]=$c[k]+0 }
		END {
			if (!n) { print "WARN  " h ": no hostmon samples in the run window"; exit }
			bad = 0; line = sprintf("%s: peak total CPU %.0f%%", h, tot)
			for (k in mp) { line = line sprintf(", busiest %s %d%% of a core", substr(k,1,length(k)-length("_maxproc_cpu_pct")), mp[k]); if (k ~ /^(sipp|webrtcload)_/ && mp[k] >= 90) { bad = 1; why = why " " k "=" mp[k] } }
			if (tot > 80 && sbc < lim) { bad = 1; why = why " total_cpu=" tot "% while FreeSBC at " sbc " < limit " lim }
			print (bad ? "INVALID  " : "OK  ") line (bad ? "  <-" why : "")
			exit bad
		}' "$f") || rc=1
	echo "$out"
done
rm -f "$tmp"
[ $rc -eq 0 ] || echo "INVALID: the generator or the switch limited this run, not FreeSBC. Do not quote it as FreeSBC's figure."
exit $rc
