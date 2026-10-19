#!/bin/bash
# End-of-day report for the 3-host run. Run on the loadgen host (as ecs-user):
#
#   test/perf/hosts/daily-report.sh [YYYY-MM-DD]       default: today
#
# Gathers into /opt/freesbc/results/<date>/:
#   runs/<run>/      summary.txt, metrics.csv, steps.csv, webrtc.log, sipp-*.csv (no pcap, no users.csv)
#   notes/<role>.md  each role's /opt/freesbc/results/<role>/notes.md
#   changes/         unified diff (about 80 lines max) of every kit file the agents modified
#                    (found through the *.orig-* backups under /opt/freesbc/test/perf, on all hosts)
#   logs/            freesbc (journal), FreeSWITCH and Asterisk logs, WARN/ERROR lines, trimmed
#   hosts.txt        instance type, CPU model, kernel, Go, SIPp, FreeSWITCH, Asterisk, freesbc
#   pprof/           profiles taken under STEPS.md R17 (already there) + the freesbc binary
#   summary.md       paste-ready GitHub issue comment (about 150 lines at most)
# and a tarball <date>.tar.gz next to it.
#
#   daily-report.sh --retar [YYYY-MM-DD]   only rebuild the tarball (progress.md refreshed first).
#                                          Run it after the last progress.sh set (R18) and after
#                                          any edit of summary.md, so the tarball is not older. Everything text is scrubbed of IPv4
# public IPv4 addresses (private RFC1918 ones stay) and of key/password material. Nothing is
# uploaded: pull-results.sh (laptop) copies it off; the issue comment is posted
# on the loadgen host with `gh issue comment 109 --body-file summary.md`.
set -u
RETAR=0
if [ "${1:-}" = --retar ]; then RETAR=1; shift; fi
DATE=${1:-$(date +%Y-%m-%d)}
RES=/opt/freesbc/results
D=$RES/$DATE
PERF=/opt/freesbc/test/perf
HERE=$(cd "$(dirname "$0")" && pwd)
STAMP=$(echo "$DATE" | tr -d -)
SSH="ssh -o BatchMode=yes -o ConnectTimeout=10"
# shellcheck disable=SC1091
. "$HERE/plan.env"

note() { echo "[$(date +%H:%M:%S)] $*" >&2; }
if [ "$RETAR" = 1 ]; then
	[ -d "$D" ] || { note "no $D"; exit 1; }
	cp "$RES/progress.md" "$D/progress.md" 2>/dev/null || true
	(cd "$RES" && tar czf "$DATE.tar.gz" "$DATE" progress.md)
	note "tarball rebuilt: $RES/$DATE.tar.gz"
	exit 0
fi
mkdir -p "$D"/runs "$D"/notes "$D"/logs "$D"/pprof "$D"/changes

# ------------------------------------------------------------- runs
for r in "$PERF"/out/"$STAMP"-*; do
	[ -d "$r" ] || continue
	n=$(basename "$r")
	mkdir -p "$D/runs/$n"
	for f in summary.txt metrics.csv steps.csv webrtc.log webrtc.csv m03.tag hostmon-sbc.csv hostmon-loadgen.csv hostmon-switch.csv sbc-cores.txt sbc-lscpu.txt; do
		[ -f "$r/$f" ] && cp "$r/$f" "$D/runs/$n/"
	done
	cp "$r"/sipp-*.csv "$r"/probe-*.log "$r"/probe-*.csv "$D/runs/$n/" 2>/dev/null || true
done

# ------------------------------------------------------------- notes, progress
cp "$RES/progress.md" "$D/progress.md" 2>/dev/null || true
for role in loadgen sbc switch; do
	if [ "$role" = loadgen ]; then
		cp "$RES/loadgen/notes.md" "$D/notes/loadgen.md" 2>/dev/null || true
	else
		$SSH "$role" cat "$RES/$role/notes.md" >"$D/notes/$role.md" 2>/dev/null || rm -f "$D/notes/$role.md"
	fi
done

# ------------------------------------------------------------- kit files the agents modified
# An agent backs a file up as <file>.orig-<date> before its first edit; the backups
# list the changes. Diffs go to changes/<role>-<file>.diff, summary.md only lists files.
: >"$D/changes/list.txt"
for role in loadgen sbc switch; do
	if [ "$role" = loadgen ]; then origs=$(find "$PERF" -name '*.orig-*' -type f 2>/dev/null)
	else origs=$($SSH "$role" "find $PERF -name '*.orig-*' -type f" 2>/dev/null); fi
	for o in $origs; do
		f=${o%.orig-*}
		rel=${f#"$PERF"/}
		echo "$role $rel" >>"$D/changes/list.txt"
		out="$D/changes/$role-$(echo "$rel" | tr / _).diff"
		if [ "$role" = loadgen ]; then diff -u "$o" "$f" 2>&1 | head -80 >"$out"
		else $SSH "$role" "diff -u '$o' '$f'" 2>&1 | head -80 >"$out"; fi
	done
done

# ------------------------------------------------------------- hosts
facts='
echo "role=$(cat /etc/perf-role 2>/dev/null)"
echo "instance_type=$(curl -s --max-time 2 http://100.100.100.200/latest/meta-data/instance/instance-type || echo unknown)"
echo "cpus=$(nproc 2>/dev/null || echo unknown)"
echo "mem_gib=$(awk "/MemTotal/ {printf \"%.1f\", \$2/1048576}" /proc/meminfo 2>/dev/null || echo unknown)"
echo "cpu_model=$(lscpu | sed -n "s/^Model name: *//p" | head -1)"
echo "kernel=$(uname -r)"
echo "go=$(/usr/local/go/bin/go version 2>/dev/null | cut -d" " -f3)"
echo "freesbc=$(/usr/local/bin/freesbc version 2>/dev/null)"
v=$(sipp -v 2>&1 | grep -m1 -i sipp); echo "sipp=${v:-unknown}"
v=$(sudo -n fs_cli -x version 2>/dev/null | grep -m1 -i freeswitch); [ -n "$v" ] || v=$(sudo -n docker exec freeswitch-perf fs_cli -x version 2>/dev/null | grep -m1 -i freeswitch); echo "freeswitch=${v:-unknown}"
v=$(sudo -n asterisk -rx "core show version" 2>/dev/null | grep -m1 -i asterisk); echo "asterisk=${v:-unknown}"
echo "pi=$(pi --version 2>/dev/null | head -1)"
echo "repo_commit=$(cat /opt/freesbc/COMMIT 2>/dev/null || echo unknown)"
echo "rmem_max=$(sysctl -n net.core.rmem_max) wmem_max=$(sysctl -n net.core.wmem_max)"
'
: >"$D/hosts.txt"
for role in loadgen sbc switch; do
	echo "== $role ==" >>"$D/hosts.txt"
	if [ "$role" = loadgen ]; then sh -c "$facts" >>"$D/hosts.txt" 2>&1
	else $SSH "$role" sh -c "'$facts'" >>"$D/hosts.txt" 2>&1; fi
done

# ------------------------------------------------------------- logs (trimmed)
$SSH sbc "sudo journalctl -u freesbc --since '$DATE 00:00:00' --no-pager 2>/dev/null | grep -E 'WARN|ERROR|level=(warn|error)' | tail -300" >"$D/logs/freesbc-warn-error.log" 2>/dev/null
$SSH sbc "sudo journalctl -u freesbc --since '$DATE 00:00:00' --no-pager 2>/dev/null | tail -200" >"$D/logs/freesbc-tail.log" 2>/dev/null
$SSH switch "sudo tail -n 400 /var/log/freeswitch-perf/freeswitch.log 2>/dev/null | grep -E 'WARN|ERR|CRIT|ALERT' | tail -200" >"$D/logs/freeswitch-warn-error.log" 2>/dev/null
$SSH switch "sudo tail -n 200 /var/log/asterisk/messages 2>/dev/null" >"$D/logs/asterisk-tail.log" 2>/dev/null
$SSH sbc "sudo cat /proc/net/snmp | awk '/^Udp:/'" >"$D/logs/sbc-udp-snmp.txt" 2>/dev/null

# pprof files made under R17 are already in $D/pprof; add the matching binary
if ls "$D"/pprof/*.pb.gz >/dev/null 2>&1; then
	scp -q -o BatchMode=yes sbc:/usr/local/bin/freesbc "$D/pprof/freesbc-linux" 2>/dev/null || note "could not copy the freesbc binary"
fi

# ------------------------------------------------------------- scrub
# public IPv4, API keys, password material, hashes.
find "$D" -type f \( -name '*.txt' -o -name '*.diff' -o -name '*.md' -o -name '*.log' -o -name '*.csv' \) | while read -r f; do
	perl -pi -e '
		s/\b(?!10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|255\.|100\.100\.|169\.254\.)(\d{1,3}\.){3}\d{1,3}\b/x.x.x.x/g;
		s/(DEEPSEEK_API_KEY=)\S+/$1REDACTED/g;
		s/(sk-[A-Za-z0-9_-]{8,})/REDACTED/g;
		s/(password[_a-z]*["\x27]?\s*[:=]\s*)\S+/$1REDACTED/gi;
		s/\$2[aby]\$\d\d\$\S+/REDACTED-HASH/g;' "$f"
done

# ------------------------------------------------------------- summary.md
S=$D/summary.md
hostval() { # ROLE KEY
	awk -v r="$1" -v k="$2" '$0 == "== " r " ==" { on = 1; next } /^== / { on = 0 } on && index($0, k "=") == 1 { sub(/^[^=]*=/, ""); print; exit }' "$D/hosts.txt"
}
{
	echo "## 3-host run results $DATE"
	echo
	echo "### Hosts"
	echo
	echo "| role | plan IP | type | vCPU / GiB | CPU | kernel |"
	echo "|---|---|---|---|---|---|"
	for p in "loadgen $A_IP" "sbc $B_PUB_IP / $B_PRIV_IP" "switch $C_IP"; do
		role=${p%% *}; ip=${p#* }
		echo "| $role | $ip | $(hostval "$role" instance_type) | $(hostval "$role" cpus) / $(hostval "$role" mem_gib) | $(hostval "$role" cpu_model) | $(hostval "$role" kernel) |"
	done
	echo
	echo "Versions: go $(hostval sbc go); freesbc \`$(hostval sbc freesbc)\`, repo commit $(hostval loadgen repo_commit); sipp $(hostval loadgen sipp); FreeSWITCH $(hostval switch freeswitch); Asterisk $(hostval switch asterisk). Sysctl rmem/wmem_max: $(hostval sbc rmem_max)."
	echo
	echo "### Steps today"
	echo
	t=$(grep -E "^[RM][0-9]+ \\| (done|failed) \\| $DATE " "$D/progress.md" 2>/dev/null)
	if [ -n "$t" ]; then printf '%s\n' "$t" | sed 's/^/- /'; else echo "- none recorded"; fi
	echo
	echo "### Key numbers"
	echo
	nrun=0
	for r in "$D"/runs/*/; do
		[ -f "$r/summary.txt" ] || continue
		nrun=$((nrun + 1)); [ $nrun -le 8 ] || break
		echo "**$(basename "$r")**"
		echo '```'
		grep -E '^(calls_created|cps_median|rt_p95_bucket|retransmissions|plateau_calls_avg|plateau_cpu|plateau_rss|plateau_rtp|cpu_avg_pct|rss_peak|udp_rcvbuf|invite_rejects|admission_drops|shield_drops|port_alloc|max sustained|calls_attempted|reg_ok|setup_p50|rtp_sent)|^RESULT ' "$r/summary.txt" |
			sed 's/^RESULT //' | head -12
		echo '```'
	done
	[ $nrun -gt 0 ] || echo "No run directories for $DATE under test/perf/out."
	echo
	echo "### Run verdicts (runcheck.sh)"
	echo
	echo '```'
	"$HERE/runcheck.sh" "$D"/runs/*/ 2>&1 | grep -v '^PASS' | head -40
	"$HERE/runcheck.sh" "$D"/runs/*/ >/dev/null 2>&1 && echo "no FAIL: every run has complete SIPp stats and passes its criteria" || echo "FAIL present: see lines above (an aborted SIPp counts as a failure)"
	echo '```'
	for r in "$D"/runs/*/; do
		[ -f "$r/m03.tag" ] || continue
		echo
		"$HERE/m03-table.sh" "$r" 2>/dev/null
	done
	echo
	if [ -s "$RES/$DATE/measure-results.md" ]; then
		echo
		echo "### Measurements recorded by the agent"
		echo
		head -60 "$RES/$DATE/measure-results.md"
	fi
	echo
	echo "### Problems found"
	echo
	p=$(grep -h '^PROBLEM' "$D"/notes/*.md 2>/dev/null)
	f=$(grep -E "^[RM][0-9]+ \\| failed \\|" "$D/progress.md" 2>/dev/null)
	if [ -n "$p$f" ]; then
		[ -z "$f" ] || printf '%s\n' "$f" | sed 's/^/- failed step: /'
		[ -z "$p" ] || printf '%s\n' "$p" | sed 's/^/- /'
	else echo "- none noted"; fi
	echo "- FreeSBC WARN/ERROR lines today: $(grep -c . "$D/logs/freesbc-warn-error.log" 2>/dev/null || echo 0) (logs/freesbc-warn-error.log)"
	echo "- FreeSWITCH warnings: $(grep -c . "$D/logs/freeswitch-warn-error.log" 2>/dev/null || echo 0) (logs/freeswitch-warn-error.log)"
	echo
	echo "### Changes made by the agents"
	echo
	if [ -s "$D/changes/list.txt" ]; then
		sed 's/^\([a-z]*\) \(.*\)$/- \1: \`\2\` (diff in changes\/)/' "$D/changes/list.txt"
	else echo "- no kit files modified"; fi
	for role in loadgen sbc switch; do
		c=$(awk '/^##+ *changes/ {on=1; next} /^#/ {on=0} on' "$D/notes/$role.md" 2>/dev/null | head -20)
		[ -z "$c" ] || { echo; echo "$role notes (changes):"; printf '%s\n' "$c" | sed 's/^/  /'; }
	done
	echo
	echo "Evidence: \`results/$DATE/\` in the pulled results (runs/, notes/, changes/, logs/, pprof/)."
	echo
	echo "### Next steps (tomorrow)"
	echo
	nx=$("$HERE/progress.sh" show 2>/dev/null | grep -v '| done |' | head -6)
	if [ -n "$nx" ]; then printf '%s\n' "$nx" | sed 's/^/- /'; else echo "- every step is done"; fi
} >"$S"
perl -pi -e 's/\b(?!10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|255\.|100\.100\.|169\.254\.)(\d{1,3}\.){3}\d{1,3}\b/x.x.x.x/g' "$S"

# ------------------------------------------------------------- tarball
(cd "$RES" && tar czf "$DATE.tar.gz" "$DATE" progress.md 2>/dev/null)
lines=$(wc -l <"$S" | tr -d ' ')
note "report: $S ($lines lines), tarball: $RES/$DATE.tar.gz"
[ "$lines" -le 150 ] || note "WARNING: summary.md is $lines lines; trim before pasting"
