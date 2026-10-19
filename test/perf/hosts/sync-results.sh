#!/bin/bash
# Run from the laptop. Periodic, read-only sync of everything needed to continue a run after a host
# reboot or a spot reclaim. Nothing is ever pushed to, deleted on or changed on the hosts.
#
#   test/perf/hosts/sync-results.sh [-d local-dir]             one tick
#   test/perf/hosts/sync-results.sh --install [-d local-dir]   run a tick every 10 minutes (launchd)
#   test/perf/hosts/sync-results.sh --uninstall                stop and remove the launchd job
#   test/perf/hosts/sync-results.sh --status [-d local-dir]    launchd state and the last sync.log lines
#
#   -d  local directory, outside the repo                      [~/freesbc-perf-results]
#   env HOST_A, HOST_B, HOST_C  ssh aliases of loadgen, sbc, switch   [ecs-A, ecs-B, ecs-C]
#
# One tick, per host and independent of the others (a host that is down logs one line and the tick
# goes on; it exits 0 unless every host failed):
#   results   pull-results.sh -r <role>: A's /opt/freesbc/results/ to <dir>/, B and C's role subtree
#             to <dir>/hosts/sbc and <dir>/hosts/switch
#   out       A only: /opt/freesbc/test/perf/out/ to <dir>/hosts/loadgen-out/, without *.pcap
#   kit       /opt/freesbc/test/perf/ (minus out/) to <dir>/kit/<role>/, so on-host edits and their
#             *.orig-<date> backups survive; no --delete, so a recreated host never wipes the
#             snapshot of its predecessor's edits
# Each tick appends one line per step to <dir>/sync.log (trimmed to its last 2000 lines when over
# 1 MB). A lock directory keeps ticks from overlapping; a lock older than 30 minutes is broken.
set -eu
dir=$HOME/freesbc-perf-results
mode=tick
label=com.freesbc.perf-sync
plist=$HOME/Library/LaunchAgents/$label.plist
while [ $# -gt 0 ]; do
	case $1 in
	-d) dir=$2; shift 2 ;;
	--install) mode=install; shift ;;
	--uninstall) mode=uninstall; shift ;;
	--status) mode=status; shift ;;
	-h | --help) sed -n '2,/^set -eu/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done
hostA=${HOST_A:-ecs-A}
hostB=${HOST_B:-ecs-B}
hostC=${HOST_C:-ecs-C}
sshopt="-o BatchMode=yes -o ConnectTimeout=10"
here=$(cd "$(dirname "$0")" && pwd)
self=$here/$(basename "$0")

if [ "$mode" = uninstall ]; then
	launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
	rm -f "$plist"
	echo "removed $label"
	exit 0
fi

mkdir -p "$dir"
top=$(cd "$here" && git rev-parse --show-toplevel 2>/dev/null || true)
real=$(cd "$dir" && pwd)
case $real in
"$top" | "$top"/*) [ -z "$top" ] || { echo "refusing: $dir is inside the repo; pick a directory outside it" >&2; exit 2; } ;;
esac
dir=$real

if [ "$mode" = status ]; then
	launchctl print "gui/$(id -u)/$label" 2>/dev/null | grep -E '^\s*(state|last exit code|runs|run interval) ' || echo "$label is not loaded"
	echo "--- last 10 lines of $dir/sync.log"
	tail -n 10 "$dir/sync.log" 2>/dev/null || echo "(no sync.log yet)"
	exit 0
fi

if [ "$mode" = install ]; then
	mkdir -p "$(dirname "$plist")"
	cat >"$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>$label</string>
	<key>ProgramArguments</key>
	<array>
		<string>/bin/bash</string>
		<string>$self</string>
		<string>-d</string>
		<string>$dir</string>
	</array>
	<key>StartInterval</key>
	<integer>600</integer>
	<key>RunAtLoad</key>
	<true/>
	<key>StandardOutPath</key>
	<string>$dir/sync.launchd.log</string>
	<key>StandardErrorPath</key>
	<string>$dir/sync.launchd.log</string>
	<key>EnvironmentVariables</key>
	<dict>
		<key>PATH</key>
		<string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
		<key>HOME</key>
		<string>$HOME</string>
	</dict>
</dict>
</plist>
PLIST
	launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
	launchctl bootstrap "gui/$(id -u)" "$plist"
	echo "installed $plist (every 10 minutes, and at login), syncing to $dir"
	echo "check:   $self --status -d $dir"
	echo "remove:  $self --uninstall"
	exit 0
fi

# --- one tick ---
log=$dir/sync.log
lock=$dir/.sync.lock
if ! mkdir "$lock" 2>/dev/null; then
	if [ -n "$(find "$lock" -maxdepth 0 -mmin +30 2>/dev/null)" ]; then
		rmdir "$lock" 2>/dev/null || true
		mkdir "$lock" 2>/dev/null || { echo "another tick holds the lock" >&2; exit 0; }
	else
		echo "another tick is running (lock $lock); skipping" >&2
		exit 0
	fi
fi
trap 'rmdir "$lock" 2>/dev/null || true' EXIT

note() { # STEP HOST STATUS DETAIL
	printf '%s %s %s %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "$2" "$3" "$4" | tee -a "$log"
}

okhosts=0
tick_host() { # HOST ROLE
	local h=$1 r=$2 good=0 msg
	# pull-results.sh in its per-role mode, so one failing host never aborts the others.
	if msg=$(bash "$here/pull-results.sh" -r "$r" -H "$h" -d "$dir" 2>&1); then
		good=1; note results "$h" ok "$(printf '%s' "$msg" | head -n 1)"
	else
		note results "$h" FAIL "$(printf '%s' "$msg" | head -n 1)"
	fi
	if [ "$r" = loadgen ]; then
		mkdir -p "$dir/hosts/loadgen-out"
		if rsync -az -e "ssh $sshopt" --exclude '*.pcap' "$h":/opt/freesbc/test/perf/out/ "$dir/hosts/loadgen-out"/ >/dev/null 2>&1; then
			good=1; note out "$h" ok "hosts/loadgen-out"
		else
			note out "$h" FAIL "rsync of out/ failed"
		fi
	fi
	mkdir -p "$dir/kit/$r"
	if rsync -az -e "ssh $sshopt" --exclude out/ "$h":/opt/freesbc/test/perf/ "$dir/kit/$r"/ >/dev/null 2>&1; then
		good=1; note kit "$h" ok "kit/$r"
	else
		note kit "$h" FAIL "rsync of kit failed"
	fi
	[ "$good" = 1 ] && okhosts=$((okhosts + 1))
	return 0
}

tick_host "$hostA" loadgen
tick_host "$hostB" sbc
tick_host "$hostC" switch

# Keep the log small.
if [ "$(wc -c <"$log")" -gt 1000000 ]; then
	tail -n 2000 "$log" >"$log.tmp" && mv "$log.tmp" "$log"
fi
if [ "$okhosts" -eq 0 ]; then
	echo "$(date '+%Y-%m-%d %H:%M:%S') tick FAIL every host failed" | tee -a "$log" >&2
	exit 1
fi
echo "$(date '+%Y-%m-%d %H:%M:%S') tick done ($okhosts of 3 hosts reachable)" | tee -a "$log"
