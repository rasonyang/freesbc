#!/bin/bash
# Run from the laptop. Copies the run results off the hosts, or puts the latest progress back
# after a recreate.
#
#   test/perf/hosts/pull-results.sh [-H ssh-host] [-d local-dir]           pull from the loadgen host
#   test/perf/hosts/pull-results.sh --all [-d local-dir]                   loadgen, then sbc and switch
#   test/perf/hosts/pull-results.sh -r sbc|switch -H ecs-B|ecs-C [-d dir]  one non-loadgen host
#   test/perf/hosts/pull-results.sh --push [-H ssh-host] [-d local-dir]
#
#   -H  ssh host alias in ~/.ssh/config (user ecs-user)       [ecs-A]
#   -r  the role of that host: loadgen, sbc or switch          [loadgen]
#   -d  local directory, outside the repo                      [~/freesbc-perf-results]
#
# Pull from loadgen: rsync -a ecs-A:/opt/freesbc/results/ into the directory (progress.md, the
# per-day directories and tarballs, loadgen/ notes). Pull from sbc or switch: ONLY that role's
# subtree (/opt/freesbc/results/<role>/) into <dir>/hosts/<role>/, never into the top level, so a
# non-loadgen host can never overwrite progress.md, a day directory or a tarball that came from
# the loadgen host. The role is checked against /etc/perf-role on the host. Nothing is deleted
# locally, so earlier days stay even if a recreated host starts empty.
# Push: after recreating the loadgen host and running provision.sh loadgen, copy progress.md and the
# per-day directories back, so the agent and daily-report.sh continue from where the last session
# stopped. Never overwrites newer files on the host (rsync -u). The daily summary is normally
# posted from the loadgen host (STEPS.md); this script is the backup copy.
set -eu
host=ecs-A
role=loadgen
dir=$HOME/freesbc-perf-results
push=0
all=0
while [ $# -gt 0 ]; do
	case $1 in
	-H) host=$2; shift 2 ;;
	-r) role=$2; shift 2 ;;
	-d) dir=$2; shift 2 ;;
	--push) push=1; shift ;;
	--all) all=1; shift ;;
	-h | --help) sed -n '2,/^set -eu/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done
case $role in loadgen | sbc | switch) ;; *) echo "-r must be loadgen, sbc or switch" >&2; exit 2 ;; esac
# A down host must fail fast (one pull_role error), not hang or prompt.
sshopt="-o BatchMode=yes -o ConnectTimeout=10"
mkdir -p "$dir"
here=$(cd "$(dirname "$0")" && pwd)
top=$(cd "$here" && git rev-parse --show-toplevel 2>/dev/null || true)
real=$(cd "$dir" && pwd)
case $real in
"$top" | "$top"/*) [ -z "$top" ] || { echo "refusing: $dir is inside the repo; pick a directory outside it" >&2; exit 2; } ;;
esac

pull_role() { # HOST ROLE
	local h=$1 r=$2 actual
	# shellcheck disable=SC2086 # sshopt is a word list on purpose
	actual=$(ssh $sshopt "$h" cat /etc/perf-role 2>/dev/null || true)
	if [ -n "$actual" ] && [ "$actual" != "$r" ]; then
		echo "refusing: $h reports role '$actual', not '$r' (wrong -H/-r pair)" >&2
		return 1
	fi
	if [ "$r" = loadgen ]; then
		rsync -az -e "ssh $sshopt" "$h":/opt/freesbc/results/ "$dir"/
		echo "pulled $h (loadgen) to $dir"
	else
		mkdir -p "$dir/hosts/$r"
		rsync -az -e "ssh $sshopt" "$h":/opt/freesbc/results/"$r"/ "$dir/hosts/$r"/
		echo "pulled $h ($r) to $dir/hosts/$r"
	fi
}

if [ "$push" = 1 ]; then
	[ "$role" = loadgen ] || { echo "--push goes to the loadgen host only" >&2; exit 2; }
	rsync -auz -e "ssh $sshopt" --exclude '*.tar.gz' --exclude hosts "$dir"/ "$host":/opt/freesbc/results/
	echo "pushed $dir to $host:/opt/freesbc/results/ (progress.md: $(grep -c '| done |' "$dir/progress.md" 2>/dev/null || echo 0) steps done)"
elif [ "$all" = 1 ]; then
	pull_role ecs-A loadgen
	pull_role ecs-B sbc
	pull_role ecs-C switch
	find "$dir" -maxdepth 1 -mindepth 1 | sort | tail -n 8
else
	pull_role "$host" "$role"
	find "$dir" -maxdepth 1 -mindepth 1 | sort | tail -n 8
fi
