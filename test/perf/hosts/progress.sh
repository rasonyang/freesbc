#!/bin/sh
# The cross-day progress checkpoint (STEPS.md setup steps R00..R09, R18; MEASURE.md measurements M01..M08).
#   progress.sh show                      print the step table
#   progress.sh next                      the first step that is not done
#   progress.sh set ID STATUS "note"      STATUS: todo | done | failed
# File: $PROGRESS, default /opt/freesbc/results/progress.md (on the loadgen host;
# on sbc/switch run it as: ssh loadgen /opt/freesbc/test/perf/hosts/progress.sh ...).
set -eu
f=${PROGRESS:-/opt/freesbc/results/progress.md}
[ -f "$f" ] || { echo "progress.sh: $f not found (provision.sh loadgen creates it)" >&2; exit 1; }
case ${1:-} in
show) grep -E '^[RM][0-9]+ \|' "$f" ;;
next) grep -E '^[RM][0-9]+ \|' "$f" | grep -v '| done |' | head -1 || true ;;
set)
	id=${2:-} st=${3:-} note=${4:-}
	case $st in todo | done | failed) ;; *) echo "status must be todo, done or failed" >&2; exit 2 ;; esac
	grep -q "^$id |" "$f" || { echo "unknown step $id" >&2; exit 2; }
	note=$(printf '%s' "$note" | tr '|\n' '/ ')
	d=$(date +%Y-%m-%d)
	tmp=$(mktemp)
	awk -v id="$id" -v st="$st" -v d="$d" -v n="$note" '
		$1 == id && $2 == "|" { print id " | " st " | " d " | " n; next }
		{ print }' "$f" >"$tmp"
	cat "$tmp" >"$f"
	rm -f "$tmp"
	grep "^$id |" "$f" ;;
*) echo "usage: progress.sh show | next | set ID todo|done|failed \"note\"" >&2; exit 2 ;;
esac
