#!/bin/sh
# Limit FreeSBC to its first N CPUs (or lift the limit), then restart it. Runs on the sbc host
# (installed as /usr/local/bin/sbc-cores by provision.sh sbc); the loadgen agent calls it over ssh:
#
#   ssh sbc sudo sbc-cores 2          CPUAffinity=0-1 drop-in, restart freesbc
#   ssh sbc sudo sbc-cores all        remove the drop-in, restart freesbc
#   ssh sbc sbc-cores show            current limit, pid, allowed CPUs, CPU topology
#
# It uses a systemd CPUAffinity= drop-in: the mask is set before freesbc starts, so Go sees only
# those CPUs and sets GOMAXPROCS to N. The NIC's interrupts and softirq work are not pinned and may
# still run on the other CPUs; note this in the report. The restart clears RSS, bans and bindings,
# which is what each M03 repeat wants anyway. N counts vCPUs (logical CPUs), not physical cores:
# on a Hyper-Threaded instance CPUs 0 and 1 may be siblings of one core. `show` prints the topology
# (lscpu -e); quote it in the report. freesbc is left in whatever config freesbc-use chose.
set -eu
conf=/etc/systemd/system/freesbc.service.d/cores.conf
cmd=${1:-}
show() {
	pid=$(pidof freesbc 2>/dev/null | cut -d' ' -f1 || true)
	echo "drop-in: $([ -f "$conf" ] && sed -n 's/^CPUAffinity=/CPUAffinity=/p' "$conf" || echo none)"
	echo "host CPUs: $(nproc --all)"
	if [ -n "$pid" ]; then
		echo "freesbc pid $pid: $(grep Cpus_allowed_list "/proc/$pid/status" | tr -s '\t ' ' ')"
		echo "GOMAXPROCS (via environ, if set): $(tr '\0' '\n' <"/proc/$pid/environ" 2>/dev/null | grep '^GOMAXPROCS=' || echo 'not set: Go uses the affinity mask')"
	else
		echo "freesbc is not running"
	fi
	lscpu -e=CPU,CORE,SOCKET 2>/dev/null | head -40
}
case $cmd in
show) show; exit 0 ;;
all | "" ) [ -n "$cmd" ] || { sed -n '2,/^set -eu/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 2; }
	[ "$(id -u)" -eq 0 ] || exec sudo "$0" "$@"
	rm -f "$conf" ;;
*)
	case $cmd in *[!0-9]*) echo "usage: sbc-cores N|all|show" >&2; exit 2 ;; esac
	[ "$(id -u)" -eq 0 ] || exec sudo "$0" "$@"
	n=$(nproc --all)
	[ "$cmd" -ge 1 ] && [ "$cmd" -le "$n" ] || { echo "N must be 1..$n" >&2; exit 2; }
	mkdir -p "$(dirname "$conf")"
	printf '[Service]\nCPUAffinity=0-%s\n' $((cmd - 1)) >"$conf" ;;
esac
systemctl daemon-reload
if systemctl is-active --quiet freesbc; then
	systemctl restart freesbc
	sleep 2
	systemctl is-active --quiet freesbc || { journalctl -u freesbc -n 20 --no-pager >&2; echo "freesbc did not restart" >&2; exit 1; }
else
	echo "freesbc is not running: the limit applies at its next start (freesbc-use sipp|fs)"
fi
show
