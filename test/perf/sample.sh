#!/bin/sh
# One sample of FreeSBC's resource use, run ON the FreeSBC host (run.sh calls
# it through $SBC_EXEC). Prints the Prometheus text from the admin /metrics
# endpoint, then three "perf_proc_*" lines read from /proc/<pid>, which work
# even when the binary has no process_* collector.
#
# Environment:
#   ADMIN_URL   default http://127.0.0.1:8081 (admin.listen in the config)
#   ADMIN_USER  default admin
#   ADMIN_PASS  default perf
#   SBC_PID     default: pidof freesbc
ADMIN_URL=${ADMIN_URL:-http://127.0.0.1:8081}
ADMIN_USER=${ADMIN_USER:-admin}
ADMIN_PASS=${ADMIN_PASS:-perf}
pid=${SBC_PID:-$(pidof freesbc 2>/dev/null | cut -d' ' -f1)}

curl -sf --max-time 5 -u "$ADMIN_USER:$ADMIN_PASS" "$ADMIN_URL/metrics" || echo "# perf_scrape_failed"

if [ -n "$pid" ] && [ -r "/proc/$pid/stat" ]; then
	# utime + stime in clock ticks (fields 14 and 15 after the "(comm)" field).
	ticks=$(sed 's/^.*) //' "/proc/$pid/stat" | awk '{print $12 + $13}')
	hz=$(getconf CLK_TCK 2>/dev/null || echo 100)
	rss_kb=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status")
	fds=$(ls "/proc/$pid/fd" 2>/dev/null | wc -l | tr -d ' ')
	echo "perf_proc_cpu_seconds_total $(awk -v t="$ticks" -v h="$hz" 'BEGIN{printf "%.2f", t/h}')"
	echo "perf_proc_rss_bytes $((rss_kb * 1024))"
	echo "perf_proc_open_fds $fds"
fi
