#!/bin/sh
# One sample of FreeSBC's resource use, run ON the FreeSBC host (run.sh calls
# it through $SBC_EXEC). Prints the Prometheus text from the admin /metrics
# endpoint, then three "perf_proc_*" lines read from /proc/<pid>, which work
# even when the binary has no process_* collector.
#
# "sample.sh pprof KIND [SECONDS]" instead writes one profile from the admin
# pprof endpoint (admin.pprof: true) to stdout: KIND is profile (CPU) or trace
# for SECONDS [30], goroutine (debug=1), heap or allocs. run.sh's PROFILE_AT
# uses it.
#
# Environment:
#   ADMIN_URL   default http://127.0.0.1:8081 (admin.listen in the config)
#   ADMIN_USER  default admin
#   ADMIN_PASS  default perf
#   SBC_PID     default: pidof freesbc
#   SIP_PORT    default 5060: the port of FreeSBC's UDP SIP sockets
ADMIN_URL=${ADMIN_URL:-http://127.0.0.1:8081}
ADMIN_USER=${ADMIN_USER:-admin}
ADMIN_PASS=${ADMIN_PASS:-perf}

if [ "${1:-}" = pprof ]; then
	secs=${3:-30}
	case $secs in '' | *[!0-9]*) echo "sample.sh: SECONDS must be a number" >&2; exit 2 ;; esac
	case ${2:-} in
	profile | trace) q="?seconds=$secs" mt=$((secs + 30)) ;;
	goroutine) q="?debug=1" mt=30 ;;
	heap | allocs) q="" mt=30 ;;
	*) echo "usage: sample.sh pprof profile|trace [SECONDS] | goroutine | heap | allocs" >&2; exit 2 ;;
	esac
	exec curl -sf --max-time "$mt" -u "$ADMIN_USER:$ADMIN_PASS" "$ADMIN_URL/debug/pprof/$2$q"
fi

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
	# Datagrams the kernel dropped because a UDP receive buffer was full, in the
	# network namespace of the process (RcvbufErrors of /proc/<pid>/net/snmp).
	awk '/^Udp:/ { if (!h) { for (i = 1; i <= NF; i++) if ($i == "RcvbufErrors") c = i; h = 1 } else print "perf_proc_udp_rcvbuf_errors " $c }' "/proc/$pid/net/snmp"
	# Per socket, for the UDP sockets bound to SIP_PORT (FreeSBC's public and
	# private SIP sockets; scrape.awk tells them apart by local IP): datagrams
	# dropped (drops, the last column) and bytes queued (rx_queue) from
	# /proc/<pid>/net/udp and udp6. Like snmp these tables cover the whole
	# namespace, so another process's socket on SIP_PORT would be counted too.
	# The address is hex words in host byte order: little-endian (x86-64,
	# arm64) is assumed. An IPv4-mapped IPv6 address prints as IPv4. Under
	# heavy socket churn (RTP ports) one read can repeat or miss a line:
	# repeats are dropped by inode; a missed socket leaves its cell empty.
	cat "/proc/$pid/net/udp" "/proc/$pid/net/udp6" 2>/dev/null | awk -v port="${SIP_PORT:-5060}" '
		function hex(s,   i, n) { n = 0; s = toupper(s); for (i = 1; i <= length(s); i++) n = n * 16 + index("0123456789ABCDEF", substr(s, i, 1)) - 1; return n }
		function v4(w) { return hex(substr(w, 7, 2)) "." hex(substr(w, 5, 2)) "." hex(substr(w, 3, 2)) "." hex(substr(w, 1, 2)) }
		function v6(a,   i, w, out) {
			if (substr(a, 1, 24) == "0000000000000000FFFF0000") return v4(substr(a, 25, 8))
			out = ""
			for (i = 0; i < 4; i++) {
				w = substr(a, i * 8 + 1, 8)
				out = out (i ? ":" : "") tolower(substr(w, 7, 2) substr(w, 5, 2) ":" substr(w, 3, 2) substr(w, 1, 2))
			}
			return "[" out "]"
		}
		BEGIN { ph = sprintf("%04X", port) }
		$1 ~ /:$/ && NF >= 13 {
			n = split($2, la, ":"); if (n != 2 || toupper(la[2]) != ph) next
			if (seen[$10]++) next   # a line repeated in one read (socket churn): count the inode once
			if (length(la[1]) == 8) ip = v4(la[1]); else if (length(la[1]) == 32) ip = v6(la[1]); else next
			split($5, q, ":")
			printf "perf_proc_udp_socket_drops{local=\"%s:%d\"} %s\n", ip, port, $NF
			printf "perf_proc_udp_socket_rx_queue_bytes{local=\"%s:%d\"} %d\n", ip, port, hex(q[2])
		}'
fi
