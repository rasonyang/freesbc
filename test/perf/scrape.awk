# Turn one sample.sh output (Prometheus text + perf_proc_* lines) into one CSV
# row. Metrics with labels are summed over the label sets. A metric that is
# absent (for example process_* or a live-RTP counter on a build that lacks
# it) leaves an empty cell. Usage:
#   awk -v ts=<epoch> -f scrape.awk sample.txt
# The column order is the one run.sh writes in the CSV header.
function pick(a, b) { return (a in v) ? v[a] : ((b in v) ? v[b] : "") }
function val(a) { return (a in v) ? v[a] : "" }
/^#/ || NF < 2 { next }
{
	name = $1
	sub(/\{.*/, "", name)
	v[name] += $NF
}
END {
	printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n", \
		ts, \
		pick("process_cpu_seconds_total", "perf_proc_cpu_seconds_total"), \
		pick("process_resident_memory_bytes", "perf_proc_rss_bytes"), \
		pick("process_open_fds", "perf_proc_open_fds"), \
		val("go_goroutines"), \
		val("go_memstats_heap_inuse_bytes"), \
		val("freesbc_media_ports_in_use"), \
		val("freesbc_active_calls"), \
		val("freesbc_active_registrations"), \
		val("freesbc_active_webrtc_sessions"), \
		val("freesbc_edge_sessions"), \
		val("freesbc_rtp_packets_rx_total"), \
		val("freesbc_rtp_packets_tx_total"), \
		val("freesbc_rtp_bytes_rx_total"), \
		val("freesbc_rtp_bytes_tx_total"), \
		val("freesbc_media_port_allocation_failure_total"), \
		val("freesbc_edge_invite_rejects_total"), \
		val("freesbc_edge_admission_drops_total"), \
		val("freesbc_shield_drops_total"), \
		val("perf_proc_udp_rcvbuf_errors")
}
