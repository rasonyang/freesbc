# Summarise the FreeSBC metrics CSV that run.sh samples (header + one row per
# sample, columns as in scrape.awk). Prints key=value lines.
#   awk -F, -f summarize_metrics.awk metrics.csv
function num(x) { return (x == "") ? -1 : x + 0 }
NR == 1 { for (i = 1; i <= NF; i++) col[$i] = i; next }
{
	n++
	t = $col["ts"] + 0
	cpu = num($col["cpu_s"]); rss = num($col["rss_bytes"]); fds = num($col["open_fds"])
	gor = num($col["goroutines"]); heap = num($col["heap_inuse_bytes"])
	ports = num($col["ports_in_use"]); calls = num($col["active_calls"])
	regs = num($col["active_regs"]); wr = num($col["webrtc_sessions"]); sess = num($col["edge_sessions"])
	if (n == 1) {
		t0 = t; cpu0 = cpu; rss0 = rss; gor0 = gor; fds0 = fds; heap0 = heap
		rx0 = num($col["rtp_pkts_rx"]); tx0 = num($col["rtp_pkts_tx"])
		rxb0 = num($col["rtp_bytes_rx"]); txb0 = num($col["rtp_bytes_tx"])
		rej0 = num($col["invite_rejects"]); adm0 = num($col["admission_drops"]); shd0 = num($col["shield_drops"])
		rbe0 = num($col["udp_rcvbuf_errors"])
		af0 = num($col["port_alloc_fail"])
	} else if (cpu >= 0 && pcpu >= 0 && t > pt) {
		c = (cpu - pcpu) / (t - pt) * 100
		if (c > peakcpu) peakcpu = c
	}
	if (rss > peakrss) peakrss = rss
	if (fds > peakfds) peakfds = fds
	if (gor > peakgor) peakgor = gor
	if (heap > peakheap) peakheap = heap
	if (ports > peakports) peakports = ports
	if (calls > peakcalls) peakcalls = calls
	if (regs > peakregs) peakregs = regs
	if (wr > peakwr) peakwr = wr
	if (sess > peaksess) peaksess = sess
	pt = t; pcpu = cpu
	tl = t; cpul = cpu; rssl = rss; gorl = gor; fdsl = fds; heapl = heap; portsl = ports; callsl = calls
	rxl = num($col["rtp_pkts_rx"]); txl = num($col["rtp_pkts_tx"])
	rxbl = num($col["rtp_bytes_rx"]); txbl = num($col["rtp_bytes_tx"])
	rejl = num($col["invite_rejects"]); adml = num($col["admission_drops"]); shdl = num($col["shield_drops"])
	rbel = num($col["udp_rcvbuf_errors"])
	afl = num($col["port_alloc_fail"])
}
END {
	if (n < 2) { print "samples=" n; exit }
	dt = tl - t0
	printf "samples=%d window_s=%.0f\n", n, dt
	if (cpul >= 0 && cpu0 >= 0) printf "cpu_avg_pct=%.1f cpu_peak_pct=%.1f   (100 = one core)\n", (cpul - cpu0) / dt * 100, peakcpu
	else print "cpu_avg_pct=n/a"
	if (peakrss >= 0) printf "rss_peak_mb=%.1f rss_start_mb=%.1f rss_end_mb=%.1f\n", peakrss / 1048576, rss0 / 1048576, rssl / 1048576
	if (peakgor >= 0) printf "goroutines_start=%d peak=%d end=%d\n", gor0, peakgor, gorl
	if (peakfds >= 0) printf "open_fds_start=%d peak=%d end=%d\n", fds0, peakfds, fdsl
	if (peakheap >= 0) printf "heap_inuse_peak_mb=%.1f end_mb=%.1f\n", peakheap / 1048576, heapl / 1048576
	if (peakports >= 0) printf "media_ports_in_use_peak=%d end=%d\n", peakports, portsl
	if (peakcalls >= 0) printf "active_calls_peak=%d end=%d\n", peakcalls, callsl
	if (peaksess >= 0) printf "edge_sessions_peak=%d\n", peaksess
	if (peakregs >= 0) printf "active_registrations_peak=%d\n", peakregs
	if (peakwr >= 0) printf "active_webrtc_sessions_peak=%d\n", peakwr
	if (rxl >= 0 && rx0 >= 0 && (rxl - rx0) > 0) {
		printf "rtp_pkts_rx=%d rtp_pkts_tx=%d avg_pps_rx=%.0f avg_pps_tx=%.0f tx_over_rx=%.4f\n", rxl - rx0, txl - tx0, (rxl - rx0) / dt, (txl - tx0) / dt, (txl - tx0) / (rxl - rx0)
		if (rxbl >= 0) printf "rtp_mbit_rx=%.2f rtp_mbit_tx=%.2f (average over the window)\n", (rxbl - rxb0) * 8 / dt / 1e6, (txbl - txb0) * 8 / dt / 1e6
	} else print "rtp_pkts=n/a (counter absent, or it counts finished sessions only and none finished in the window)"
	if (afl >= 0) printf "port_alloc_failures=%d\n", afl - af0
	if (rejl >= 0) printf "invite_rejects=%d\n", rejl - rej0
	if (adml >= 0) printf "admission_drops=%d\n", adml - adm0
	if (shdl >= 0) printf "shield_drops=%d\n", shdl - shd0
	if (rbel >= 0) printf "udp_rcvbuf_errors=%d   (datagrams the kernel dropped on FreeSBC's UDP sockets: receive buffer full)\n", rbel - rbe0
}
