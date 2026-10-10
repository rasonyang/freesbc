# The plateau of a run: the samples where active_calls is at least 90% of its
# peak (webrtc runs: active_webrtc_sessions). Prints key=value lines with the
# resources over that window.
#   awk -F, -f plateau_metrics.awk metrics.csv
function num(x) { return (x == "") ? -1 : x + 0 }
NR == 1 { for (i = 1; i <= NF; i++) col[$i] = i; next }
{
	n++
	T[n] = $col["ts"] + 0; CPU[n] = num($col["cpu_s"]); RSS[n] = num($col["rss_bytes"])
	FD[n] = num($col["open_fds"]); G[n] = num($col["goroutines"]); P[n] = num($col["ports_in_use"])
	C[n] = num($col["active_calls"]); W[n] = num($col["webrtc_sessions"])
	RX[n] = num($col["rtp_pkts_rx"]); TX[n] = num($col["rtp_pkts_tx"])
	if (C[n] > pc) pc = C[n]
	if (W[n] > pw) pw = W[n]
}
END {
	key = (pw > pc) ? "w" : "c"; peak = (key == "w") ? pw : pc
	if (peak <= 0) { print "plateau=none (no calls seen)"; exit }
	thr = peak * 0.9; a = 0; b = 0
	for (i = 1; i <= n; i++) {
		v = (key == "w") ? W[i] : C[i]
		if (v >= thr) { if (!a) a = i; b = i }
	}
	if (b - a < 1) { print "plateau=none (too short)"; exit }
	for (i = a; i <= b; i++) {
		if (RSS[i] > rss) rss = RSS[i]; if (FD[i] > fd) fd = FD[i]
		if (G[i] > g) g = G[i]; if (P[i] > p) p = P[i]
		cs += (key == "w") ? W[i] : C[i]
		if (i > a && CPU[i] >= 0 && T[i] > T[i-1]) {
			c = (CPU[i] - CPU[i-1]) / (T[i] - T[i-1]) * 100
			cpusum += c * (T[i] - T[i-1]); span += T[i] - T[i-1]
			if (c > cpk) cpk = c
		}
	}
	dt = T[b] - T[a]
	printf "plateau_s=%d (samples %d, active %s >= 90%% of peak %d)\n", dt, b - a + 1, (key == "w" ? "webrtc sessions" : "calls"), peak
	printf "plateau_calls_avg=%.0f\n", cs / (b - a + 1)
	printf "plateau_cpu_avg_pct=%.0f plateau_cpu_peak_pct=%.0f\n", (span ? cpusum / span : 0), cpk
	printf "plateau_rss_max_mb=%.0f goroutines_max=%d open_fds_max=%d ports_in_use_max=%d\n", rss / 1048576, g, fd, p
	if (RX[a] >= 0 && dt > 0) {
		rxp = (RX[b] - RX[a]) / dt; txp = (TX[b] - TX[a]) / dt
		printf "plateau_rtp_rx_pps=%.0f plateau_rtp_tx_pps=%.0f plateau_tx_over_rx=%.4f\n", rxp, txp, (rxp ? txp / rxp : 0)
	}
}
