# Resource figures for one time window of the metrics CSV that run.sh samples.
#   awk -F, -v w0=<epoch> -v w1=<epoch> -f window_metrics.awk metrics.csv
# Prints one line: cpu_avg cpu_peak rss_peak_mb goroutines_peak ports_peak rx_pps tx_pps udp_rcvbuf_errors
#   udp_pub_drops udp_priv_drops udp_pub_rxq_peak_bytes udp_priv_rxq_peak_bytes
# CPU is the delta of cpu_s over the delta of ts between consecutive samples
# inside the window (100 = one core); pps is the delta of the live RTP packet
# counters over the window (empty when the build lacks them). The drop counts
# are deltas over the window and the receive queues the largest sample, per
# FreeSBC UDP SIP socket (empty when the column is absent or empty).
function num(x) { return (x == "") ? -1 : x + 0 }
function cv(name) { return (name in col) ? num($col[name]) : -1 }
NR == 1 { for (i = 1; i <= NF; i++) col[$i] = i; next }
{
	t = $col["ts"] + 0
	cpu = num($col["cpu_s"])
	if (t >= w0 && t <= w1) {
		if (havep && cpu >= 0 && t > pt) {
			c = (cpu - pcpu) / (t - pt) * 100
			sum += c * (t - pt); span += t - pt
			if (c > peak) peak = c
		}
		r = num($col["rss_bytes"]); if (r > rss) rss = r
		g = num($col["goroutines"]); if (g > gor) gor = g
		p = num($col["ports_in_use"]); if (p > ports) ports = p
		if (!seen) {
			rb0 = num($col["udp_rcvbuf_errors"]); rx0 = num($col["rtp_pkts_rx"]); tx0 = num($col["rtp_pkts_tx"]); t0 = t; seen = 1
			pd0 = -1; vd0 = -1; pd1 = -1; vd1 = -1; pq = -1; vq = -1
		}
		rb1 = num($col["udp_rcvbuf_errors"]); rx1 = num($col["rtp_pkts_rx"]); tx1 = num($col["rtp_pkts_tx"]); t1 = t
		# per-socket cells can be empty (a socket missed in one /proc read):
		# the delta runs from the first to the last non-empty cell
		q = cv("udp_pub_drops"); if (q >= 0) { if (pd0 < 0) pd0 = q; pd1 = q }
		q = cv("udp_priv_drops"); if (q >= 0) { if (vd0 < 0) vd0 = q; vd1 = q }
		q = cv("udp_pub_rxq_bytes"); if (q > pq) pq = q
		q = cv("udp_priv_rxq_bytes"); if (q > vq) vq = q
	}
	pt = t; pcpu = cpu; havep = 1
}
END {
	rxp = (seen && t1 > t0 && rx0 >= 0) ? sprintf("%.0f", (rx1 - rx0) / (t1 - t0)) : ""
	txp = (seen && t1 > t0 && tx0 >= 0) ? sprintf("%.0f", (tx1 - tx0) / (t1 - t0)) : ""
	rbe = (seen && rb0 >= 0) ? rb1 - rb0 : ""
	pd = (seen && pd0 >= 0 && pd1 >= 0) ? pd1 - pd0 : ""
	vd = (seen && vd0 >= 0 && vd1 >= 0) ? vd1 - vd0 : ""
	pqs = (seen && pq >= 0) ? pq : ""
	vqs = (seen && vq >= 0) ? vq : ""
	printf "%.0f %.0f %.0f %d %d %s %s %s %s %s %s %s\n", (span ? sum / span : 0), peak, rss / 1048576, gor, ports, rxp, txp, rbe, pd, vd, pqs, vqs
}
