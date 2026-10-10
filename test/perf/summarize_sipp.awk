# Summarise a SIPp statistics CSV (-trace_stat -stf, comma delimited).
#   awk -F, -f summarize_sipp.awk sipp.csv
# Prints key=value lines: calls created/ok/failed, failed %, the median of the
# 1 s call-rate samples while calls were being created, the mean response time
# and the p95 upper bound from the response-time repartition.
function tms(s,   a, n) {         # hh:mm:ss:uuuuuu or hh:mm:ss -> ms
	n = split(s, a, ":")
	if (n == 4) return (a[1] * 3600 + a[2] * 60 + a[3]) * 1000 + a[4] / 1000
	if (n == 3) return (a[1] * 3600 + a[2] * 60 + a[3]) * 1000
	return 0
}
NR == 1 { for (i = 1; i <= NF; i++) { col[$i] = i; hdr[i] = $i } nf = NF; next }
NF < 10 { next }
{
	have = 1
	for (i = 1; i <= NF; i++) lastrow[i] = $i
	if ($col["OutgoingCall(P)"] + $col["IncomingCall(P)"] > 0) { r[++nr] = $col["CallRate(P)"] + 0 }
}
END {
	if (!have) { print "sipp_stats=empty"; exit }
	created = lastrow[col["TotalCallCreated"]] + 0
	ok = lastrow[col["SuccessfulCall(C)"]] + 0
	fail = lastrow[col["FailedCall(C)"]] + 0
	printf "calls_created=%d calls_ok=%d calls_failed=%d failed_pct=%.3f\n", created, ok, fail, (created > 0 ? fail / created * 100 : 0)
	for (i = 2; i <= nr; i++) { x = r[i]; j = i - 1; while (j > 0 && r[j] > x) { r[j + 1] = r[j]; j-- } r[j + 1] = x }
	if (nr > 0) printf "cps_median=%.1f cps_max=%.1f (1 s samples while creating calls)\n", r[int((nr + 1) / 2)], r[nr]
	elapsed = tms(lastrow[col["ElapsedTime(C)"]])
	if (elapsed > 0) printf "elapsed_s=%.0f cps_over_elapsed=%.2f\n", elapsed / 1000, created / (elapsed / 1000)
	printf "retransmissions=%d timeouts_recv=%d unexpected_msg=%d max_udp_retrans=%d\n", lastrow[col["Retransmissions(C)"]], lastrow[col["FailedTimeoutOnRecv(C)"]], lastrow[col["FailedUnexpectedMessage(C)"]], lastrow[col["FailedMaxUDPRetrans(C)"]]
	if ("ResponseTime1(C)" in col) printf "rt_mean_ms=%.1f\n", tms(lastrow[col["ResponseTime1(C)"]])
	tot = 0; nb = 0
	for (i = 1; i <= nf; i++) if (hdr[i] ~ /^ResponseTimeRepartition1_/) { nb++; b[nb] = hdr[i]; cnt[nb] = lastrow[i] + 0; tot += cnt[nb] }
	if (tot > 0) {
		run = 0
		for (k = 1; k <= nb; k++) { run += cnt[k]; if (run >= 0.95 * tot) { name = b[k]; sub(/^ResponseTimeRepartition1_/, "", name); printf "rt_p95_bucket_ms=%s (of %d timed calls)\n", name, tot; break } }
	}
}
