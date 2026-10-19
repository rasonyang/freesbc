#!/bin/bash
# Growth check for a soak: compares the first and the last quarter of a run's metrics.csv.
#
#   test/perf/hosts/soakcheck.sh RUN_DIR [SKIP_MIN]    SKIP_MIN: ignore the first minutes (ramp), default 10
#
# For goroutines, rss_bytes, open_fds and ports_in_use it prints the median of the first and of
# the last quarter of the samples (after the skipped ramp), the change in percent and a verdict:
# PASS when the last quarter is within GROWTH_PCT (default 5) of the first, else FAIL. Also prints
# the maximum, the linear-fit slope per hour, and whether ports_in_use is back to 0 at the end
# (only meaningful after the run has ended and drained). Exit 1 on any FAIL.
set -u
d=${1:?usage: soakcheck.sh RUN_DIR [SKIP_MIN]}
skip=${2:-10}
f=$d/metrics.csv
[ -f "$f" ] || { echo "no $f" >&2; exit 2; }
awk -F, -v skip="$skip" -v tol="${GROWTH_PCT:-5}" '
function med(a, n,   i, j, x, b) { for (i = 1; i <= n; i++) b[i] = a[i]
	for (i = 2; i <= n; i++) { x = b[i]; j = i - 1; while (j > 0 && b[j] > x) { b[j+1] = b[j]; j-- } b[j+1] = x }
	return b[int((n + 1) / 2)] }
NR == 1 { for (i = 1; i <= NF; i++) col[$i] = i; next }
{ n++; T[n] = $col["ts"] + 0; for (k = 1; k <= 4; k++) V[k, n] = $col[nm[k]] + 0 }
BEGIN { nm[1] = "goroutines"; nm[2] = "rss_bytes"; nm[3] = "open_fds"; nm[4] = "ports_in_use" }
END {
	if (n < 8) { print "FAIL  too few samples (" n ")"; exit 1 }
	t0 = T[1] + skip * 60; a = 0
	for (i = 1; i <= n; i++) if (T[i] >= t0) { a = i; break }
	if (!a) { print "FAIL  run shorter than the skipped ramp"; exit 1 }
	m = n - a + 1; q = int(m / 4); bad = 0
	if (q < 2) { print "FAIL  too few samples after the ramp"; exit 1 }
	printf "samples=%d after ramp=%d window_h=%.2f\n", n, m, (T[n] - T[a]) / 3600
	for (k = 1; k <= 4; k++) {
		for (i = 1; i <= q; i++) { x[i] = V[k, a + i - 1]; y[i] = V[k, n - q + i] }
		mf = med(x, q); ml = med(y, q); mx = 0; sx = sy = sxx = sxy = 0
		for (i = a; i <= n; i++) { v = V[k, i]; if (v > mx) mx = v; tt = (T[i] - T[a]) / 3600; sx += tt; sy += v; sxx += tt * tt; sxy += tt * v }
		den = m * sxx - sx * sx; slope = (den ? (m * sxy - sx * sy) / den : 0)
		ch = (mf > 0 ? (ml - mf) / mf * 100 : (ml > 0 ? 100 : 0))
		verdict = (ch > tol) ? "FAIL" : "PASS"; if (verdict == "FAIL") bad = 1
		printf "%s  %-12s first_q_median=%.0f last_q_median=%.0f change=%+.1f%% max=%.0f slope_per_h=%+.1f\n", verdict, nm[k], mf, ml, ch, mx, slope
	}
	printf "INFO  ports_in_use at the last sample: %d (0 expected once the run has drained)\n", V[4, n]
	exit bad
}' "$f"
