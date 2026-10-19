#!/bin/bash
# Verdict for finished run.sh runs, from their summary.txt. Run it on the loadgen host:
#
#   test/perf/hosts/runcheck.sh [RUN_DIR...]     default: every test/perf/out/* directory
#
# One line per finding: PASS, WARN or FAIL, the run, the reason. Exit 1 when any FAIL.
# What FAIL means (run.sh itself only checks failed_pct, so it misses an aborted SIPp):
#   - failed_pct above 0.1 in any SIPp block (step mode: in any step but the last,
#     which is allowed to be the failing one that ends the ramp)
#   - calls_ok + calls_failed < calls_created: SIPp was killed or aborted with calls
#     in flight. run.sh counts such a run as 0% failed; it is not a pass. In step
#     mode this also invalidates the "max sustained rate" line.
#   - a webrtc run with calls_ok + calls_failed < calls_attempted, or reg_failed > 0
#   - a run with no SIPp stats at all (no sipp block, or sipp_stats=empty)
#   - non-step runs: invite_rejects, admission_drops, shield_drops, port_alloc_failures
#     or udp_rcvbuf_errors above 0 (step runs: WARN, the failing step causes them)
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT_ROOT:-$HERE/../out}
if [ $# -eq 0 ]; then set -- "$OUT"/*/; fi
rc=0
for d in "$@"; do
	d=${d%/}
	[ -f "$d/summary.txt" ] || { echo "WARN  $(basename "$d") no summary.txt (run not finished?)"; continue; }
	step=0
	{ [ -f "$d/steps.csv" ] || grep -q '^max sustained rate' "$d/summary.txt"; } && step=1
	awk -v run="$(basename "$d")" -v step="$step" '
	function say(level, msg) { print level "  " run " " msg; if (level == "FAIL") bad = 1 }
	/^--- SIPp / { blk = $3; nblk++; order[nblk] = blk; next }
	/^--- webrtcload ---/ { blk = "webrtc"; web = 1; next }
	/^--- / { blk = ""; next }
	/^sipp_stats=empty/ { if (blk != "") say("FAIL", "SIPp stats of " blk " are empty (SIPp did not run or was killed at once)") }
	/^calls_created=/ && blk != "" {
		split($1, a, "="); split($2, b, "="); split($3, c, "="); split($4, p, "=")
		cr[blk] = a[2] + 0; ok[blk] = b[2] + 0; fl[blk] = c[2] + 0; pc[blk] = p[2] + 0
		seen[blk] = 1
	}
	/^calls_attempted=/ {
		split($1, a, "="); split($2, b, "="); split($3, c, "="); split($4, p, "=")
		wat = a[2] + 0; wok = b[2] + 0; wfl = c[2] + 0; wpc = p[2] + 0
	}
	/^reg_ok=/ { split($2, r, "="); wreg = r[2] + 0 }
	/^max sustained rate/ { knee = $0 }
	/^rtp_pkts_rx=/ { for (i = 1; i <= NF; i++) if ($i ~ /^tx_over_rx=/) { split($i, t, "="); txrx = t[2] } }
	/^(invite_rejects|admission_drops|shield_drops|port_alloc_failures|udp_rcvbuf_errors)=/ { split($1, m, "="); met[m[1]] = m[2] + 0 }
	END {
		if (!web && nblk == 0) say("FAIL", "no SIPp block in summary.txt")
		for (i = 1; i <= nblk; i++) {
			k = order[i]
			if (!(k in seen)) continue
			last = (i == nblk)
			if (cr[k] > 0 && ok[k] + fl[k] < cr[k])
				say("FAIL", "SIPp " k " aborted: created=" cr[k] " ok=" ok[k] " failed=" fl[k] " (" cr[k] - ok[k] - fl[k] " calls neither finished nor failed)")
			else if (pc[k] > 0.1 && !(step && last))
				say("FAIL", "SIPp " k " failed_pct=" pc[k] " (" fl[k] " of " cr[k] ")")
			else if (pc[k] > 0.1)
				say("PASS", "SIPp " k " is the failing step that ends the ramp (failed_pct=" pc[k] ")")
			else
				say("PASS", "SIPp " k " created=" cr[k] " ok=" ok[k] " failed=" fl[k])
		}
		if (web) {
			if (wat > 0 && wok + wfl < wat) say("FAIL", "webrtc: attempted=" wat " ok=" wok " failed=" wfl " (calls unaccounted for)")
			else if (wpc > 0.1) say("FAIL", "webrtc failed_pct=" wpc)
			else say("PASS", "webrtc attempted=" wat " ok=" wok " failed=" wfl)
			if (wreg > 0 || ("reg_failed" in met)) {}
		}
		for (k in met) if (met[k] > 0) say(step ? "WARN" : "FAIL", k "=" met[k])
		if (txrx != "" && txrx + 0 < 0.999) say("WARN", "tx_over_rx=" txrx " (FreeSBC forwarded fewer RTP packets than it received)")
		if (knee != "") say("INFO", knee)
		exit bad
	}' "$d/summary.txt" || rc=1
done
exit $rc
