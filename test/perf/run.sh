#!/usr/bin/env bash
# FreeSBC load-test runner. See README.md in this directory.
#
#   run.sh up | down                      build and start / stop the compose rig
#   run.sh [options] SCENARIO             run one scenario and print a summary
#
# SCENARIO: register | call | carrier-in | carrier-out | webrtc
#
# Options:
#   -r RATE      calls (REGISTERs for "register") started per second     [10]
#   -t SECS      how long to keep starting calls                          [30]
#   -H SECS      hold time of each call                                   [10]
#   -c CALLS     target concurrent calls: sets RATE = ceil(CALLS/HOLD) when
#                -r is not given, and caps SIPp's concurrency (-l)
#   -u USERS     registered users (register, call, webrtc)    [1000; webrtc 100]
#   -s F:T:I[:S] step mode: run at F, F+I, ... up to T calls/s, S seconds per
#                step [20], stop at the first step over STEP_FAIL_PCT [0.1]
#                failures and report the highest passing rate
#   -n           no media: strip the RTP pcap play (signaling-only capacity)
#   -i SECS      metrics sampling interval                                [2]
#   -T HOST:PORT SIPp target instead of FreeSBC (a direct-to-switch baseline)
#   -w URL       webrtc target                         [ws://$SBC_PUBLIC:8080]
#   -W N         webrtc WebSocket connections (max 256 per source IP)    [20]
#   -h           this text
#
# Topology and paths are environment variables (defaults = docker compose rig):
#   TOPOLOGY=compose|hosts   LOADGEN_EXEC CARRIERGEN_EXEC CARRIER_EXEC
#   SWITCH_EXEC SBC_EXEC     command prefix that runs a command ON that role
#   SBC_PUBLIC SBC_PRIVATE LOADGEN_IP CARRIERGEN_IP CARRIER_IP SWITCH_IP
#   REMOTE_PERF  path of test/perf as seen by the roles       SAMPLE_CMD
# In hosts mode every *_EXEC defaults to empty (= run locally) except where you
# set it, e.g. SBC_EXEC="ssh sbc" SWITCH_EXEC="ssh switch".

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
TOPOLOGY=${TOPOLOGY:-compose}
COMPOSE_FILE=${COMPOSE_FILE:-$HERE/docker-compose.yml}

SBC_PUBLIC=${SBC_PUBLIC:-172.28.1.10}
SBC_PRIVATE=${SBC_PRIVATE:-172.28.2.10}
LOADGEN_IP=${LOADGEN_IP:-172.28.1.20}
CARRIERGEN_IP=${CARRIERGEN_IP:-172.28.1.25}
CARRIER_IP=${CARRIER_IP:-172.28.1.30}
SWITCH_IP=${SWITCH_IP:-172.28.2.20}
CARRIER_PORT=${CARRIER_PORT:-5060}      # edge.carriers.perfcarrier port
SIP_PORT=${SIP_PORT:-5060}              # FreeSBC public and private SIP port
GEN_PORT=${GEN_PORT:-5070}              # generator's fixed source port (registration identity)
SERVICE=${SERVICE:-2000}                # dialed user part
REG_RATE=${REG_RATE:-200}               # registrations/s while pre-registering
STEP_FAIL_PCT=${STEP_FAIL_PCT:-0.1}
OUT_ROOT=${OUT_ROOT:-$HERE/out}

if [[ $TOPOLOGY == compose ]]; then
	DC="docker compose -f $COMPOSE_FILE"
	LOADGEN_EXEC=${LOADGEN_EXEC-$DC exec -T loadgen}
	CARRIERGEN_EXEC=${CARRIERGEN_EXEC-$DC exec -T carriergen}
	CARRIER_EXEC=${CARRIER_EXEC-$DC exec -T carrier}
	SWITCH_EXEC=${SWITCH_EXEC-$DC exec -T switch}
	SBC_EXEC=${SBC_EXEC-$DC exec -T freesbc}
	REMOTE_PERF=${REMOTE_PERF:-/perf}
else
	LOADGEN_EXEC=${LOADGEN_EXEC-}
	CARRIERGEN_EXEC=${CARRIERGEN_EXEC-}
	CARRIER_EXEC=${CARRIER_EXEC-}
	SWITCH_EXEC=${SWITCH_EXEC-}
	SBC_EXEC=${SBC_EXEC-}
	REMOTE_PERF=${REMOTE_PERF:-$HERE}
fi
SAMPLE_CMD=${SAMPLE_CMD-$SBC_EXEC $REMOTE_PERF/sample.sh}

die() { echo "run.sh: $*" >&2; exit 1; }
note() { echo "[$(date +%H:%M:%S)] $*" >&2; }

usage() { sed -n '2,/^set -u/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }

# ---------------------------------------------------------------- up / down
case ${1:-} in
up)
	[[ $TOPOLOGY == compose ]] || die "up/down manage the compose rig only"
	export FREESBC_VERSION=${FREESBC_VERSION:-$(git -C "$HERE" describe --always --dirty 2>/dev/null || echo perf)}
	$DC build loadgen freesbc && $DC up -d --force-recreate && exit 0
	exit 1 ;;
down)
	[[ $TOPOLOGY == compose ]] || die "up/down manage the compose rig only"
	$DC down; exit $? ;;
-h|--help|help) usage; exit 0 ;;
esac

# ---------------------------------------------------------------- options
RATE="" CONC="" DUR=30 HOLD=10 USERS="" STEP="" NOMEDIA=0 INTERVAL=2 TARGET="" WSURL="" WCONNS=20
while getopts "r:t:H:c:u:s:ni:T:w:W:h" o; do
	case $o in
	r) RATE=$OPTARG ;; t) DUR=$OPTARG ;; H) HOLD=$OPTARG ;; c) CONC=$OPTARG ;; u) USERS=$OPTARG ;;
	s) STEP=$OPTARG ;; n) NOMEDIA=1 ;; i) INTERVAL=$OPTARG ;; T) TARGET=$OPTARG ;;
	w) WSURL=$OPTARG ;; W) WCONNS=$OPTARG ;; h) usage; exit 0 ;;
	*) usage >&2; exit 2 ;;
	esac
done
shift $((OPTIND - 1))
SCEN=${1:-}
[[ -n $SCEN ]] || { usage >&2; exit 2; }
case $SCEN in register|call|carrier-in|carrier-out|webrtc) ;; *) die "unknown scenario '$SCEN'" ;; esac

if [[ -z $RATE ]]; then
	if [[ -n $CONC ]]; then RATE=$(( (CONC + HOLD - 1) / HOLD )); else RATE=10; fi
fi
if [[ -z $USERS ]]; then
	if [[ $SCEN == webrtc ]]; then
		USERS=$(( RATE * HOLD * 12 / 10 + 5 )); (( USERS < 100 )) && USERS=100
		[[ -n $CONC && $CONC -gt $USERS ]] && USERS=$CONC
	else USERS=1000; fi
	# enough distinct users that a user is rarely in two calls at once
	if [[ $SCEN == call && -n $CONC && $CONC -gt $USERS ]]; then USERS=$CONC; fi
fi
[[ -n $WSURL ]] || WSURL="ws://$SBC_PUBLIC:8080"

STAMP=$(date +%Y%m%d-%H%M%S)
RUN_NAME="$STAMP-$SCEN"
RUN_DIR="$OUT_ROOT/$RUN_NAME"
mkdir -p "$RUN_DIR" || die "cannot create $RUN_DIR"
RO="$REMOTE_PERF/out/$RUN_NAME"          # the same directory as the roles see it
[[ $OUT_ROOT == "$HERE/out" ]] || RO="$OUT_ROOT/$RUN_NAME"
SUMMARY="$RUN_DIR/summary.txt"
exec > >(tee "$SUMMARY") 2>&1

# ---------------------------------------------------------------- inputs
# Users: one per line, SIPp -inf SEQUENTIAL.
awk -v n="$USERS" 'BEGIN { print "SEQUENTIAL"; for (i = 1; i <= n; i++) printf "u%06d\n", i }' > "$RUN_DIR/users.csv"

# G.711 pcap: the shipped 10 s file, or one generated to cover the hold.
PCAP="$REMOTE_PERF/pcap/g711u_10s.pcap"
if [[ $SCEN != register && $SCEN != webrtc && $HOLD -gt 8 ]]; then
	secs=$((HOLD + 2))
	if (( secs > 900 )); then
		note "hold $HOLD s: the pcap is capped at 900 s; RTP stops then, and FreeSBC's 5 min silence watchdog ends the call 300 s later"
		secs=900
	fi
	python3 "$HERE/pcap/gen_pcap.py" -s "$secs" -o "$RUN_DIR/g711u.pcap" || die "python3 is needed to generate a pcap for hold > 8 s"
	PCAP="$RO/g711u.pcap"
fi

# Scenario files; -n strips the pcap play action.
SC_DIR="$REMOTE_PERF/sipp"
if (( NOMEDIA )); then
	mkdir -p "$RUN_DIR/sipp"
	for f in uac_call carrier_in_uac switch_uac_carrier; do
		sed '/<nop>$/,/<\/nop>/d' "$HERE/sipp/$f.xml" > "$RUN_DIR/sipp/$f.xml"
	done
	SC_DIR="$RO/sipp"
fi

# ---------------------------------------------------------------- roles
BG_PIDS=""
kill_role() { # EXEC pattern
	local ex=$1 pat=$2
	$ex pkill -f "$pat" >/dev/null 2>&1 || true
}
start_switch_uas() {
	kill_role "$SWITCH_EXEC" switch_uas.xml
	# -deadcall_wait 2: SIPp otherwise ignores a request for 33 s after a
	# Call-ID's scenario ended, which would swallow a REGISTER refresh.
	$SWITCH_EXEC sipp -sf "$REMOTE_PERF/sipp/switch_uas.xml" -i "$SWITCH_IP" -p "$SIP_PORT" \
		-rtp_echo -mp 6000 -nostdin -fd 60 -deadcall_wait 2 >/dev/null 2>&1 &
	BG_PIDS="$BG_PIDS $!"
}
start_carrier_uas() {
	kill_role "$CARRIER_EXEC" carrier_uas.xml
	$CARRIER_EXEC sipp -sf "$REMOTE_PERF/sipp/carrier_uas.xml" -i "$CARRIER_IP" -p "$CARRIER_PORT" \
		-rtp_echo -mp 6000 -nostdin -fd 60 >/dev/null 2>&1 &
	BG_PIDS="$BG_PIDS $!"
}
stop_roles() {
	[[ -n ${SAMPLER_PID:-} ]] && kill "$SAMPLER_PID" 2>/dev/null
	kill_role "$SWITCH_EXEC" switch_uas.xml
	kill_role "$CARRIER_EXEC" carrier_uas.xml
	for p in $BG_PIDS; do kill "$p" 2>/dev/null; done
}
trap 'stop_roles' EXIT
trap 'echo; note "interrupted"; exit 130' INT TERM

# ---------------------------------------------------------------- sampler
METRICS="$RUN_DIR/metrics.csv"
echo "ts,cpu_s,rss_bytes,open_fds,goroutines,heap_inuse_bytes,ports_in_use,active_calls,active_regs,webrtc_sessions,edge_sessions,rtp_pkts_rx,rtp_pkts_tx,rtp_bytes_rx,rtp_bytes_tx,port_alloc_fail,invite_rejects,admission_drops,shield_drops,udp_rcvbuf_errors" > "$METRICS"
sample_once() {
	local ts out
	ts=$(date +%s)
	out=$($SAMPLE_CMD 2>/dev/null) || return 1
	[[ -n $out ]] || return 1
	printf '%s\n' "$out" | awk -v ts="$ts" -f "$HERE/scrape.awk" >> "$METRICS"
}
start_sampler() {
	( while :; do sample_once; sleep "$INTERVAL"; done ) &
	SAMPLER_PID=$!
}

# ---------------------------------------------------------------- SIPp
# sipp_run EXEC LOCAL_IP LABEL SCENARIO_XML RATE TOTAL HOLD_MS TARGET extra...
sipp_run() {
	local ex=$1 lip=$2 label=$3 xml=$4 rate=$5 total=$6 holdms=$7 target=$8
	shift 8
	local lim=()
	[[ -n $CONC && $label != reg* ]] && lim=(-l $(( CONC + CONC / 10 + 10 )))
	$ex sipp -sf "$xml" -i "$lip" -p "$GEN_PORT" -r "$rate" -m "$total" -d "$holdms" \
		-recv_timeout 10000 -nostdin -trace_stat -stat_delimiter , -fd 1 -stf "$RO/sipp-$label.csv" \
		"${lim[@]+"${lim[@]}"}" "$@" "$target" >"$RUN_DIR/sipp-$label.log" 2>&1
	return 0
}
# stats_of FILE...: "created ok failed" summed over SIPp stats CSVs.
stats_of() {
	local f t_c=0 t_o=0 t_f=0 line c o x
	for f in "$@"; do
		[[ -e $f ]] || continue
		line=$(awk -F, -f "$HERE/summarize_sipp.awk" "$f" 2>/dev/null | sed -n 's/^calls_created=\([0-9]*\) calls_ok=\([0-9]*\) calls_failed=\([0-9]*\).*/\1 \2 \3/p')
		[[ -n $line ]] || continue
		read -r c o x <<<"$line"
		t_c=$((t_c + c)); t_o=$((t_o + o)); t_f=$((t_f + x))
	done
	echo "$t_c $t_o $t_f"
}
# label_files LABEL: the stats files of a run: the label itself or its register rounds.
label_files() { ls "$RUN_DIR"/sipp-"$1".csv "$RUN_DIR"/sipp-"$1".rd*.csv 2>/dev/null; }
sipp_created() { local c o x; read -r c o x <<<"$(stats_of $(label_files "$1"))"; echo "$c"; }
sipp_fail_pct() { local c o x; read -r c o x <<<"$(stats_of $(label_files "$1"))"; awk -v c="$c" -v x="$x" 'BEGIN { if (c == 0) print "?"; else printf "%.3f", x / c * 100 }'; }

# register_rounds LABEL RATE TOTAL: REGISTER TOTAL times over the user list. A
# round is one SIPp process and registers every user once with Call-ID
# "<n>@<ip>"; the next round re-registers them with the SAME Call-IDs, which
# FreeSBC treats as a refresh of the same binding (it keys bindings on AoR +
# Call-ID, so a new Call-ID per REGISTER would pile up bindings and hit the
# 10-per-AoR cap).
register_rounds() {
	local label=$1 rate=$2 total=$3 left=$3 round=1 m
	while (( left > 0 )); do
		m=$(( left < USERS ? left : USERS ))
		sipp_run "$LOADGEN_EXEC" "$LOADGEN_IP" "$label.rd$round" "$REMOTE_PERF/sipp/register.xml" "$rate" "$m" 0 \
			"${TARGET:-$SBC_PUBLIC:$SIP_PORT}" -inf "$RO/users.csv" -key expires 86400 -cid_str '%u@%s'
		left=$(( left - m )); round=$(( round + 1 ))
		(( left > 0 )) && sleep 3
	done
	return 0
}

TOTAL_DEFAULT=$(awk -v r="$RATE" -v t="$DUR" 'BEGIN { n = int(r * t + 0.5); if (n < 1) n = 1; print n }')
HOLD_MS=$((HOLD * 1000))
MEDIA_KEY=(-key pcap "$PCAP")

preregister() {
	note "registering $USERS users from $LOADGEN_IP:$GEN_PORT at $REG_RATE/s"
	sipp_run "$LOADGEN_EXEC" "$LOADGEN_IP" prereg "$REMOTE_PERF/sipp/register.xml" "$REG_RATE" "$USERS" 0 \
		"${TARGET:-$SBC_PUBLIC:$SIP_PORT}" -inf "$RO/users.csv" -key expires 86400 -cid_str '%u@%s'
	local f
	f=$(sipp_fail_pct prereg)
	[[ $f != "?" ]] || die "pre-registration produced no stats; see $RUN_DIR/sipp-prereg.log"
	awk -v f="$f" 'BEGIN { exit !(f > 0) }' && die "pre-registration failed for $f% of users (see $RUN_DIR/sipp-prereg.log); is FreeSBC up, the switch UAS answering, and is this generator IP not in carrier_sources?"
	sleep 3
	return 0
}

# one_load LABEL RATE TOTAL: run the chosen scenario once.
one_load() {
	local label=$1 rate=$2 total=$3
	case $SCEN in
	register) register_rounds "$label" "$rate" "$total" ;;
	call)
		sipp_run "$LOADGEN_EXEC" "$LOADGEN_IP" "$label" "$SC_DIR/uac_call.xml" "$rate" "$total" "$HOLD_MS" \
			"${TARGET:-$SBC_PUBLIC:$SIP_PORT}" -inf "$RO/users.csv" -s "$SERVICE" "${MEDIA_KEY[@]}" ;;
	carrier-in)
		sipp_run "$CARRIERGEN_EXEC" "$CARRIERGEN_IP" "$label" "$SC_DIR/carrier_in_uac.xml" "$rate" "$total" "$HOLD_MS" \
			"${TARGET:-$SBC_PUBLIC:$SIP_PORT}" -s "$SERVICE" "${MEDIA_KEY[@]}" ;;
	carrier-out)
		sipp_run "$SWITCH_EXEC" "$SWITCH_IP" "$label" "$SC_DIR/switch_uac_carrier.xml" "$rate" "$total" "$HOLD_MS" \
			"${TARGET:-$SBC_PRIVATE:$SIP_PORT}" -s "$SERVICE" -key carrier "$CARRIER_IP:$CARRIER_PORT" "${MEDIA_KEY[@]}" ;;
	esac
}

# ---------------------------------------------------------------- run
note "scenario=$SCEN topology=$TOPOLOGY out=$RUN_DIR"
if ! out=$($SAMPLE_CMD 2>/dev/null) || [[ -z $out ]]; then
	note "WARNING: cannot scrape FreeSBC metrics with: $SAMPLE_CMD (is it running? ADMIN_URL/ADMIN_PASS?); resource columns will be empty"
fi
note "FreeSBC build: $(printf '%s\n' "${out:-}" | sed -n 's/^freesbc_build_info{\(.*\)} 1/\1/p' | head -1)"

start_switch_uas
[[ $SCEN == carrier-out ]] && start_carrier_uas
sleep 1
start_sampler
T_START=$(date +%s)

if [[ $SCEN == webrtc ]]; then
	WCALLS=$TOTAL_DEFAULT
	note "webrtc: $WSURL users=$USERS conns=$WCONNS rate=$RATE/s calls=$WCALLS hold=${HOLD}s"
	nm=()
	(( NOMEDIA )) && nm=(-no-media)
	$LOADGEN_EXEC webrtcload -target "$WSURL" -users "$USERS" -conns "$WCONNS" -rate "$RATE" -calls "$WCALLS" \
		-hold "${HOLD}s" -out "$RO/webrtc.csv" "${nm[@]+"${nm[@]}"}" 2>&1 | tee "$RUN_DIR/webrtc.log" | grep -v '^RESULT'
elif [[ -n $STEP ]]; then
	IFS=: read -r S_FROM S_TO S_INC S_SECS <<<"$STEP"
	S_SECS=${S_SECS:-20}
	[[ -n $S_FROM && -n $S_TO && -n $S_INC ]] || die "-s wants FROM:TO:INC[:SECS]"
	[[ $SCEN == call ]] && preregister
	BEST=0 FIRST_BAD=""
	STEPS="$RUN_DIR/steps.csv"
	echo "rate,created,failed_pct,verdict,cpu_avg_pct,cpu_peak_pct,rss_peak_mb,goroutines_peak,ports_peak,rtp_rx_pps,rtp_tx_pps,udp_rcvbuf_errors" > "$STEPS"
	r=$S_FROM
	while (( r <= S_TO )); do
		total=$((r * S_SECS))
		note "step: $r calls/s for ${S_SECS}s ($total calls, hold ${HOLD}s)"
		st0=$(date +%s)
		one_load "r$r" "$r" "$total"
		st1=$(date +%s)
		# resources over the step, skipping its first 5 s (ramp-up)
		res=$(awk -F, -v w0=$((st0 + 5)) -v w1="$st1" -f "$HERE/window_metrics.awk" "$METRICS" | tr ' ' ',')
		created=$(sipp_created "r$r"); fp=$(sipp_fail_pct "r$r")
		if [[ $fp == "?" ]]; then verdict=nostats; elif awk -v f="$fp" -v m="$STEP_FAIL_PCT" 'BEGIN { exit !(f > m) }'; then verdict=FAIL; else verdict=pass; fi
		echo "$r,${created:-0},${fp:-?},$verdict,$res" | tee -a "$STEPS"
		if [[ $verdict == pass ]]; then BEST=$r; else FIRST_BAD=$r; break; fi
		sleep 3
		r=$((r + S_INC))
	done
	echo
	echo "== step result =="
	column -s, -t "$STEPS" 2>/dev/null || cat "$STEPS"
	echo "max sustained rate under ${STEP_FAIL_PCT}% failures: ${BEST} calls/s (hold ${HOLD}s, media $((1 - NOMEDIA)))${FIRST_BAD:+; first failing step: $FIRST_BAD}"
else
	[[ $SCEN == call ]] && preregister
	CAP=""
	[[ -n $CONC ]] && CAP=" concurrency cap $CONC"
	note "load: $RATE/s for ${DUR}s = $TOTAL_DEFAULT calls, hold ${HOLD}s$CAP"
	one_load main "$RATE" "$TOTAL_DEFAULT"
fi

# Let the last RTP counters and the teardown show up before the final sample.
sleep $((INTERVAL + 1))
sample_once
[[ -n ${SAMPLER_PID:-} ]] && kill "$SAMPLER_PID" 2>/dev/null && SAMPLER_PID=""
T_END=$(date +%s)

# ---------------------------------------------------------------- summary
echo
echo "================ summary: $SCEN ($((T_END - T_START)) s) ================"
echo "run dir: $RUN_DIR"
SEEN=""
for f in "$RUN_DIR"/sipp-*.csv; do
	[[ -e $f ]] || continue
	b=$(basename "$f" .csv); b=${b#sipp-}
	base=${b%%.rd*}
	case " $SEEN " in *" $base "*) continue ;; esac
	SEEN="$SEEN $base"
	[[ $base == prereg && -z $STEP && $SCEN != call ]] && continue
	if [[ $b == *.rd* ]]; then
		read -r c o x <<<"$(stats_of $(label_files "$base"))"
		echo "--- SIPp $base ($(ls "$RUN_DIR"/sipp-"$base".rd*.csv | wc -l | tr -d ' ') rounds over $USERS users) ---"
		awk -v c="$c" -v o="$o" -v x="$x" 'BEGIN { printf "calls_created=%d calls_ok=%d calls_failed=%d failed_pct=%.3f\n", c, o, x, (c ? x / c * 100 : 0) }'
		last=$(ls "$RUN_DIR"/sipp-"$base".rd*.csv | sort -V | tail -1)
		awk -F, -f "$HERE/summarize_sipp.awk" "$last" | grep -v '^calls_created'
		continue
	fi
	echo "--- SIPp $b ---"
	awk -F, -f "$HERE/summarize_sipp.awk" "$f"
done
if [[ $SCEN == webrtc ]]; then
	echo "--- webrtcload ---"
	grep '^RESULT' "$RUN_DIR/webrtc.log" | sed 's/^RESULT //'
fi
echo "--- FreeSBC (sampled every ${INTERVAL}s, $METRICS) ---"
awk -F, -f "$HERE/summarize_metrics.awk" "$METRICS"
echo "--- plateau ---"
awk -F, -f "$HERE/plateau_metrics.awk" "$METRICS"
echo "(RTP quality: SIPp does not measure received loss/jitter. Use the webrtc scenario, or FreeSBC's rtp rx vs tx above; see README.)"
