#!/usr/bin/env bash
# FreeSBC load-test driver on S1 (SIPp). Run from the rendered out/sipp dir.
#
#   ./run.sh <case> [VAR=value ...]
#
# Cases (README §5 has the matrix):
#   t1            carrier -> FreeSBC -> switch, echo                (CPS, CC, HOLD)
#   t2            carrier -> switch -> carrier, hairpin via FreeSBC (CPS, CC, HOLD)
#   reg-a|unreg-a register / remove the calling phones   (users_a, port SIPP_CLIENT_A_PORT)
#   t3            registered phone -> FreeSBC -> switch echo        (CPS, CC, HOLD)
#   reg-b|unreg-b register / remove the agents           (users_b, port SIPP_CLIENT_B_PORT)
#   t4            carrier -> switch -> registered agent             (CPS, CC, HOLD)
#   t5            REGISTER storm (users_a)                          (CPS, N_REG)
#   t6-admission  INVITE from an unregistered phone socket: expect no answer
#   t6-rate       OPTIONS above shield.rate_limit: expect drops     (CPS, T6_SECS)
#   t6-scanner    OPTIONS with a scanner User-Agent: expect drops
#   t6-ringcap    100 calls held ringing from one IP: expect 64 + 36 x 503
#   t6-garbage    COUNT [2000] malformed datagrams: shows they bypass the shield
#   ramp          run CASE at each of STEPS concurrent calls        (CASE, STEPS, HOLD, STEP_SECS)
#
# Variables (defaults in brackets):
#   CPS [CC/HOLD]  calls per second      CC [100]  concurrent calls (-l)
#   HOLD [60]      seconds a call lasts  SECS [300] how long to keep offering calls
#   N              total calls (default CPS*SECS)
#   CAPTURE [0]    1 = tcpdump RTP on S1 for CAPTURE_SECS [20] mid-run, then rtp_report.sh
#   LABEL          free text added to the result directory name
set -euo pipefail
cd "$(dirname "$0")"
set -a; . ./env; set +a
for kv in "${@:2}"; do export "${kv?}"; done
case_=${1:?usage: run.sh <case> [VAR=value ...]}

SIPP=${SIPP:-sipp}
TARGET=$SBC_PUBLIC_IP:5060
CC=${CC:-100}; HOLD=${HOLD:-60}; SECS=${SECS:-300}
CALL_CPS=${CPS:-$(( (CC + HOLD - 1) / HOLD ))}
N=${N:-$(( CALL_CPS * SECS ))}
ts=$(date +%Y%m%d-%H%M%S)
res=results/$ts-$case_${LABEL:+-$LABEL}
mkdir -p "$res"
ulimit -n 1048576 2>/dev/null || ulimit -n "$(ulimit -Hn)"

common=(-t u1 -bind_local -nostdin -aa
        -min_rtp_port "$SIPP_RTP_MIN" -max_rtp_port "$SIPP_RTP_MAX" -rtp_threadtasks 20
        -buff_size 4194304 -max_socket 100000
        -trace_stat -stf "$res/stat.csv" -fd 5
        -trace_rtt -rtt_freq 100 -trace_counts
        -trace_err -error_file "$res/errors.log"
        -trace_screen -screen_file "$res/screen.log")
load=(-r "$CALL_CPS" -rp 1000 -l "$CC" -m "$N" -d $(( HOLD * 1000 )))

bg_pids=()
cleanup() { for p in "${bg_pids[@]:-}"; do [[ -n $p ]] && kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

note() { echo "$*" | tee -a "$res/meta.txt"; }
sipp_run() { # $1 name, rest: sipp args. Foreground; returns SIPp's status.
  local name=$1; shift
  note "[$name] $SIPP $*"
  set +e; "$SIPP" "$@" >"$res/$name.out" 2>&1; local rc=$?; set -e
  mv -f scenarios/*_rtt.csv scenarios/*_counts.csv ./*_rtt.csv ./*_counts.csv "$res/" 2>/dev/null || true
  note "[$name] exit $rc"
  return $rc
}
sipp_bg() { # $1 name, rest: sipp args. A far end that runs until the case ends.
  local name=$1; shift
  note "[$name] $SIPP $* (background)"
  "$SIPP" "$@" -trace_screen -screen_file "$res/$name.screen.log" -trace_err -error_file "$res/$name.errors.log" \
    >"$res/$name.out" 2>&1 &
  bg_pids+=($!)
  sleep 1
  kill -0 "${bg_pids[-1]}" 2>/dev/null || { cat "$res/$name.out" >&2; echo "far end failed to start" >&2; exit 1; }
}
capture() { # tcpdump RTP from FreeSBC to SIPp mid-run, then analyse it
  [[ ${CAPTURE:-0} == 1 ]] || return 0
  ( sleep "${CAPTURE_DELAY:-$(( HOLD / 2 + 5 ))}"
    timeout "${CAPTURE_SECS:-20}" tcpdump -i any -n -s 256 -w "$res/rtp.pcap" \
      "udp and src host $SBC_PUBLIC_IP and portrange $SIPP_RTP_MIN-$SIPP_RTP_MAX" 2>/dev/null || true
    ./rtp_report.sh "$res/rtp.pcap" >"$res/rtp_report.txt" 2>&1 || true ) &
  bg_pids+=($!)
}
summary() {
  local f
  f=$(ls -t "$res"/*screen.log 2>/dev/null | grep -v '\.screen\.log$' | head -1 || true)
  [[ -n $f ]] && awk '/Successful call|Failed call|Retransmissions|Total Call created|Call Rate/' "$f" | tee -a "$res/meta.txt"
  [[ -f $res/rtp_report.txt ]] && tail -5 "$res/rtp_report.txt"
  echo "results: $res"
}

carrier=(-i "$SIPP_CARRIER_BIND" -p "$SIPP_CARRIER_UAC_PORT")
phone_a=(-i "$SIPP_CLIENT_BIND" -p "$SIPP_CLIENT_A_PORT")
phone_b=(-i "$SIPP_CLIENT_BIND" -p "$SIPP_CLIENT_B_PORT")
note "case=$case_ target=$TARGET CPS=$CALL_CPS CC=$CC HOLD=${HOLD}s N=$N"

rc=0
case $case_ in
t1)
  capture
  sipp_run caller "$TARGET" -sf scenarios/carrier_uac.xml -inf data/did_echo.csv "${carrier[@]}" "${load[@]}" "${common[@]}" || rc=$? ;;
t2)
  sipp_bg carrier-far -sf scenarios/uas.xml -i "$SIPP_CARRIER_BIND" -p "$SIPP_CARRIER_UAS_PORT" -t u1 -bind_local -nostdin \
    -min_rtp_port "$SIPP_RTP_MIN" -max_rtp_port "$SIPP_RTP_MAX" -rtp_threadtasks 20 -buff_size 4194304 -max_socket 100000 -d 0
  capture
  sipp_run caller "$TARGET" -sf scenarios/carrier_uac.xml -inf data/did_hairpin.csv "${carrier[@]}" "${load[@]}" "${common[@]}" || rc=$? ;;
reg-a|unreg-a|reg-b|unreg-b)
  [[ $case_ == *-a ]] && { users=data/users_a.csv; ep=("${phone_a[@]}"); count=$USERS_A_COUNT; } \
                      || { users=data/users_b.csv; ep=("${phone_b[@]}"); count=$USERS_B_COUNT; }
  [[ $case_ == unreg-* ]] && scen=scenarios/client_unreg.xml || scen=scenarios/client_reg.xml
  sipp_run register "$TARGET" -sf "$scen" -inf "$users" -key expires "${EXPIRES:-3600}" "${ep[@]}" \
    -r "${CPS:-50}" -l 200 -m "$count" "${common[@]}" || rc=$? ;;
t3)
  capture
  sipp_run caller "$TARGET" -sf scenarios/client_uac.xml -inf data/users_a.csv -s 7100 "${phone_a[@]}" "${load[@]}" "${common[@]}" || rc=$? ;;
t4)
  sipp_bg agents -sf scenarios/uas.xml -i "$SIPP_CLIENT_BIND" -p "$SIPP_CLIENT_B_PORT" -t u1 -bind_local -nostdin \
    -min_rtp_port "$SIPP_RTP_MIN" -max_rtp_port "$SIPP_RTP_MAX" -rtp_threadtasks 20 -buff_size 4194304 -max_socket 100000 -d "${RING_MS:-0}"
  capture
  sipp_run caller "$TARGET" -sf scenarios/carrier_uac.xml -inf data/did_agents.csv "${carrier[@]}" "${load[@]}" "${common[@]}" || rc=$? ;;
t5)
  sipp_run register "$TARGET" -sf scenarios/client_reg.xml -inf data/users_a.csv -key expires 3600 "${phone_a[@]}" \
    -r "${CPS:-200}" -l 5000 -m "${N_REG:-$USERS_A_COUNT}" "${common[@]}" || rc=$? ;;
t6-admission)
  # Same IP as the phones, a socket that never registered: every INVITE must vanish.
  sipp_run caller "$TARGET" -sf scenarios/client_uac.xml -inf data/users_a.csv -s 7100 -i "$SIPP_CLIENT_BIND" -p 5099 \
    -r 5 -m 20 -recv_timeout 4000 "${common[@]}" || true
  note "expect: 20 failed calls (timeouts); freesbc_edge_admission_drops_total{reason=\"invite_not_admitted\"} grows by 20 x (1 + retransmissions), ~80" ;;
t6-rate)
  sipp_run probe "$TARGET" -sf scenarios/options.xml -key ua load-phone -i "$SIPP_CLIENT_BIND" -p 5098 \
    -r "${CPS:-200}" -m $(( ${CPS:-200} * ${T6_SECS:-10} )) -recv_timeout 2000 "${common[@]}" || true
  note "expect with shield-default (20/s per_ip): ~20 answered per second, the rest timed out; freesbc_shield_drops_total{reason=\"rate\"} rises" ;;
t6-scanner)
  sipp_run probe "$TARGET" -sf scenarios/options.xml -key ua friendly-scanner -i "$SIPP_CLIENT_BIND" -p 5097 \
    -r 1 -m 5 -recv_timeout 2000 "${common[@]}" || true
  note "expect: 5 timeouts; freesbc_shield_drops_total{reason=\"scanner\"} += 1: the first datagram bans socket :5097 for 1 min and later ones die uncounted in the read filter; other ports of this IP still work" ;;
t6-ringcap)
  sipp_run caller "$TARGET" -sf scenarios/client_uac.xml -inf data/users_a.csv -s 7101 "${phone_a[@]}" \
    -r 100 -l 100 -m 100 -d 1000 "${common[@]}" || true
  note "expect: 64 answered after ~30 s, 36 failed with 503 (maxEarlyPerSource); not applicable from a carrier source" ;;
t6-garbage)
  # Malformed SIP is rejected by the parser, which runs before the shield.
  python3 - "$SIPP_CLIENT_BIND" "$SBC_PUBLIC_IP" "${COUNT:-2000}" <<'PY'
import socket, sys, time
src, dst, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((src, 5096))
msg = b"INVITE sip:x@" + dst.encode() + b" SIP/2.0\r\nVia: broken\r\nX-Pad: " + b"A" * 1200 + b"\r\n\r\n"
for i in range(n):
    s.sendto(msg, (dst, 5060))
    if i % 100 == 99: time.sleep(0.01)
PY
  note "sent ${COUNT:-2000} malformed datagrams from :5096"
  note "expect: no response; freesbc_shield_drops_total unchanged (the parser runs before the shield); S2 logs one ERROR \"failed to parse\" line carrying the raw datagram per message" ;;
ramp)
  inner=${CASE:?ramp needs CASE=t1|t2|t3|t4}
  for step in ${STEPS:?ramp needs STEPS=\"100 250 500 ...\"}; do
    "$0" "$inner" CC="$step" HOLD="$HOLD" SECS="${STEP_SECS:-300}" CPS="$(( (step + HOLD - 1) / HOLD ))" \
      LABEL="cc$step${LABEL:+-$LABEL}" N="" ${CAPTURE:+CAPTURE=$CAPTURE} || { echo "step $step failed; stopping the ramp"; exit 1; }
    sleep "${COOL_SECS:-60}"   # let every call, binding and port drain before the next step
  done ;;
*) echo "unknown case $case_" >&2; exit 2 ;;
esac

# Give far ends time to see the last BYEs before they are killed.
(( ${#bg_pids[@]} )) && sleep 5
summary
exit $rc
