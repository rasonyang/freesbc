#!/usr/bin/env bash
# End-to-end smoke test of the harness on one Linux host: SIPp -> FreeSBC ->
# Asterisk in three network namespaces (netns.sh). It proves the rendered
# configs and scenarios work together before any real server is touched.
# It is not a capacity test: all three "servers" share one kernel and CPU.
#
#   sudo FREESBC=/path/to/freesbc SIPP=/path/to/sipp ./smoke.sh [direct|nat]
#   ABUSE=1 also runs the T6 cases under the production shield profile.
#
# Needs root, iproute2, nftables (nat), asterisk (apt), sipp built with
# PCAP/RTP support, tcpdump, tshark, envsubst, htpasswd, sox.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
mode=${1:-direct}
: "${FREESBC:?set FREESBC to the freesbc binary}" "${SIPP:?set SIPP to the sipp binary}"
work=${WORK:-/tmp/freesbc-smoke}
rm -rf "$work"; mkdir -p "$work"/ast/{etc,run,log,spool,db} "$work/sbc"

stop() {
  pkill -f "asterisk -C $work" 2>/dev/null || true
  pkill -f "freesbc run -c $work" 2>/dev/null || true
  [[ -n ${KEEP:-} ]] || "$here/netns.sh" down
}
trap stop EXIT

ENV_FILE=$here/env.lab.$mode "$here/../render.sh" >/dev/null
out=$here/../out
"$here/netns.sh" up "$mode"

# S3: Asterisk with the rendered config, private dirs under $work
cp "$out"/switch/asterisk/* "$work/ast/etc/"
moddir=$(dirname "$(find /usr/lib -name chan_pjsip.so -path '*asterisk*' | head -1)")
cat >"$work/ast/etc/asterisk.conf" <<EOF
[directories]
astetcdir => $work/ast/etc
astmoddir => $moddir
astvarlibdir => /var/lib/asterisk
astdatadir => /usr/share/asterisk
astdbdir => $work/ast/db
astspooldir => $work/ast/spool
astrundir => $work/ast/run
astlogdir => $work/ast/log
[options]
maxfiles=1048576
verbose=0
EOF
ip netns exec s3 asterisk -C "$work/ast/etc/asterisk.conf" -f >"$work/ast/stdout.log" 2>&1 &
# S2: FreeSBC
cat "$out/sbc/base-asterisk.yaml" "$out/sbc/shield-load.yaml" >"$work/sbc/freesbc.yaml"
ip netns exec s2 "$FREESBC" run -c "$work/sbc/freesbc.yaml" >"$work/sbc/freesbc.log" 2>&1 &
sleep 6
grep -q "edge proxy listening" "$work/sbc/freesbc.log" || { cat "$work/sbc/freesbc.log"; exit 1; }

# S1: the cases, small
export SIPP
cd "$out/sipp"
fail=0
for c in "t1 CC=10 HOLD=5 SECS=10 CAPTURE=1 CAPTURE_DELAY=3 CAPTURE_SECS=6" \
         "t2 CC=10 HOLD=5 SECS=10" \
         "reg-a" "t3 CC=10 HOLD=5 SECS=10" \
         "reg-b" "t4 CC=10 HOLD=5 SECS=10" \
         "unreg-a" "unreg-b"; do
  if ip netns exec s1 ./run.sh $c >"$work/run.log" 2>&1; then r=PASS; else r=FAIL; fail=1; fi
  printf '%-4s %-55s %s\n' "$r" "$c" "$(grep -E 'Successful call' "$work/run.log" | awk -F'|' '{gsub(/ /,"",$3); print "ok=" $3}')"
  [[ $r == PASS ]] || tail -20 "$work/run.log"
done
grep -h "streams=" results/*-t1/rtp_report.txt 2>/dev/null | sed 's/^/     t1 rtp: /'

metric() { ip netns exec s2 curl -fsS -u "admin:$(. "$here/env.lab.$mode"; echo "$SBC_ADMIN_PASSWORD")" \
             http://127.0.0.1:8080/metrics | awk -v k="$1" '$1 == k {print $2}'; }
t6() { # run one T6 case, print SIPp's result and the drop counters it moved
  local c=$1 a0 r0 s0 ok ko
  a0=$(metric 'freesbc_edge_admission_drops_total{reason="invite_not_admitted"}')
  r0=$(metric 'freesbc_shield_drops_total{reason="rate"}'); s0=$(metric 'freesbc_shield_drops_total{reason="scanner"}')
  ip netns exec s1 ./run.sh $c >"$work/run.log" 2>&1 || true
  ok=$(grep -E 'Successful call' "$work/run.log" | awk -F'|' '{gsub(/ /,"",$3); print $3}' || true)
  ko=$(grep -E 'Failed call' "$work/run.log" | awk -F'|' '{gsub(/ /,"",$3); print $3}' || true)
  printf 'T6   %-27s ok=%-4s failed=%-4s admission+%d rate+%d scanner+%d\n' "$c" "${ok:--}" "${ko:--}" \
    $(( $(metric 'freesbc_edge_admission_drops_total{reason="invite_not_admitted"}') - a0 )) \
    $(( $(metric 'freesbc_shield_drops_total{reason="rate"}') - r0 )) \
    $(( $(metric 'freesbc_shield_drops_total{reason="scanner"}') - s0 ))
  T6_OK=$ok T6_KO=$ko
}
if [[ -n ${ABUSE:-} ]]; then
  ip netns exec s1 ./run.sh reg-a >/dev/null 2>&1 || true
  # Admission and the ringing cap under the load profile, so the rate limit
  # does not interfere.
  t6 t6-admission
  [[ $T6_OK == 0 && $T6_KO == 20 ]] || { echo "FAIL admission: expected 0/20"; fail=1; }
  t6 t6-ringcap
  [[ $T6_OK == 64 && $T6_KO == 36 ]] || { echo "FAIL ringing cap: expected 64/36"; fail=1; }
  # The shield itself under the production profile (hot reload).
  NO_SYSTEMD=1 FREESBC_CONFIG=$work/sbc/freesbc.yaml FREESBC_BIN=$FREESBC "$out/sbc/activate.sh" asterisk default >/dev/null
  sleep 1
  t6 "t6-rate CPS=100 T6_SECS=5"
  t6 t6-scanner
  t6 t6-garbage
  NO_SYSTEMD=1 FREESBC_CONFIG=$work/sbc/freesbc.yaml FREESBC_BIN=$FREESBC "$out/sbc/activate.sh" asterisk load >/dev/null
  sleep 1
  ip netns exec s1 ./run.sh unreg-a >/dev/null 2>&1 || true
fi

# Every call, dialog, port and binding must be back to zero.
sleep 3
for g in freesbc_active_calls freesbc_active_sip_dialogs freesbc_active_media_sessions freesbc_media_ports_in_use freesbc_active_registrations; do
  v=$(metric "$g")
  [[ $v == 0 ]] && echo "PASS $g=0" || { echo "FAIL $g=$v"; fail=1; }
done
exit $fail
