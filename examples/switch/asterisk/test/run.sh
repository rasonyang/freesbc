#!/usr/bin/env bash
# End-to-end check of the Asterisk example configs behind a real FreeSBC.
#
#   examples/switch/asterisk/test/run.sh
#
# Needs docker and a Go toolchain. It builds freesbc for linux, starts the switch (the
# configs in the parent directory, addresses rewritten to the test subnets), FreeSBC,
# a client simulator, two carrier simulators and a LAN intruder, runs the checks and
# removes everything. The test subnets differ from the documented ones so the run does
# not collide with a lab that already uses 10.77.0.0/24 or 203.0.113.0/24.
#
#   private 10.78.0.0/24: freesbc .2, switch .10, intruder .50
#   public  198.18.0.0/24: freesbc .7, client .20, carrier-a .30, carrier-b (mobile) .31:16060
#
# Env: IMG (default andrius/asterisk:latest), WORK (default ~/.cache/freesbc-asterisk-test,
# must be under a path docker can bind-mount), KEEP=1 to leave the containers running.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
EX=$(dirname "$HERE")
REPO=$(cd "$EX/../../.." && pwd)
IMG=${IMG:-andrius/asterisk:latest}
WORK=${WORK:-$HOME/.cache/freesbc-asterisk-test}
P=ast108   # name prefix for networks and containers
fail=0

cleanup() {
  [ "${KEEP:-0}" = 1 ] && return
  docker rm -f $P-sw $P-cli $P-carA $P-carB $P-fsbc $P-intr >/dev/null 2>&1
  docker network rm $P-pub $P-priv >/dev/null 2>&1
}
trap cleanup EXIT
cleanup

check() { # description, command...
  local d=$1; shift
  if "$@" >/dev/null 2>&1; then echo "PASS  $d"; else echo "FAIL  $d"; fail=1; fi
}
log() { docker logs "$P-$1" 2>&1 | sed 's/\x1b\[[0-9;]*m//g'; }
rx() { docker exec "$P-$1" asterisk -rx "$2"; }
has() { log "$1" | grep -Eq "$2"; }   # container, regex
wait_for() { local n=0; until "$@" >/dev/null 2>&1; do n=$((n+1)); [ $n -gt 90 ] && return 1; sleep 1; done; }

arch=$(docker version -f '{{.Server.Arch}}' 2>/dev/null); arch=${arch:-arm64}
rm -rf "$WORK"; mkdir -p "$WORK"; cd "$WORK" || exit 1
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$WORK/freesbc" ./cmd/freesbc) || exit 1

# --- configs --------------------------------------------------------------
docker create --name $P-tmp "$IMG" >/dev/null && docker cp $P-tmp:/etc/asterisk base && docker rm $P-tmp >/dev/null
for n in sw cli carA carB; do
  cp -r base $n
  printf '[general]\n[logfiles]\nconsole => notice,warning,error,verbose\n' > $n/logger.conf
done
for f in pjsip.conf extensions.conf acl.conf; do
  sed -e 's/10\.77\.0\./10.78.0./g' -e 's/sip\.carrier-a\.com/198.18.0.30/g' \
      -e 's/223\.76\.90\.4:16060/198.18.0.31:16060/g' "$EX/$f" > sw/$f
done

cat > freesbc.yaml <<'Y'
public: {ip: 198.18.0.7}
private: {ip: 10.78.0.2}
rtp: 20000-20999
edge:
  switch: [10.78.0.10:5060]
  switch_carrier_port: 5080
  listen: {udp: 5060}
  carriers:
    carrier-a: 198.18.0.30
    mobile: 198.18.0.31:16060
Y

# client simulator: registers 1001 through FreeSBC, answers with Echo
cat > cli/pjsip.conf <<'Y'
[global]
type=global
endpoint_identifier_order=ip
[t]
type=transport
protocol=udp
bind=198.18.0.20:5060
[sw]
type=endpoint
context=incoming
disallow=all
allow=ulaw,alaw
direct_media=no
outbound_auth=1001
aors=sw
from_user=1001
[sw]
type=aor
contact=sip:198.18.0.7:5060
[sw]
type=identify
endpoint=sw
match=198.18.0.7
[1001]
type=auth
auth_type=userpass
username=1001
password=CHANGE-ME-1001
[1001]
type=registration
outbound_auth=1001
server_uri=sip:198.18.0.7
client_uri=sip:1001@198.18.0.7
contact_user=1001
expiration=120
Y
cat > cli/extensions.conf <<'Y'
[incoming]
exten => _X.,1,NoOp(CLIENT SIM got call to ${EXTEN})
 same => n,Answer()
 same => n,Echo()
 same => n,Hangup()
[out]
exten => _X.,1,Dial(PJSIP/${EXTEN}@sw,30)
[tone]
exten => s,1,Set(TIMEOUT(absolute)=4)
 same => n,Milliwatt()
[spoof]
exten => _X.,1,Dial(PJSIP/${EXTEN}@sw,30,b(addhdr^s^1))
[addhdr]
exten => s,1,Set(PJSIP_HEADER(add,X-FreeSBC-Carrier)=carrier-a)
 same => n,Return()
Y

# carrier-a simulator: digest-protected registrar, challenges INVITEs, refuses 0155555559
cat > carA/pjsip.conf <<'Y'
[global]
type=global
endpoint_identifier_order=username,ip
[t]
type=transport
protocol=udp
bind=198.18.0.30:5060
[acct]
type=endpoint
context=from-switch
disallow=all
allow=ulaw,alaw
direct_media=no
auth=acct
aors=acct
[acct]
type=auth
auth_type=userpass
username=acct
password=CHANGE-ME-CARRIER-A
[acct]
type=aor
max_contacts=1
remove_existing=yes
[acct]
type=identify
endpoint=acct
match=198.18.0.7
Y
cat > carA/extensions.conf <<'Y'
[from-switch]
exten => 0155555559,1,NoOp(CARRIER-A SIM refusing ${EXTEN})
 same => n,Congestion()
exten => _X.,1,NoOp(CARRIER-A SIM got call to ${EXTEN} from ${CALLERID(num)})
 same => n,Answer()
 same => n,Echo()
 same => n,Hangup()
Y

# carrier-b ("mobile") simulator: IP-trusted, port 16060, calls the switch by DID
cat > carB/pjsip.conf <<'Y'
[global]
type=global
endpoint_identifier_order=ip
[t]
type=transport
protocol=udp
bind=198.18.0.31:16060
[fsbc]
type=endpoint
context=from-switch
disallow=all
allow=ulaw,alaw
direct_media=no
aors=fsbc
[fsbc]
type=aor
contact=sip:198.18.0.7:5060
[fsbc]
type=identify
endpoint=fsbc
match=198.18.0.7
Y
cat > carB/extensions.conf <<'Y'
[from-switch]
exten => _X.,1,NoOp(CARRIER-B SIM got call to ${EXTEN} from ${CALLERID(num)})
 same => n,Answer()
 same => n,Echo()
 same => n,Hangup()
Y

# --- topology -------------------------------------------------------------
docker network create --subnet 198.18.0.0/24 $P-pub >/dev/null
docker network create --subnet 10.78.0.0/24 $P-priv >/dev/null
ast() { docker run -d --name $P-$1 --network $2 --ip $3 -v "$WORK/$4:/etc/asterisk" --entrypoint asterisk "$IMG" -f -vvv >/dev/null; }
# Start order matters: registrations are attempted once at startup and retried only
# after a long interval, so the registrar side (carriers, FreeSBC) comes up before
# the switch, and the switch before the client.
ast carA $P-pub 198.18.0.30 carA
ast carB $P-pub 198.18.0.31 carB
# Create, attach both networks, then start: FreeSBC checks at startup that both bind
# addresses are assigned to a local interface.
docker create --name $P-fsbc --network $P-priv --ip 10.78.0.2 --cap-add NET_ADMIN -v "$WORK:/w" \
  --entrypoint /w/freesbc debian:bookworm-slim run -c /w/freesbc.yaml >/dev/null
docker network connect --ip 198.18.0.7 $P-pub $P-fsbc
docker start $P-fsbc >/dev/null
sleep 3
ast sw $P-priv 10.78.0.10 sw
sleep 8
ast cli $P-pub 198.18.0.20 cli
docker run -d --name $P-intr --network $P-priv --ip 10.78.0.50 alpine:3 sleep 600 >/dev/null

echo "Asterisk: $(rx sw 'core show version' 2>/dev/null | head -1)"
reg_up() { rx "$1" 'pjsip show registrations' | grep -q Registered; }
wait_for reg_up sw  || { echo "FAIL  carrier-a registration"; fail=1; }
wait_for reg_up cli || { echo "FAIL  client registration"; fail=1; }
rx cli 'pjsip set logger on' >/dev/null

# --- 1. clients -----------------------------------------------------------
check "client 1001 registered with digest; stored Contact keeps fsbc=" \
  bash -c "docker exec $P-sw asterisk -rx 'pjsip show contacts' | grep -q 'transport=udp;fsb'"
rx cli 'channel originate Local/600@out extension s@tone' >/dev/null; sleep 7
check "client -> 600 Echo reached the dialplan after a digest challenge" has sw 'Executing \[600@from-clients:2\] Echo'
check "client call carried RTP both ways through FreeSBC" has fsbc 'carrier=false stats=.*RTPPacketsRx:[1-9]'
rx sw 'channel originate PJSIP/1001 application Milliwatt' >/dev/null; sleep 4; rx sw 'channel request hangup all' >/dev/null; sleep 1
check "switch -> registered client call rang the client" has cli 'CLIENT SIM got call to 1001'

# --- 2. carriers ----------------------------------------------------------
check "carrier-a REGISTER through FreeSBC succeeded" bash -c "docker exec $P-carA asterisk -rx 'pjsip show contacts' | grep -q 'acct/sip:acct@198.18.0.7:5060;fsbc='"
rx cli 'channel originate Local/0112345678@out extension s@tone' >/dev/null; sleep 7
check "outbound via carrier-a (carrier digest-challenged the INVITE)" has carA 'CARRIER-A SIM got call to 0112345678'
rx cli 'channel originate Local/0155555559@out extension s@tone' >/dev/null; sleep 8
check "carrier-a refused 0155555559, Dial failed over to mobile" has carB 'CARRIER-B SIM got call to 0155555559'
rx carA 'channel originate PJSIP/acct application Milliwatt' >/dev/null; sleep 4; rx carA 'channel request hangup all' >/dev/null; sleep 1
check "inbound carrier-a call identified by X-FreeSBC-Carrier" has sw 'carrier=carrier-a X-FreeSBC-Carrier=carrier-a DID=acct'
rx carB 'channel originate PJSIP/5551001@fsbc application Milliwatt' >/dev/null; sleep 4; rx carB 'channel request hangup all' >/dev/null; sleep 1
check "inbound DID call from mobile identified as endpoint mobile" has sw 'carrier=mobile X-FreeSBC-Carrier=mobile DID=5551001'

# --- 3. / 4. boundaries ---------------------------------------------------
invite() { # dst:port, extra header line (may be empty)
  local ip=${1%:*} port=${1#*:}
  printf 'INVITE sip:600@%s SIP/2.0\r\nVia: SIP/2.0/UDP 10.78.0.50:5099;branch=z9hG4bKt%s\r\nFrom: <sip:1001@10.78.0.50>;tag=a%s\r\nTo: <sip:600@%s>\r\nCall-ID: t%s@x\r\nCSeq: 1 INVITE\r\nContact: <sip:1001@10.78.0.50:5099>\r\nMax-Forwards: 70\r\n%bContent-Length: 0\r\n\r\n' \
    "$1" $$ $$ "$1" $$ "${2:+$2\r\n}" | docker exec -i $P-intr sh -c "nc -u -p 5099 -w 2 $ip $port"
}
out=$(invite 10.78.0.10:5080 "X-FreeSBC-Carrier: carrier-a"); sleep 1
check "5080 from a LAN host that is not private.ip, forged header: rejected by ACL" has sw "failure to pass ACL 'freesbc-only'"
check "  ... and answered 401, never identified as the carrier" bash -c "echo '$out' | grep -q '401 Unauthorized'"
out=$(invite 10.78.0.10:5060 ""); sleep 1
check "5060 INVITE without credentials is challenged (401)" bash -c "echo '$out' | grep -q '401 Unauthorized'"
rx cli 'channel originate Local/600@spoof extension s@tone' >/dev/null; sleep 7
check "client forged X-FreeSBC-Carrier (sent on the wire)" has cli 'X-FreeSBC-Carrier: carrier-a'
check "  ... FreeSBC stripped it: the switch never ran from-carrier for it" bash -c "! docker logs $P-sw 2>&1 | grep -q 'Executing \[600@from-carrier'"

# --- limits ---------------------------------------------------------------
for i in 1 2 3; do rx cli 'channel originate Local/0112345678@out extension s@tone' >/dev/null; sleep 0.3; done; sleep 7
check "third concurrent outbound call of one user got Busy (GROUP_COUNT)" has sw 'Executing \[s@outbound:[0-9]+\] Busy\('

echo; [ $fail = 0 ] && echo "ALL PASS" || echo "SOME CHECKS FAILED"
exit $fail
