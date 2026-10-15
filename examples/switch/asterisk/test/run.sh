#!/usr/bin/env bash
# End-to-end check of the Asterisk example configs behind two real FreeSBC nodes.
#
#   examples/switch/asterisk/test/run.sh
#
# Needs docker and a Go toolchain. It builds freesbc for linux, starts the switch (the
# configs in the parent directory, addresses rewritten to the test subnets), FreeSBC
# nodes A and B, client simulators, two carrier simulators and a LAN intruder, runs the
# checks and removes everything. The test subnets differ from the documented ones so the
# run does not collide with a lab that already uses 10.77.0.0/24 or 203.0.113.0/24.
#
#   private 10.78.0.0/24: freesbc A .2, freesbc B .3, switch .10, intruder .50
#   public  198.18.0.0/24: freesbc A .7, freesbc B .8, client (via A) .20, client (via B) .21,
#                          carrier-a .30, carrier-b (mobile) .31:16060
#
# The nodes share one config (addresses from the environment). The test shortens three
# timers of the shipped files in the switch's copy: rtp_timeout 30 -> 10 s, the carrier
# qualify_frequency 30 -> 5 s, and it turns qualify on (5 s) for client 1002 only.
# Client failover is modelled by a second client simulator that registers the same user
# through node B once node A is gone; carrier failover by carrier simulators that try the
# next SBC address on 503 or after a 3 s timeout.
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
  docker rm -f $P-sw $P-cli $P-cliB $P-carA $P-carB $P-fsa $P-fsb $P-intr >/dev/null 2>&1
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
cnt() { log "$1" | grep -Ec "$2"; }   # container, regex: number of matching log lines
secs() { date +%s; }
# wait_cnt container regex above-count timeout-seconds: wait until the log has more than N matching lines
wait_cnt() { local t0; t0=$(secs); until [ "$(cnt "$1" "$2")" -gt "$3" ]; do sleep 1; [ $(( $(secs) - t0 )) -gt "$4" ] && return 1; done; return 0; }
# a call file makes the switch originate a call with a longer timeout than 'channel originate' (30 s)
callfile() { # channel
  printf 'Channel: %s\nApplication: Wait\nData: 120\nWaitTime: 100\n' "$1" | \
    docker exec -i $P-sw sh -c "cat > /tmp/cf$$.call && chown asterisk /tmp/cf$$.call && mv /tmp/cf$$.call /var/spool/asterisk/outgoing/"
}
# number of responses with this status to an OPTIONS, from the pjsip logger of container $1
opt_resp() { log "$1" | awk -v st="$2" '/^SIP\/2.0 /{r=($2==st)} r&&/^CSeq:.*OPTIONS/{n++;r=0} /^$/{r=0} END{print n+0}'; }
wait_for() { local n=0; until "$@" >/dev/null 2>&1; do n=$((n+1)); [ $n -gt 90 ] && return 1; sleep 1; done; }

arch=$(docker version -f '{{.Server.Arch}}' 2>/dev/null); arch=${arch:-arm64}
rm -rf "$WORK"; mkdir -p "$WORK"; cd "$WORK" || exit 1
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$WORK/freesbc" ./cmd/freesbc) || exit 1

# --- configs --------------------------------------------------------------
docker create --name $P-tmp "$IMG" >/dev/null && docker cp $P-tmp:/etc/asterisk base && docker rm $P-tmp >/dev/null
for n in sw cli cliB carA carB; do
  cp -r base $n
  printf '[general]\n[logfiles]\nconsole => notice,warning,error,verbose\n' > $n/logger.conf
done
for f in pjsip.conf extensions.conf acl.conf; do
  sed -e 's/10\.77\.0\./10.78.0./g' -e 's/sip\.carrier-a\.com/198.18.0.30/g' \
      -e 's/223\.76\.90\.4:16060/198.18.0.31:16060/g' "$EX/$f" > sw/$f
done
# Shorter timers for the test (see the header), and qualify on client 1002 only.
sed -e 's/^rtp_timeout=30/rtp_timeout=10/' -e 's/^qualify_frequency=30/qualify_frequency=5/' \
    -e 's/^\[1002\](client-aor)$/&\
qualify_frequency=5\
qualify_timeout=3/' sw/pjsip.conf > sw/pjsip.conf.new && mv sw/pjsip.conf.new sw/pjsip.conf
# probe: dial a user from the switch and log the result and the time it took
cat >> sw/extensions.conf <<'Y'

[t]
; outbound carrier call placed from the switch itself, as user 1001 (does not depend on any FreeSBC node)
exten => _carrier.,1,Set(CALLERID(num)=1001)
 same => n,Gosub(outbound,s,1(${EXTEN:7}))
 same => n,Hangup()
exten => _probe.,1,Set(S=${EPOCH})
 same => n,Dial(PJSIP/${EXTEN:5},40)
 same => n,NoOp(T-RESULT ${EXTEN:5} DIALSTATUS=${DIALSTATUS} HANGUPCAUSE=${HANGUPCAUSE} SECS=$[${EPOCH}-${S}])
Y

PW=test-admin-pw
HASH=$(printf '%s' "$PW" | docker run --rm -i -v "$WORK:/w" debian:bookworm-slim /w/freesbc hash-password | tail -1)
AUTH=$(printf 'admin:%s' "$PW" | base64)
# One config for both nodes: only the addresses differ, supplied through ${VAR}.
cat > freesbc.yaml <<'Y'
public: {ip: "${PUB_IP}"}
private: {ip: "${PRIV_IP}"}
rtp: 20000-20999
admin: {listen: "127.0.0.1:8080", password_hash: "${ADMIN_HASH}"}
edge:
  switch: [10.78.0.10:5060]
  switch_carrier_port: 5080
  listen: {udp: 5060}
  carriers:
    carrier-a: 198.18.0.30
    mobile: 198.18.0.31:16060
Y

# client simulator: registers 1001 and 1002 through the given FreeSBC node, answers with Echo
mkcli() { # dir, own public ip, FreeSBC public ip, users...
  local d=$1 me=$2 fs=$3; shift 3
  cat > $d/pjsip.conf <<Y
[global]
type=global
endpoint_identifier_order=ip
[t]
type=transport
protocol=udp
bind=$me:5060
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
contact=sip:$fs:5060
[sw]
type=identify
endpoint=sw
match=$fs
Y
  for u in "$@"; do cat >> $d/pjsip.conf <<Y
[$u]
type=auth
auth_type=userpass
username=$u
password=CHANGE-ME-$u
[$u]
type=registration
outbound_auth=$u
server_uri=sip:$fs
client_uri=sip:$u@$fs
contact_user=$u
expiration=120
Y
  done
  cat > $d/extensions.conf <<'Y'
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
}
mkcli cli 198.18.0.20 198.18.0.7 1001 1002
mkcli cliB 198.18.0.21 198.18.0.8 1001

# carrier-a simulator: digest-protected registrar with two accounts (acct through node A,
# acct-b through node B), challenges INVITEs, refuses 0155555559. [trunk] is the carrier's
# own failover: acct (node A), then acct-b (node B) on 503 or after 3 s.
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
[acct-b]
type=endpoint
context=from-switch
disallow=all
allow=ulaw,alaw
direct_media=no
auth=acct-b
aors=acct-b
[acct-b]
type=auth
auth_type=userpass
username=acct-b
password=CHANGE-ME-CARRIER-A-B
[acct-b]
type=aor
max_contacts=1
remove_existing=yes
[acct-b]
type=identify
endpoint=acct-b
match=198.18.0.8
Y
cat > carA/extensions.conf <<'Y'
[from-switch]
exten => 0155555559,1,NoOp(CARRIER-A SIM refusing ${EXTEN})
 same => n,Congestion()
exten => _X.,1,NoOp(CARRIER-A SIM got call to ${EXTEN} from ${CALLERID(num)})
 same => n,Answer()
 same => n,Echo()
 same => n,Hangup()
[trunk]
exten => _X.,1,Dial(PJSIP/acct,3)
 same => n,NoOp(TRUNK acct DIALSTATUS=${DIALSTATUS})
 same => n,GotoIf($["${DIALSTATUS}" = "ANSWER"]?done)
 same => n,Dial(PJSIP/acct-b,10)
 same => n,NoOp(TRUNK acct-b DIALSTATUS=${DIALSTATUS})
 same => n(done),Hangup()
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
[fsbc-b]
type=endpoint
context=from-switch
disallow=all
allow=ulaw,alaw
direct_media=no
aors=fsbc-b
[fsbc-b]
type=aor
contact=sip:198.18.0.8:5060
[fsbc-b]
type=identify
endpoint=fsbc-b
match=198.18.0.8
Y
cat > carB/extensions.conf <<'Y'
[from-switch]
exten => _X.,1,NoOp(CARRIER-B SIM got call to ${EXTEN} from ${CALLERID(num)})
 same => n,Answer()
 same => n,Echo()
 same => n,Hangup()
; The carrier is given both SBC addresses: node A first, node B on 503 or after 3 s.
[trunk]
exten => _X.,1,Dial(PJSIP/${EXTEN}@fsbc,3)
 same => n,NoOp(TRUNK fsbc DIALSTATUS=${DIALSTATUS})
 same => n,GotoIf($["${DIALSTATUS}" = "ANSWER"]?done)
 same => n,Dial(PJSIP/${EXTEN}@fsbc-b,10)
 same => n,NoOp(TRUNK fsbc-b DIALSTATUS=${DIALSTATUS})
 same => n(done),Hangup()
Y

# --- topology -------------------------------------------------------------
docker network create --subnet 198.18.0.0/24 $P-pub >/dev/null
docker network create --subnet 10.78.0.0/24 $P-priv >/dev/null
ast() { docker run -d --name $P-$1 --network $2 --ip $3 -v "$WORK/$4:/etc/asterisk" --entrypoint asterisk "$IMG" -f -vvv >/dev/null; }
# FreeSBC node: name, private ip, public ip. Create, attach both networks, then start:
# FreeSBC checks at startup that both bind addresses are assigned to a local interface.
fsbc() {
  docker create --name $P-$1 --network $P-priv --ip $2 --cap-add NET_ADMIN -v "$WORK:/w" \
    -e PRIV_IP=$2 -e PUB_IP=$3 -e ADMIN_HASH="$HASH" \
    --entrypoint /w/freesbc debian:bookworm-slim run -c /w/freesbc.yaml >/dev/null
  docker network connect --ip $3 $P-pub $P-$1
  docker start $P-$1 >/dev/null
}
# admin API of a node, from inside its network namespace (admin listens on loopback)
adm() { # node METHOD path
  docker run --rm --network container:$P-$1 alpine:3 sh -c \
    'printf "%s %s HTTP/1.0\r\nHost: 127.0.0.1:8080\r\nAuthorization: Basic %s\r\nOrigin: http://127.0.0.1:8080\r\n\r\n" "$0" "$1" "$2" | nc -w 3 127.0.0.1 8080' "$2" "$3" "$AUTH" 2>&1
}
# Start order matters: registrations are attempted once at startup and retried only
# after a long interval, so the registrar side (carriers, FreeSBC) comes up before
# the switch, and the switch before the client.
ast carA $P-pub 198.18.0.30 carA
ast carB $P-pub 198.18.0.31 carB
fsbc fsa 10.78.0.2 198.18.0.7
fsbc fsb 10.78.0.3 198.18.0.8
sleep 3
ast sw $P-priv 10.78.0.10 sw
sleep 8
ast cli $P-pub 198.18.0.20 cli
docker run -d --name $P-intr --network $P-priv --ip 10.78.0.50 alpine:3 sleep 3000 >/dev/null

echo "Asterisk: $(rx sw 'core show version' 2>/dev/null | head -1)"
nreg() { rx "$1" 'pjsip show registrations' | grep -c Registered; }
reg2() { [ "$(nreg "$1")" -ge 2 ]; }
reg1() { [ "$(nreg "$1")" -ge 1 ]; }
wait_for reg2 sw  || { echo "FAIL  carrier-a registrations through both nodes"; fail=1; }
wait_for reg2 cli || { echo "FAIL  client registrations"; fail=1; }
rx cli 'pjsip set logger on' >/dev/null
rx sw 'pjsip set logger on' >/dev/null

# --- 1. clients -----------------------------------------------------------
check "client 1001 registered with digest; stored Contact keeps fsbc=" \
  bash -c "docker exec $P-sw asterisk -rx 'pjsip show contacts' | grep -q 'transport=udp;fsb'"
rx cli 'channel originate Local/600@out extension s@tone' >/dev/null; sleep 7
check "client -> 600 Echo reached the dialplan after a digest challenge" has sw 'Executing \[600@from-clients:2\] Echo'
check "client call carried RTP both ways through FreeSBC" has fsa 'carrier=false stats=.*RTPPacketsRx:[1-9]'
rx sw 'channel originate PJSIP/1001 application Milliwatt' >/dev/null; sleep 4; rx sw 'channel request hangup all' >/dev/null; sleep 1
check "switch -> registered client call rang the client" has cli 'CLIENT SIM got call to 1001'

# --- 2. carriers ----------------------------------------------------------
check "carrier-a REGISTER through FreeSBC node A succeeded" bash -c "docker exec $P-carA asterisk -rx 'pjsip show contacts' | grep -q 'acct/sip:acct@198.18.0.7:5060;fsbc='"
check "carrier-a REGISTER (account acct-b) through node B succeeded" bash -c "docker exec $P-carA asterisk -rx 'pjsip show contacts' | grep -q 'acct-b/sip:acct-b@198.18.0.8:5060;fsbc='"
rx cli 'channel originate Local/0112345678@out extension s@tone' >/dev/null; sleep 7
check "outbound via carrier-a (carrier digest-challenged the INVITE)" has carA 'CARRIER-A SIM got call to 0112345678'
check "  ... through node A (first Dial target)" bash -c "docker logs $P-fsa 2>&1 | grep -q 'call ended.*carrier=true'"
rx cli 'channel originate Local/0155555559@out extension s@tone' >/dev/null; sleep 8
check "carrier-a refused 0155555559 on both nodes, Dial failed over to mobile" has carB 'CARRIER-B SIM got call to 0155555559'
check "  ... first target (node A) ended CONGESTION, node B was tried" has sw 'carrier-a-b DIALSTATUS=CONGESTION'
rx carA 'channel originate PJSIP/acct application Milliwatt' >/dev/null; sleep 4; rx carA 'channel request hangup all' >/dev/null; sleep 1
check "inbound carrier-a call identified by X-FreeSBC-Carrier" has sw 'carrier=carrier-a X-FreeSBC-Carrier=carrier-a DID=acct '
rx carA 'channel originate PJSIP/acct-b application Milliwatt' >/dev/null; sleep 4; rx carA 'channel request hangup all' >/dev/null; sleep 1
check "inbound carrier-a call through node B (private.ip .3 passes the acl, same identify)" has sw 'carrier=carrier-a X-FreeSBC-Carrier=carrier-a DID=acct-b '
rx carB 'channel originate PJSIP/5551001@fsbc application Milliwatt' >/dev/null; sleep 4; rx carB 'channel request hangup all' >/dev/null; sleep 1
check "inbound DID call from mobile identified as endpoint mobile" has sw 'carrier=mobile X-FreeSBC-Carrier=mobile DID=5551001'
rx carB 'channel originate PJSIP/5551001@fsbc-b application Milliwatt' >/dev/null; sleep 4; rx carB 'channel request hangup all' >/dev/null; sleep 1
check "inbound DID call from mobile through node B" bash -c "[ \$(docker logs $P-sw 2>&1 | grep -c 'carrier=mobile X-FreeSBC-Carrier=mobile DID=5551001') -ge 2 ]"

# --- 3. / 4. boundaries ---------------------------------------------------
invite() { # dst:port, extra header line (may be empty)
  local ip=${1%:*} port=${1#*:}
  printf 'INVITE sip:600@%s SIP/2.0\r\nVia: SIP/2.0/UDP 10.78.0.50:5099;branch=z9hG4bKt%s\r\nFrom: <sip:1001@10.78.0.50>;tag=a%s\r\nTo: <sip:600@%s>\r\nCall-ID: t%s@x\r\nCSeq: 1 INVITE\r\nContact: <sip:1001@10.78.0.50:5099>\r\nMax-Forwards: 70\r\n%bContent-Length: 0\r\n\r\n' \
    "$1" $$ $$ "$1" $$ "${2:+$2\r\n}" | docker exec -i $P-intr sh -c "nc -u -p 5099 -w 2 $ip $port"
}
out=$(invite 10.78.0.10:5080 "X-FreeSBC-Carrier: carrier-a"); sleep 1
check "5080 from a LAN host that is not a FreeSBC private.ip, forged header: rejected by ACL" has sw "failure to pass ACL 'freesbc-only'"
check "  ... and answered 401, never identified as the carrier" bash -c "echo '$out' | grep -q '401 Unauthorized'"
out=$(invite 10.78.0.10:5060 ""); sleep 1
check "5060 INVITE without credentials is challenged (401)" bash -c "echo '$out' | grep -q '401 Unauthorized'"
rx cli 'channel originate Local/600@spoof extension s@tone' >/dev/null; sleep 7
check "client forged X-FreeSBC-Carrier (sent on the wire)" has cli 'X-FreeSBC-Carrier: carrier-a'
check "  ... FreeSBC stripped it: the switch never ran from-carrier for it" bash -c "! docker logs $P-sw 2>&1 | grep -q 'Executing \[600@from-carrier'"

# --- limits ---------------------------------------------------------------
for i in 1 2 3; do rx cli 'channel originate Local/0112345678@out extension s@tone' >/dev/null; sleep 0.3; done; sleep 7
check "third concurrent outbound call of one user got Busy (GROUP_COUNT)" has sw 'Executing \[s@outbound:[0-9]+\] Busy\('

# --- 5. two nodes: qualify and drain --------------------------------------
contact_status() { rx sw 'pjsip show contacts' | grep -E "^ *Contact: +$1/" | awk '{print $NF" "$(NF-1)}'; }
cstat() { rx sw 'pjsip show contacts' | grep -E "Contact: +$1/" | grep -oE '(Avail|Unavail|NonQual|Unknown)'| head -1; }
echo "INFO  contact status before drain: carrier-a=$(cstat carrier-a) carrier-a-b=$(cstat carrier-a-b) mobile=$(cstat mobile) 1002=$(cstat 1002)"
check "qualify: carrier contacts of both nodes are Avail" bash -c "[ '$(cstat carrier-a)' = Avail ] && [ '$(cstat carrier-a-b)' = Avail ] && [ '$(cstat mobile)' = Avail ] && [ '$(cstat mobile-b)' = Avail ]"

echo "INFO  drain A: $(adm fsa POST /api/drain | tail -1)"
check "node A reports draining" bash -c "docker run --rm --network container:$P-fsa alpine:3 sh -c 'printf \"GET /api/drain HTTP/1.0\r\nHost: 127.0.0.1:8080\r\nAuthorization: Basic $AUTH\r\n\r\n\" | nc -w 3 127.0.0.1 8080' | grep -q '\"draining\":true'"
sleep 12
echo "INFO  contact status while A drains: carrier-a=$(cstat carrier-a) carrier-a-b=$(cstat carrier-a-b) mobile=$(cstat mobile) mobile-b=$(cstat mobile-b)"
check "qualify OPTIONS to a carrier host through the draining node were answered 503" bash -c "[ $(opt_resp sw 503) -ge 2 ]"
check "  ... and the 503 did NOT mark the contacts Unavail (any response counts as reachable)" bash -c "[ '$(cstat carrier-a)' = Avail ] && [ '$(cstat mobile)' = Avail ] && [ '$(cstat carrier-a-b)' = Avail ] && [ '$(cstat mobile-b)' = Avail ]"
a_ended=$(cnt fsa 'call ended'); b_ended=$(cnt fsb 'call ended.*carrier=true')
t0=$(secs); rx sw 'channel originate Local/carrier0198765401@t application Wait 3' >/dev/null
until has carA 'CARRIER-A SIM got call to 0198765401'; do sleep 1; [ $(( $(secs) - t0 )) -gt 20 ] && break; done
echo "INFO  outbound call with node A draining (contact still Avail): placed after $(( $(secs) - t0 )) s"
check "outbound carrier call: node A answered 503 (CONGESTION), Dial went on to node B" bash -c "docker logs $P-sw 2>&1 | grep -q 'carrier-a DIALSTATUS=CONGESTION' && docker logs $P-sw 2>&1 | grep -q 'carrier-a-b DIALSTATUS='"
sleep 6
check "  ... carried by node B" bash -c "[ \$(docker logs $P-fsb 2>&1 | grep -c 'call ended.*carrier=true') -gt $b_ended ]"
check "  ... node A took no new call" bash -c "[ \$(docker logs $P-fsa 2>&1 | grep -c 'call ended') -eq $a_ended ]"
# the 503 itself: what the switch does when the INVITE reaches the draining node (qualify not yet run)
# inbound carrier calls during drain go to B (the carriers fail over on 503)
b_ended=$(cnt fsb 'call ended.*carrier=true'); n=$(cnt sw 'carrier=mobile X-FreeSBC-Carrier=mobile DID=5551002')
rx carB 'channel originate Local/5551001@trunk application Milliwatt' >/dev/null; sleep 6; rx carB 'channel request hangup all' >/dev/null; sleep 2
check "drain A: inbound mobile call (carrier tried A, got 503) completed through B" has carB 'TRUNK fsbc DIALSTATUS=CONGESTION'
check "  ... and ran on B" bash -c "[ \$(docker logs $P-fsb 2>&1 | grep -c 'call ended.*carrier=true') -gt $b_ended ]"
b_ended=$(cnt fsb 'call ended.*carrier=true')
rx carA 'channel originate Local/7771@trunk application Milliwatt' >/dev/null; sleep 6; rx carA 'channel request hangup all' >/dev/null; sleep 2
check "drain A: inbound carrier-a call to the registered Contact on A got 503, trunk used acct-b" has carA 'TRUNK acct DIALSTATUS=CONGESTION'
check "  ... and ran on B" bash -c "[ \$(docker logs $P-fsb 2>&1 | grep -c 'call ended.*carrier=true') -gt $b_ended ]"
m=$(adm fsa GET /metrics | grep 'freesbc_edge_invite_rejects_total{reason="draining"}' | awk '{print $2}')
check "node A counted the draining rejects" bash -c "[ '${m:-0}' -ge 2 ]"
# agent attached to A still takes calls from the switch, and its own calls
n=$(cnt cli 'CLIENT SIM got call to 1001'); a_ended=$(cnt fsa 'call ended.*carrier=false')
rx sw 'channel originate PJSIP/1001 application Milliwatt' >/dev/null; sleep 4; rx sw 'channel request hangup all' >/dev/null; sleep 2
check "drain A: switch -> agent attached to A still rings (client calls are admitted)" bash -c "[ \$(docker logs $P-cli 2>&1 | grep -c 'CLIENT SIM got call to 1001') -gt $n ]"
check "  ... through node A" bash -c "[ \$(docker logs $P-fsa 2>&1 | grep -c 'call ended.*carrier=false') -gt $a_ended ]"
c=$(cnt sw 'Executing \[600@from-clients:2\] Echo')
rx cli 'channel originate Local/600@out extension s@tone' >/dev/null; sleep 7
check "drain A: agent -> 600 still admitted through A" bash -c "[ \$(docker logs $P-sw 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -c 'Executing \[600@from-clients:2\] Echo') -gt $c ]"
echo "INFO  undrain A: $(adm fsa DELETE /api/drain | tail -1)"
sleep 12
echo "INFO  contact status after undrain: carrier-a=$(cstat carrier-a) mobile=$(cstat mobile)"
check "after DELETE /api/drain qualify marks node A's carrier contacts Avail again" bash -c "[ '$(cstat carrier-a)' = Avail ] && [ '$(cstat mobile)' = Avail ]"

# --- 6. restart of A: stale Contacts --------------------------------------
echo "INFO  1001 contacts before restart: $(rx sw 'pjsip show contacts' | grep -cE 'Contact: +1001/')"
docker restart $P-fsa >/dev/null; sleep 5   # a restart starts not draining; its bindings are gone
probe() { # user: dial it from the switch, wait for the T-RESULT line
  local n; n=$(cnt sw "T-RESULT $1 ")
  rx sw "channel originate Local/probe$1@t application Wait 1" >/dev/null
  wait_cnt sw "T-RESULT $1 " "$n" 60
  log sw | grep "T-RESULT $1 " | tail -1 | sed 's/.*"T-RESULT/T-RESULT/'
}
n404=$(opt_resp sw 404)
r=$(probe 1001); echo "INFO  switch -> 1001 with a stale Contact (node A restarted): $r"
check "stale Contact (unknown fsbc= token): FreeSBC answers 404, Dial ends CHANUNAVAIL at once" bash -c "echo '$r' | grep -q 'DIALSTATUS=CHANUNAVAIL' && echo '$r' | grep -qE 'SECS=[0-2]\"'"
sleep 10
check "qualify OPTIONS to the stale Contact of 1002 were answered 404" bash -c "[ $(opt_resp sw 404) -gt $n404 ]"
echo "INFO  1002 (qualify 5 s) stale contact after A restarted: $(cstat 1002)  [1001 (no qualify): $(cstat 1001)]"
check "  ... the 404 did NOT mark the stale Contact Unavail (any response counts as reachable)" bash -c "[ '$(cstat 1002)' = Avail ]"
r=$(probe 1002); echo "INFO  switch -> 1002, qualify still says Avail: $r"
check "  ... so Dial still tries it and gets the same 404 -> CHANUNAVAIL" bash -c "echo '$r' | grep -q 'DIALSTATUS=CHANUNAVAIL'"

# --- 7. media timeout, and a crash of A -----------------------------------
# Re-register the agents through A (the restarted node), then put three channels on A: an agent
# call to 600 and an outbound call to carrier-a (two channels).
docker restart $P-cli >/dev/null
wait_for reg2 cli || { echo "FAIL  client re-registration after A restarted"; fail=1; }
sleep 2
# Both calls carry a continuous tone from the originating side, so media only stops when A dies.
rx cli 'channel originate Local/600@out application Milliwatt' >/dev/null
rx cli 'channel originate Local/0112345679@out application Milliwatt' >/dev/null
sleep 15
chans() { rx sw 'core show channels count' | grep -oE '^[0-9]+ active channel' | grep -oE '^[0-9]+'; }
check "three channels still up 15 s later (rtp_timeout=10 does not fire while media flows)" bash -c "[ $(chans) -eq 3 ]"
nlack=$(cnt sw 'for lack of audio RTP activity')
docker kill $P-fsa >/dev/null; tstop=$(secs)   # SIGKILL: a crash, no BYEs
# While node A is silent and qualify has not noticed yet, place an outbound carrier call from the switch.
nd=$(cnt sw 'carrier-a DIALSTATUS=')
callfile Local/carrier0198765402@t
wait_cnt sw 'for lack of audio RTP activity' $((nlack+2)) 60
echo "INFO  rtp_timeout (10 s in this test, 30 s shipped): $(( $(cnt sw 'for lack of audio RTP activity') - nlack )) channels disconnected, the last $(( $(secs) - tstop )) s after the crash (the kill was the last moment media could arrive)"
check "rtp_timeout tore down the three channels whose media anchor died" bash -c "[ $(( $(cnt sw 'for lack of audio RTP activity') - nlack )) -ge 3 ]"
wait_cnt sw 'carrier-a DIALSTATUS=' "$nd" 60
echo "INFO  Dial through the silent node A ended after $(( $(secs) - tstop )) s: $(log sw | grep 'carrier-a DIALSTATUS=' | tail -1 | sed 's/.*"\(carrier-a DIALSTATUS[^"]*\)".*/\1/')"
wait_for has carA 'CARRIER-A SIM got call to 0198765402'
echo "INFO  that outbound call reached the carrier through node B $(( $(secs) - tstop )) s after the crash"
check "Dial to the silent node A ended (timer B) and went on to node B: the call reached the carrier" has carA 'CARRIER-A SIM got call to 0198765402'
rx sw 'channel request hangup all' >/dev/null; rx cli 'channel request hangup all' >/dev/null; rx carA 'channel request hangup all' >/dev/null
sleep 8
echo "INFO  contact status with A crashed: carrier-a=$(cstat carrier-a) carrier-a-b=$(cstat carrier-a-b) mobile=$(cstat mobile) mobile-b=$(cstat mobile-b)"
check "qualify: node A's carrier contacts are Unavail (OPTIONS timed out), node B's stay Avail" bash -c "[ '$(cstat carrier-a)' = Unavail ] && [ '$(cstat mobile)' = Unavail ] && [ '$(cstat carrier-a-b)' = Avail ] && [ '$(cstat mobile-b)' = Avail ]"
nd=$(cnt sw 'carrier-a DIALSTATUS=')
t0=$(secs); rx sw 'channel originate Local/carrier0198765403@t application Wait 3' >/dev/null
wait_cnt sw 'carrier-a-b DIALSTATUS=' 0 20; wait_cnt carA 'CARRIER-A SIM got call to 0198765403' 0 20
echo "INFO  outbound call with A's endpoint Unavail: carrier reached after $(( $(secs) - t0 )) s; $(log sw | grep 'carrier-a DIALSTATUS=' | tail -1 | sed 's/.*"\(carrier-a DIALSTATUS[^"]*\)".*/\1/')"
check "outbound call with node A Unavail: Dial skipped it at once (CHANUNAVAIL) and used node B" bash -c "docker logs $P-sw 2>&1 | grep -q 'carrier-a DIALSTATUS=CHANUNAVAIL' && [ $(( $(secs) - t0 )) -le 8 ] && docker logs $P-carA 2>&1 | grep -q 'CARRIER-A SIM got call to 0198765403'"

# --- 8. A stays down: the next calls through B -----------------------------
nmob=$(cnt sw 'carrier=mobile X-FreeSBC-Carrier=mobile DID=5551001')
rx carB 'channel originate Local/5551001@trunk application Milliwatt' >/dev/null
wait_cnt sw 'carrier=mobile X-FreeSBC-Carrier=mobile DID=5551001' "$nmob" 20
sleep 3; rx carB 'channel request hangup all' >/dev/null; sleep 2
check "A down: next inbound mobile call timed out on A (3 s) and completed through B" bash -c "docker logs $P-carB 2>&1 | grep -q 'TRUNK fsbc DIALSTATUS=NOANSWER' && [ $(cnt sw 'carrier=mobile X-FreeSBC-Carrier=mobile DID=5551001') -gt $nmob ]"
nacct=$(cnt sw 'carrier=carrier-a X-FreeSBC-Carrier=carrier-a DID=acct-b ')
rx carA 'channel originate Local/7772@trunk application Milliwatt' >/dev/null
wait_cnt sw 'carrier=carrier-a X-FreeSBC-Carrier=carrier-a DID=acct-b ' "$nacct" 20
sleep 3; rx carA 'channel request hangup all' >/dev/null; sleep 2
check "A down: next inbound carrier-a call timed out on acct and completed through acct-b (B)" bash -c "docker logs $P-carA 2>&1 | grep -q 'TRUNK acct DIALSTATUS=NOANSWER' && [ $(cnt sw 'carrier=carrier-a X-FreeSBC-Carrier=carrier-a DID=acct-b ') -gt $nacct ]"

# agent: its phone lost node A; the same user registers again, through B
echo "INFO  1001 contacts with A down, before the agent re-registers: $(rx sw 'pjsip show contacts' | grep -E 'Contact: +1001/' | sed 's/ \+/ /g')"
docker stop -t 1 $P-cli >/dev/null
ast cliB $P-pub 198.18.0.21 cliB
wait_for reg1 cliB || { echo "FAIL  client registration through B"; fail=1; }
sleep 2
echo "INFO  1001 contacts after it registered through B: $(rx sw 'pjsip show contacts' | grep -E 'Contact: +1001/' | sed 's/ \+/ /g')"
check "max_contacts=1 + remove_existing: registering through B replaced the stale Contact (exactly one, host 10.78.0.3)" \
  bash -c "[ \$(docker exec $P-sw asterisk -rx 'pjsip show contacts' | grep -cE 'Contact: +1001/') -eq 1 ] && docker exec $P-sw asterisk -rx 'pjsip show contacts' | grep -E 'Contact: +1001/' | grep -q '10.78.0.3'"
n=$(cnt cliB 'CLIENT SIM got call to 1001')
rx sw 'channel originate PJSIP/1001 application Milliwatt' >/dev/null; sleep 4; rx sw 'channel request hangup all' >/dev/null; sleep 1
check "A down: next switch -> agent call rang the agent through B" bash -c "[ $(cnt cliB 'CLIENT SIM got call to 1001') -gt $n ]"
c=$(cnt sw 'Executing \[600@from-clients:2\] Echo')
rx cliB 'channel originate Local/600@out extension s@tone' >/dev/null; sleep 7
check "A down: next agent -> 600 call completed through B" bash -c "[ $(cnt sw 'Executing \[600@from-clients:2\] Echo') -gt $c ]"
check "  ... with RTP both ways through node B" has fsb 'carrier=false stats=.*RTPPacketsRx:[1-9]'

echo; [ $fail = 0 ] && echo "ALL PASS" || echo "SOME CHECKS FAILED"
exit $fail
