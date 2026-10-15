#!/usr/bin/env bash
# End-to-end check of the FreeSWITCH example configs behind a real FreeSBC.
#
#   examples/switch/freeswitch/test/run.sh
#
# Needs docker and a Go toolchain; takes 20+ minutes when the image is amd64 under
# emulation. It builds freesbc for linux, derives three FreeSWITCH configs from the stock
# config of the image (the switch = stock + the files in the parent directory, installed
# as the README says; a phone and a carrier simulator = stock + small overlays below),
# starts everything on the documented subnets, runs the checks and removes everything.
# Do not run it while a lab already uses 10.77.0.0/24 or 203.0.113.0/24.
#
#   private 10.77.0.0/24:   FreeSBC node A .2, node B .3, switch .10, intruder .99
#   public  203.0.113.0/24: node A .7, node B .8, phone .50 (client 1000), carrier .60 (:5060
#                           registrar for acct-a and acct-a2, :5061 answers 503)
#
# Parts 1-4 exercise one node (A). Part 5 is the two-node HA run (docs/two-node.md): the switch
# has gateways through both nodes, the phone moves from A to B, A is restarted and stopped,
# then drained.
#
# Env: IMG (default safarov/freeswitch:latest), WORK (default ~/.cache/freesbc-freeswitch-test,
# must be under a path docker can bind-mount), KEEP=1 to leave the containers running.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
EX=$(dirname "$HERE")
REPO=$(cd "$EX/../../.." && pwd)
IMG=${IMG:-safarov/freeswitch:latest}
STOCK=/usr/share/freeswitch/conf/vanilla   # stock config inside the image
WORK=${WORK:-$HOME/.cache/freesbc-freeswitch-test}
P=fs108   # name prefix for networks and containers
fail=0

cleanup() {
  [ "${KEEP:-0}" = 1 ] && return
  docker rm -f $P-switch $P-carrier $P-phone $P-sbc $P-sbcb $P-probe $P-tmp >/dev/null 2>&1
  docker network rm $P-priv $P-pub >/dev/null 2>&1
}
trap cleanup EXIT
cleanup

check() { # description, command...
  local d=$1; shift
  if "$@" >/dev/null 2>&1; then echo "PASS  $d"; else echo "FAIL  $d"; fail=1; fi
}
fsx() { docker exec "$P-$1" fs_cli -x "$2"; }
flog() { docker exec "$P-$1" cat /tmp/log/freeswitch.log 2>/dev/null; }
has() { flog "$1" | grep -Eq "$2"; }                       # FreeSWITCH container, regex
sbc_has() { docker logs $P-sbc 2>&1 | grep -Eq "$1"; }        # node A log
sbcb_has() { docker logs $P-sbcb 2>&1 | grep -Eq "$1"; }      # node B log
adm() { # container, method, path -> response (admin API on the node's loopback, basic auth)
  printf "$2 $3 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nOrigin: http://127.0.0.1:8080\r\nAuthorization: Basic $(printf 'admin:labpw' | base64)\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" |
    docker exec -i "$1" nc -w3 127.0.0.1 8080 | tr -d '\r'
}
fsx_has() { fsx "$1" "$2" 2>/dev/null | grep -Eq "$3"; }   # container, command, regex
wait_for() { local n=0; until "$@" >/dev/null 2>&1; do n=$((n+1)); [ $n -gt ${WAIT:-300} ] && return 1; sleep 1; done; }
sedi() { # sed expression, file: portable in-place edit
  sed "$1" "$2" > "$2.new" && mv "$2.new" "$2"
}
# Add an include just before the closing </include> of a stock file.
include_last() { # file, data
  sed '$d' "$1" > "$1.new"; printf '  <X-PRE-PROCESS cmd="include" data="%s"/>\n</include>\n' "$2" >> "$1.new"; mv "$1.new" "$1"
}
sip() { # container, method, src ip, dst ip:port -> response status line
  local dst=$4 body="" len
  if [ "$2" = INVITE ]; then body="v=0\r\no=- 1 1 IN IP4 $3\r\ns=-\r\nc=IN IP4 $3\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"; fi
  len=$(printf "$body" | wc -c | tr -d ' ')
  printf "$2 sip:9196@$dst SIP/2.0\r\nVia: SIP/2.0/UDP $3:5099;branch=z9hG4bKprobe$$\r\nMax-Forwards: 70\r\nFrom: <sip:probe@$3>;tag=abc\r\nTo: <sip:9196@$dst>\r\nCall-ID: probe-$$-$RANDOM@$3\r\nCSeq: 1 $2\r\nContact: <sip:probe@$3:5099>\r\nContent-Type: application/sdp\r\nContent-Length: $len\r\n\r\n$body" |
    docker exec -i "$1" sh -c "nc -u -w3 -p 5099 ${dst%:*} ${dst#*:}" | head -1 | tr -d '\r'
}
rtp_moved() { # FreeSBC node A relayed RTP in both directions
  docker exec $P-sbc wget -qO- --header "Authorization: Basic $(printf 'admin:labpw' | base64)" http://127.0.0.1:8080/metrics |
    awk '/^freesbc_rtp_packets_(rx|tx)_total/ {n++; if ($2+0 > 0) ok++} END {exit !(n == 2 && ok == 2)}'
}

arch=$(docker version -f '{{.Server.Arch}}' 2>/dev/null); arch=${arch:-arm64}
rm -rf "${WORK:?}"; mkdir -p "$WORK"; cd "$WORK" || exit 1
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$WORK/freesbc" ./cmd/freesbc) || exit 1

# --- configs --------------------------------------------------------------
docker create --name $P-tmp --platform linux/amd64 "$IMG" >/dev/null && docker cp $P-tmp:$STOCK base && docker rm $P-tmp >/dev/null || exit 1
for n in sw cli car; do
  cp -r base "$n"
  # fs_cli inside the container; no STUN lookups (offline, each costs seconds)
  sedi 's#name="listen-ip" value="::"#name="listen-ip" value="127.0.0.1"#' "$n/autoload_configs/event_socket.conf.xml"
  sedi '/cmd="stun-set"/d' "$n/vars.xml"
done
# switch: the README install steps
(
  cd sw || exit 1
  cp "$EX/freesbc-vars.xml" .
  cp "$EX/autoload_configs/acl.conf.xml" autoload_configs/
  cp "$EX/sip_profiles/internal.xml" "$EX/sip_profiles/external.xml" sip_profiles/
  cp "$EX"/sip_profiles/external/*.xml sip_profiles/external/
  cp "$EX/dialplan/carrier-in.xml" dialplan/
  cp "$EX/dialplan/default/00_freesbc_outbound.xml" dialplan/default/
  rm -f sip_profiles/*-ipv6.xml dialplan/default/01_example.com.xml
  include_last vars.xml freesbc-vars.xml
  # test only (sorts before 00_freesbc_outbound): a number whose first carrier (b) refuses
  cat > dialplan/default/00_a_test_failover.xml <<'Y'
<include>
  <extension name="test-failover">
    <condition field="destination_number" expression="^(15559990000)$">
      <action application="set" data="continue_on_fail=true"/>
      <action application="set" data="hangup_after_bridge=true"/>
      <action application="bridge" data="sofia/gateway/carrier-b-n1/$1|sofia/gateway/carrier-a-n1/$1"/>
      <action application="hangup" data="${originate_disposition}"/>
    </condition>
  </extension>
</include>
Y
  # test only: a number whose first leg is a gateway through node A WITHOUT ping, so a draining
  # node is reached and answers 503 before the gateway ping could mark it down (part 5)
  cat > sip_profiles/external/zz-test-noping.xml <<'Y'
<include>
  <gateway name="test-noping-n1">
    <param name="proxy" value="203.0.113.60:5060"/>
    <param name="outbound-proxy" value="$${freesbc_a_ip}:5060"/>
    <param name="register-proxy" value="$${freesbc_a_ip}:5060"/>
    <param name="register" value="false"/>
  </gateway>
</include>
Y
  cat > dialplan/default/00_a_test_503.xml <<'Y'
<include>
  <extension name="test-503">
    <condition field="destination_number" expression="^(15559990001)$">
      <action application="set" data="continue_on_fail=true"/>
      <action application="set" data="hangup_after_bridge=true"/>
      <action application="bridge" data="sofia/gateway/test-noping-n1/$1|sofia/gateway/carrier-a-n2/$1"/>
      <action application="hangup" data="${originate_disposition}"/>
    </condition>
  </extension>
</include>
Y
) || exit 1

simvars() { # dir, ip
  cat > "$1/vars-sim.xml" <<Y
<include>
  <X-PRE-PROCESS cmd="set" data="domain=$2"/>
  <X-PRE-PROCESS cmd="set" data="domain_name=\$\${domain}"/>
  <X-PRE-PROCESS cmd="set" data="external_rtp_ip=$2"/>
  <X-PRE-PROCESS cmd="set" data="external_sip_ip=$2"/>
  <X-PRE-PROCESS cmd="set" data="disable_system_api_commands=false"/>
</include>
Y
  include_last "$1/vars.xml" vars-sim.xml
}

# phone simulator: user 1000 registers through FreeSBC with a gateway, answers with echo
simvars cli 203.0.113.50
rm -f cli/sip_profiles/internal.xml cli/sip_profiles/external.xml cli/sip_profiles/*-ipv6.xml
phone_profile() { # extra gateway XML (part 5 adds one through node B)
  cat > cli/sip_profiles/phone.xml <<Y
<profile name="phone"><gateways>
<gateway name="fsbc"><param name="username" value="1000"/><param name="password" value="CHANGE-ME-NOW"/>
<param name="realm" value="203.0.113.7"/><param name="proxy" value="203.0.113.7:5060"/><param name="register" value="true"/>
<param name="expire-seconds" value="3600"/><param name="extension" value="1000"/></gateway>
$1
</gateways><domains><domain name="all" alias="false" parse="true"/></domains>
<settings>
<param name="sip-ip" value="203.0.113.50"/><param name="rtp-ip" value="203.0.113.50"/>
<param name="ext-sip-ip" value="203.0.113.50"/><param name="ext-rtp-ip" value="203.0.113.50"/>
<param name="sip-port" value="5080"/><param name="rtp-timer-name" value="soft"/><param name="dialplan" value="XML"/><param name="context" value="public"/>
<param name="auth-calls" value="false"/><param name="inbound-codec-prefs" value="PCMU,PCMA"/><param name="outbound-codec-prefs" value="PCMU,PCMA"/>
</settings></profile>
Y
}
phone_profile ""
cat > cli/dialplan/public.xml <<'Y'
<include>
  <context name="public">
    <extension name="any">
      <condition field="destination_number" expression="^(.*)$">
        <action application="log" data="INFO PHONE-SIM incoming to=$1 from=${caller_id_number} req_uri=${sip_req_uri}"/>
        <action application="answer"/>
        <action application="echo"/>
      </condition>
    </extension>
  </context>
</include>
Y

# carrier simulator: :5060 registrar for acct-a that answers, :5061 refuses with 503
simvars car 203.0.113.60
rm -f car/sip_profiles/internal.xml car/sip_profiles/external.xml car/sip_profiles/*-ipv6.xml
cat > car/sip_profiles/carrier.xml <<'Y'
<profile name="carrier"><gateways/><domains><domain name="all" alias="false" parse="true"/></domains>
<settings>
<param name="sip-ip" value="203.0.113.60"/><param name="rtp-ip" value="203.0.113.60"/>
<param name="ext-sip-ip" value="203.0.113.60"/><param name="ext-rtp-ip" value="203.0.113.60"/>
<param name="sip-port" value="5060"/><param name="rtp-timer-name" value="soft"/><param name="dialplan" value="XML"/><param name="context" value="public"/>
<param name="auth-calls" value="false"/><param name="challenge-realm" value="auto_from"/>
<param name="inbound-codec-prefs" value="PCMU,PCMA"/><param name="outbound-codec-prefs" value="PCMU,PCMA"/>
</settings></profile>
Y
cat > car/sip_profiles/carrier503.xml <<'Y'
<profile name="carrier503"><gateways/><domains><domain name="all" alias="false" parse="true"/></domains>
<settings>
<param name="sip-ip" value="203.0.113.60"/><param name="rtp-ip" value="203.0.113.60"/>
<param name="ext-sip-ip" value="203.0.113.60"/><param name="ext-rtp-ip" value="203.0.113.60"/>
<param name="sip-port" value="5061"/><param name="rtp-timer-name" value="soft"/><param name="dialplan" value="XML"/><param name="context" value="reject"/>
<param name="auth-calls" value="false"/>
</settings></profile>
Y
cat > car/directory/default/acct-a.xml <<'Y'
<include>
  <user id="acct-a">
    <params><param name="password" value="CHANGE-ME"/></params>
    <variables><variable name="user_context" value="public"/></variables>
  </user>
</include>
Y
cat > car/directory/default/acct-a2.xml <<'Y'
<include>
  <user id="acct-a2">
    <params><param name="password" value="CHANGE-ME"/></params>
    <variables><variable name="user_context" value="public"/></variables>
  </user>
</include>
Y
cat > car/dialplan/public.xml <<'Y'
<include>
<context name="public">
 <extension name="any"><condition field="destination_number" expression="^(.*)$">
  <action application="log" data="INFO CARRIER-SIM got call to=$1 from_user=${sip_from_user} from_host=${sip_from_host} cid=${caller_id_number} via=${sip_via_host} contact=${sip_contact_uri}"/>
  <action application="answer"/>
  <action application="playback" data="tone_stream://%(2000,0,440)"/>
  <action application="echo"/>
 </condition></extension>
</context>
<context name="reject">
 <extension name="r"><condition field="destination_number" expression="^(.*)$">
  <action application="log" data="INFO CARRIER-SIM-B rejecting 503 to=$1"/>
  <action application="respond" data="503"/>
 </condition></extension>
</context>
</include>
Y

# One file for both nodes; the addresses come from the environment (docs/two-node.md)
cat > freesbc.yaml <<'Y'
public: {ip: "${PUBLIC_IP}"}
private: {ip: "${PRIVATE_IP}"}
rtp: 20000-20999
edge:
  switch: [10.77.0.10:5060]
  switch_carrier_port: 5080
  listen: {udp: 5060}
  carriers:
    carrier-a: 203.0.113.60:5060
    carrier-b: 203.0.113.60:5061
admin:
  listen: 127.0.0.1:8080
  password_hash: '$2y$10$lOPnLgx6oS7k/OkRmVkngOMdq3j/DeDNkz7HeEuvvrN4RQZw1W4LG'   # "labpw"
Y

# --- topology -------------------------------------------------------------
docker network create --subnet 10.77.0.0/24 $P-priv >/dev/null
docker network create --subnet 203.0.113.0/24 $P-pub >/dev/null
fs() { # name, network, ip, config dir
  docker run -d --platform linux/amd64 --name $P-$1 --network $2 --ip $3 -v "$WORK/$4:/etc/freeswitch" \
    --entrypoint /usr/bin/freeswitch "$IMG" -nf -nonat -nc -conf /etc/freeswitch -log /tmp/log -db /tmp -run /tmp >/dev/null
}
# Start order matters: gateways register at startup and retry only after a while, so the
# registrar side (carrier, FreeSBC) comes up before the switch, and the switch before the phone.
fs carrier $P-pub 203.0.113.60 car
# Create, attach both networks, then start: FreeSBC checks at startup that both bind
# addresses are assigned to a local interface.
sbc() { # container suffix, private ip, public ip
  docker create --name $P-$1 --network $P-priv --ip $2 -e PRIVATE_IP=$2 -e PUBLIC_IP=$3 -v "$WORK":/w:ro \
    --entrypoint /w/freesbc alpine:3 run -c /w/freesbc.yaml >/dev/null
  docker network connect --ip $3 $P-pub $P-$1
  docker start $P-$1 >/dev/null
}
sbc sbc 10.77.0.2 203.0.113.7
sbc sbcb 10.77.0.3 203.0.113.8
fs switch $P-priv 10.77.0.10 sw
fs phone $P-pub 203.0.113.50 cli
docker run -d --name $P-probe --network $P-priv --ip 10.77.0.99 alpine:3 sleep 3600 >/dev/null

ready() { fsx_has "$1" 'sofia status' "$2"; }
wait_for ready switch 'external[[:space:]]+profile.*RUNNING' || { echo "FAIL  switch did not start"; exit 1; }
wait_for ready carrier 'carrier503[[:space:]]+profile.*RUNNING' || { echo "FAIL  carrier simulator did not start"; exit 1; }
wait_for ready phone 'phone[[:space:]]+profile.*RUNNING' || { echo "FAIL  phone simulator did not start"; exit 1; }
for c in switch phone carrier; do fsx $c 'sofia global siptrace on' >/dev/null; fsx $c 'console loglevel 7' >/dev/null; done
echo "FreeSWITCH: $(fsx switch version | head -1)"
gw_up() { fsx_has "$1" "sofia status gateway $2" 'State[[:space:]]+REGED'; }
WAIT=120 wait_for gw_up switch carrier-a-n1 || { echo "retrying carrier-a registration"; fsx switch 'sofia profile external killgw carrier-a-n1' >/dev/null; fsx switch 'sofia profile external rescan' >/dev/null; WAIT=90 wait_for gw_up switch carrier-a-n1; }
WAIT=120 wait_for gw_up switch carrier-a-n2 || { fsx switch 'sofia profile external killgw carrier-a-n2' >/dev/null; fsx switch 'sofia profile external rescan' >/dev/null; WAIT=90 wait_for gw_up switch carrier-a-n2; }
WAIT=120 wait_for gw_up phone fsbc || { fsx phone 'sofia profile phone killgw fsbc' >/dev/null; fsx phone 'sofia profile phone rescan' >/dev/null; WAIT=90 wait_for gw_up phone fsbc; }

# --- 1. clients -----------------------------------------------------------
check "client 1000 registered through FreeSBC (digest); stored Contact keeps fsbc=" \
  fsx_has switch 'sofia status profile internal reg' 'fsbc='
fsx phone 'bgapi originate {origination_uuid=s1,ignore_early_media=true}sofia/gateway/fsbc/9196 &playback(tone_stream://%(30000,0,440))' >/dev/null; sleep 6
check "client -> 9196 reached the switch (channel up)" fsx_has switch 'show channels' '9196'
check "  ... after a 407 digest challenge" has phone '^SIP/2.0 407'
fsx phone 'uuid_kill s1' >/dev/null; sleep 2
check "  ... and carried RTP both ways through FreeSBC" rtp_moved
check "client call ended cleanly (FreeSBC logged it)" sbc_has 'call ended.*reason=bye'
fsx switch 'originate user/1000@203.0.113.7 &playback(tone_stream://%(2000,0,440))' >/dev/null; sleep 3
check "switch -> registered client call rang the phone (via the stored Contact)" has phone 'PHONE-SIM incoming to=1000'

# --- 2. carriers ----------------------------------------------------------
check "carrier-a-n1 gateway REGED through FreeSBC node A" fsx_has switch 'sofia status gateway carrier-a-n1' 'State[[:space:]]+REGED'
check "  ... FreeSBC logged the carrier registration" sbc_has 'carrier registration.*carrier=carrier-a'
fsx phone 'bgapi originate {origination_uuid=s2,ignore_early_media=true}sofia/gateway/fsbc/15551230001 &playback(tone_stream://%(30000,0,440))' >/dev/null; sleep 6
check "outbound via carrier-a; carrier saw FreeSBC's public address in Via and Contact" \
  has carrier 'CARRIER-SIM got call to=15551230001 from_user=acct-a .*via=203.0.113.7 contact=acct-a@203.0.113.7'
fsx phone 'uuid_kill s2' >/dev/null; sleep 1
fsx phone 'bgapi originate {origination_uuid=s3,ignore_early_media=true}sofia/gateway/fsbc/15559990000 &playback(tone_stream://%(30000,0,440))' >/dev/null; sleep 8
check "failover: carrier-b (503) then carrier-a" \
  bash -c "docker logs $P-sbc 2>&1 | grep 'INVITE to carrier' | tail -2 | tr '\n' ' ' | grep -Eq 'carrier=carrier-b.*carrier=carrier-a'"
fsx phone 'uuid_kill s3' >/dev/null; sleep 1
fsx carrier 'originate sofia/carrier/1555010001@203.0.113.7:5060 &playback(tone_stream://%(3000,0,440))' >/dev/null; sleep 4
check "inbound DID call reached carrier-in with the carrier identified" has switch 'inbound carrier=carrier-a did=1555010001'
check "  ... and was bridged on to the phone" has phone 'PHONE-SIM incoming to=1000'
fsx carrier 'expand originate ${sofia_contact(carrier/acct-a@203.0.113.60)} &playback(tone_stream://%(3000,0,440))' >/dev/null; sleep 4
check "inbound call to the registered Contact matched \${sip_gateway}=carrier-a" has switch 'Regex \(PASS\) \[registered-line-a\]'
check "  ... and carrier-in saw it as carrier-a" has switch 'inbound carrier=carrier-a did=acct-a'

# --- 3. / 4. boundaries ---------------------------------------------------
r=$(sip $P-probe INVITE 10.77.0.99 10.77.0.10:5080)
check "5080 INVITE from a LAN host that is not private.ip: 403 (ACL) [$r]" bash -c "echo '$r' | grep -q ' 403 '"
r=$(sip $P-sbc INVITE 10.77.0.2 10.77.0.10:5080)
check "5080 INVITE from private.ip is not refused by the ACL [$r]" bash -c "[ -n '$r' ] && ! echo '$r' | grep -q ' 403 '"
r=$(sip $P-sbc INVITE 10.77.0.2 10.77.0.10:5060)
check "5060 INVITE without credentials from private.ip is challenged [$r]" bash -c "echo '$r' | grep -q ' 407 '"
r=$(sip $P-sbc REGISTER 10.77.0.2 10.77.0.10:5060)
check "5060 REGISTER without credentials from private.ip is challenged [$r]" bash -c "echo '$r' | grep -q ' 401 '"
r=$(fsx phone 'originate {ignore_early_media=true}sofia/gateway/fsbc/999999999999 &echo' 2>&1)
check "a destination outside the outbound allowlist is refused [$r]" bash -c "! echo '$r' | grep -q '^+OK'"

# --- 5. two nodes: restart, stop and drain node A -------------------------
# Everything above ran through node A. Now the switch has gateways through both nodes
# (carrier-a-n1/-n2, carrier-b-n1/-n2) and the phone can register through either.
echo; echo "== two-node failover (docs/two-node.md) =="
metric() { # container, regex -> value of the first matching sample
  docker exec "$1" wget -qO- --header "Authorization: Basic $(printf 'admin:labpw' | base64)" http://127.0.0.1:8080/metrics | awk -v re="$2" '$0 ~ re {print $2; exit}'
}
reg_contacts() { fsx switch 'sofia status profile internal reg'; }
gw_status() { fsx switch "sofia status gateway $1" | awk '$1=="Status" {print $2}'; }
gw_is() { [ "$(gw_status "$1")" = "$2" ]; }
gw_reged() { fsx_has switch "sofia status gateway $1" 'State[[:space:]]+REGED'; }
phone_in() { flog phone | grep -c 'PHONE-SIM incoming'; }
carrier_calls() { flog carrier | grep -c "CARRIER-SIM got call to=$1"; }
phone_regate() { # re-register the phone's gateway $1 (fsbc = through A, fsbc-b = through B)
  fsx phone "sofia profile phone killgw $1" >/dev/null; sleep 1; fsx phone 'sofia profile phone rescan' >/dev/null
  WAIT=60 wait_for gw_up phone "$1"   # the phone's own gateway is REGED (a call needs that, not only the switch's row)
}
contact_via() { reg_contacts | grep -q "Contact:.*@$1:5060"; }   # the stored Contact of 1000 names this node
contact_token() { reg_contacts | sed -n 's/.*fsbc=\([^;>]*\).*/\1/p' | head -1; }
new_contact_via() { contact_via "$1" && [ "$(contact_token)" != "$2" ]; }
one_contact_via() { [ "$(reg_contacts | grep -c '^Contact:')" = 1 ] && contact_via "$1"; }
echo_has() { echo "$1" | grep -q "$2"; }
gt() { [ "$1" -gt "$2" ]; }
all_gw_up() { gw_is carrier-a-n1 UP && gw_is carrier-a-n2 UP && gw_is carrier-b-n1 UP && gw_is carrier-b-n2 UP; }
no_external_channel() { ! fsx switch 'show channels' | grep -q 'sofia/external'; }
reject_count() { metric $P-sbc 'invite_rejects_total.*draining'; }
count_gt_ref() { gt "$(reject_count)" "$1"; }

check "both nodes: carrier-a-n1 and carrier-a-n2 registered, carrier-b-n1 and carrier-b-n2 pinged UP (through their own node)" all_gw_up
check "node B registered carrier-a-n2 (own carrier account acct-a2)" sbcb_has 'carrier registration.*carrier=carrier-a '

# 5.1 A restarts and loses its bindings. The switch still holds a Contact with A's old fsbc= token.
t0=$(date +%s)
docker restart $P-sbc >/dev/null; sleep 3
r=$(fsx switch 'originate user/1000@203.0.113.7 &playback(tone_stream://%(2000,0,440))' 2>&1); t1=$(date +%s)
check "stale Contact (node A restarted, unknown fsbc= token, 404): the call to 1000 fails at once [$r in $((t1-t0))s]" \
  echo_has "$r" UNALLOCATED_NUMBER
check "  ... in under 20 s" gt 20 $((t1-t0))

# 5.2 media timeout: a carrier call through A bridged to the phone, then A dies
old=$(contact_token)
phone_regate fsbc
WAIT=60 wait_for new_contact_via 10.77.0.2 "$old"   # the stale row is replaced by a fresh registration
n0=$(phone_in)
fsx carrier 'bgapi originate {origination_uuid=c9}sofia/carrier/1555010003@203.0.113.7:5060 &playback(tone_stream://%(600000,0,440))' >/dev/null; sleep 6
check "carrier call through node A is up on both switch profiles (2 channels)" fsx_has switch 'show channels count' '^[[:space:]]*2 total'
check "  ... and bridged to the phone" gt "$(phone_in)" "$n0"
tstop=$(date +%s); docker stop $P-sbc >/dev/null
# 5.3 stop A: the Contact is stale and names a dead node; an INVITE to it times out (about 32 s)
fsx switch 'bgapi originate user/1000@203.0.113.7 &playback(tone_stream://%(2000,0,440))' >/dev/null
# the phone moves to node B (client failover: the second gateway registers through B)
phone_profile '<gateway name="fsbc-b"><param name="username" value="1000"/><param name="password" value="CHANGE-ME-NOW"/>
<param name="realm" value="203.0.113.7"/><param name="proxy" value="203.0.113.8:5060"/><param name="register" value="true"/>
<param name="expire-seconds" value="3600"/><param name="extension" value="1000"/></gateway>'
fsx phone 'sofia profile phone rescan' >/dev/null
WAIT=60 wait_for gw_up phone fsbc-b
WAIT=60 wait_for contact_via 10.77.0.3
check "one Contact per AoR: after registering through B the switch holds exactly one Contact for 1000, and it names node B" one_contact_via 10.77.0.3
# outbound from the agent through B; the first bridge leg is node A, which is dead but may not be pinged DOWN yet
nc0=$(carrier_calls 15551230001)
t2=$(date +%s)
fsx phone 'bgapi originate {origination_uuid=o1,ignore_early_media=true}sofia/gateway/fsbc-b/15551230001 &playback(tone_stream://%(60000,0,440))' >/dev/null
WAIT=100 wait_for bash -c "[ \"\$(docker exec $P-carrier cat /tmp/log/freeswitch.log | grep -c 'CARRIER-SIM got call to=15551230001')\" -gt $nc0 ]"; t3=$(date +%s)
check "stop A: agent call to a carrier completes through B (carrier saw acct-a2 and node B's public address) after $((t3-t2))s" \
  has carrier 'CARRIER-SIM got call to=15551230001 from_user=acct-a2 .*via=203.0.113.8'
fsx phone 'uuid_kill o1' >/dev/null
if [ $((t3-t2)) -ge 25 ]; then echo "INFO  carrier-a-n1 was not yet DOWN: the dead node cost an INVITE timeout of $((t3-t2))s before the bridge moved on"
else echo "INFO  carrier-a-n1 was already DOWN (ping): the bridge skipped it at once ($((t3-t2))s)"; fi
[ $((t3-t2)) -lt 100 ] || { echo "DIAG  switch log for the outbound call:"; flog switch | grep -E '15551230001|GATEWAY_DOWN|RECOVERY_ON|Ping failed carrier-a-n1|Cannot create' | cut -c1-220 | tail -25;
  echo "DIAG  phone:"; flog phone | grep -E '^(INVITE|SIP/2.0|REGISTER)|Originate|Cannot create|originate' | cut -c1-200 | tail -30
  echo "DIAG  node B:"; docker logs $P-sbcb 2>&1 | tail -15 | cut -c1-250; }
WAIT=60 wait_for has switch 'Standard HANGUP, cause: RECOVERY_ON_TIMER_EXPIRE'
check "  ... the stale-Contact call placed before the phone moved timed out on the dead node (RECOVERY_ON_TIMER_EXPIRE)" \
  has switch 'Standard HANGUP, cause: RECOVERY_ON_TIMER_EXPIRE'
WAIT=90 wait_for gw_is carrier-a-n1 DOWN
check "gateway ping marked carrier-a-n1 DOWN once node A stopped answering" gw_is carrier-a-n1 DOWN
r=$(fsx switch 'originate sofia/gateway/carrier-a-n1/15551230009 &echo' 2>&1)
check "  ... and a DOWN gateway is skipped at once [$r]" echo_has "$r" GATEWAY_DOWN
# next carrier calls and agent calls
n0=$(phone_in)
fsx carrier 'originate sofia/carrier/1555010004@203.0.113.8:5060 &playback(tone_stream://%(3000,0,440))' >/dev/null; sleep 4
check "stop A: next inbound carrier call (to node B's public address) reached the switch" has switch 'inbound carrier=carrier-a did=1555010004'
check "  ... and was bridged to the agent" gt "$(phone_in)" "$n0"
n0=$(phone_in)
fsx switch 'originate user/1000@203.0.113.7 &playback(tone_stream://%(2000,0,440))' >/dev/null; sleep 3
check "stop A: next switch -> agent call rang the phone through node B" gt "$(phone_in)" "$n0"
fsx phone 'bgapi originate {origination_uuid=s5,ignore_early_media=true}sofia/gateway/fsbc-b/9196 &playback(tone_stream://%(30000,0,440))' >/dev/null; sleep 6
check "stop A: next agent -> switch call (9196) completed through B" fsx_has switch 'show channels' '9196'
fsx phone 'uuid_kill s5' >/dev/null
# 5.2 (cont.): media timeout of the call that was up on A when it died
WAIT=150 wait_for no_external_channel
tend=$(date +%s)
check "media timeout: the carrier call that lost node A was torn down by the switch (rtp-timeout-sec=60) after $((tend-tstop))s" \
  has switch 'hanging up, cause: MEDIA_TIMEOUT'
check "  ... within 140 s" gt 140 $((tend-tstop))
fsx phone 'hupall' >/dev/null; fsx carrier 'hupall' >/dev/null

# 5.4 drain A: new carrier calls go to B, an agent attached to A still takes calls
docker start $P-sbc >/dev/null; sleep 3
phone_regate fsbc
WAIT=60 wait_for contact_via 10.77.0.2
check "one Contact per AoR: the phone moved back to node A and the switch holds one Contact, naming A" one_contact_via 10.77.0.2
WAIT=150 wait_for gw_is carrier-a-n1 UP
check "node A is back: carrier-a-n1 UP" gw_is carrier-a-n1 UP
WAIT=100 wait_for gw_reged carrier-a-n1
check "  ... and registered again" gw_reged carrier-a-n1
d0=$(reject_count); d0=${d0:-0}
r=$(adm $P-sbc POST /api/drain | tail -1)
check "POST /api/drain on node A [$r]" echo_has "$r" '"draining":true'
# deterministic 503: this route's first leg is a gateway through A with no ping
fsx phone 'bgapi originate {origination_uuid=o2,ignore_early_media=true}sofia/gateway/fsbc/15559990001 &playback(tone_stream://%(20000,0,440))' >/dev/null; sleep 8
check "drain A: bridge failover on 503 (first leg through A refused, second leg through B reached the carrier)" \
  has carrier 'CARRIER-SIM got call to=15559990001 from_user=acct-a2 .*via=203.0.113.8'
check "  ... node A counted the refusal (reason draining)" count_gt_ref "$d0"
fsx phone 'uuid_kill o2' >/dev/null
# the configured route: carrier-a-n1 (503) or, once the ping saw the 503, GATEWAY_DOWN; either way the call goes through B
fsx phone 'bgapi originate {origination_uuid=o3,ignore_early_media=true}sofia/gateway/fsbc/15551230002 &playback(tone_stream://%(20000,0,440))' >/dev/null; sleep 8
check "drain A: agent call to a carrier over the configured route completes via B" \
  has carrier 'CARRIER-SIM got call to=15551230002 from_user=acct-a2 .*via=203.0.113.8'
fsx phone 'uuid_kill o3' >/dev/null
r=$(fsx carrier 'originate sofia/carrier/1555010005@203.0.113.7:5060 &playback(tone_stream://%(3000,0,440))' 2>&1)
check "drain A: a new inbound carrier call to node A is refused [$r]" bash -c "! echo '$r' | grep -q '^+OK'"
n0=$(phone_in)
fsx carrier 'originate sofia/carrier/1555010006@203.0.113.8:5060 &playback(tone_stream://%(3000,0,440))' >/dev/null; sleep 4
check "drain A: the same call to node B reaches the switch" has switch 'inbound carrier=carrier-a did=1555010006'
check "  ... and is bridged to the agent" gt "$(phone_in)" "$n0"
n0=$(phone_in)
fsx switch 'originate user/1000@203.0.113.7 &playback(tone_stream://%(2000,0,440))' >/dev/null; sleep 3
check "drain A: an agent attached to A still receives a call from the switch" gt "$(phone_in)" "$n0"
fsx phone 'bgapi originate {origination_uuid=s6,ignore_early_media=true}sofia/gateway/fsbc/9196 &playback(tone_stream://%(30000,0,440))' >/dev/null; sleep 6
check "drain A: an agent call from the phone through A to the switch (9196) is still admitted" fsx_has switch 'show channels' '9196'
fsx phone 'uuid_kill s6' >/dev/null
WAIT=60 wait_for gw_is carrier-a-n1 DOWN
check "gateway ping: OPTIONS 503 from the draining node marks carrier-a-n1 DOWN" has switch 'Ping failed carrier-a-n1 with code 503'
check "  ... carrier-a-n1 Status is DOWN" gw_is carrier-a-n1 DOWN
check "  ... carrier-b-n1 (register=false, register-proxy set) goes DOWN with it" has switch 'Ping failed carrier-b-n1 with code 503'
check "  ... client Contacts on A are unaffected: the OPTIONS ping to the phone's Contact is still answered" \
  fsx_has switch 'sofia status profile internal reg' 'Ping-Status:.*Reachable'
r=$(adm $P-sbc DELETE /api/drain | tail -1)
check "DELETE /api/drain on node A [$r]" echo_has "$r" '"draining":false'
WAIT=120 wait_for gw_is carrier-a-n1 UP
check "  ... the next ping succeeds and carrier-a-n1 is UP" gw_is carrier-a-n1 UP
WAIT=100 wait_for gw_reged carrier-a-n1
check "  ... and registered" gw_reged carrier-a-n1

echo; [ $fail = 0 ] && echo "ALL PASS" || echo "SOME CHECKS FAILED"
exit $fail
