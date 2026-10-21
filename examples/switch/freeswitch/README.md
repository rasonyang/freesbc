# FreeSWITCH behind FreeSBC

Minimal FreeSWITCH configuration for the reference topology. It illustrates the normative list in [`docs/edge.md`](../../../docs/edge.md#switch-side-requirements) ("Switch-side requirements"); if the two disagree, `docs/edge.md` wins.

| | Address | Role |
|---|---|---|
| FreeSBC node A public side | `203.0.113.7` | `public.ip` |
| FreeSBC node A private side | `10.77.0.2:5060/udp` | `private.ip`, the only socket the switch talks to |
| FreeSBC node B public / private side (optional) | `203.0.113.8` / `10.77.0.3:5060/udp` | second node of a two-node pair, see [Two FreeSBC nodes](#two-freesbc-nodes) |
| FreeSWITCH `internal` profile | `10.77.0.10:5060` | `edge.switch`: phones and browsers (auth required) |
| FreeSWITCH `external` profile | `10.77.0.10:5080` | `edge.switch_carrier_port`: carriers and carrier gateways |

These are the addresses of [`freesbc.example.yaml`](../../../freesbc.example.yaml) (node A); node B is the same file with `public.ip: 203.0.113.8` and `private.ip: 10.77.0.3`. The carrier lines below use `203.0.113.60:5060` and `203.0.113.60:5061` as stand-ins; use your own. The matching FreeSBC side, identical on both nodes:

```yaml
edge:
  switch: [10.77.0.10:5060]
  switch_carrier_port: 5080
  carriers:
    carrier-a: 203.0.113.60:5060   # must equal gateway "proxy" in sip_profiles/external/carrier-a-n1.xml and -n2.xml
    carrier-b: 203.0.113.60:5061   # must equal gateway "proxy" in sip_profiles/external/carrier-b-n1.xml and -n2.xml
```

## Files

Paths are relative to the FreeSWITCH conf directory (`/etc/freeswitch`, `/usr/local/freeswitch/conf`, ...). They are written against the stock `vanilla` configuration of FreeSWITCH 1.10.

| File | Purpose |
|---|---|
| `freesbc-vars.xml` | Global variables: SIP domain, pinned `ext-*-ip`, default password, the `private.ip` of each FreeSBC node. Included from `vars.xml`. |
| `autoload_configs/acl.conf.xml` | `freesbc_carrier` list: only the FreeSBC nodes (`10.77.0.2`, `10.77.0.3`) may use the carrier port. |
| `sip_profiles/internal.xml` | Client port 5060: digest auth, no trust, no NAT handling. |
| `sip_profiles/external.xml` | Carrier port 5080: ACL, own context, owns the gateways. |
| `sip_profiles/external/carrier-a-n1.xml`, `carrier-a-n2.xml` | Registered carrier line `carrier-a`, one gateway per node (`n1` = node A, `n2` = node B). |
| `sip_profiles/external/carrier-b-n1.xml`, `carrier-b-n2.xml` | IP-authenticated carrier line `carrier-b` (failover), one gateway per node. |
| `dialplan/carrier-in.xml` | Context for inbound carrier calls. |
| `dialplan/default/00_freesbc_outbound.xml` | Outbound routing with failover across carriers and nodes, for authenticated users. |

### Install

```sh
FS_CONF=/etc/freeswitch          # your conf directory
cd examples/switch/freeswitch

cp freesbc-vars.xml                          $FS_CONF/
cp autoload_configs/acl.conf.xml             $FS_CONF/autoload_configs/
cp sip_profiles/internal.xml sip_profiles/external.xml  $FS_CONF/sip_profiles/
cp sip_profiles/external/*.xml               $FS_CONF/sip_profiles/external/
cp dialplan/carrier-in.xml                   $FS_CONF/dialplan/
cp dialplan/default/00_freesbc_outbound.xml  $FS_CONF/dialplan/default/

# Stock files to remove: IPv6 profiles listen on the same ports with the stock ACLs;
# 01_example.com.xml routes 7/10/11-digit numbers to a stock "default_gateway".
rm -f $FS_CONF/sip_profiles/*-ipv6.xml $FS_CONF/dialplan/default/01_example.com.xml

# Include the variables LAST in vars.xml, just before the closing </include>, so they override
# the stock ones (a later "set" wins):
sed -i 's#^</include>#  <X-PRE-PROCESS cmd="include" data="freesbc-vars.xml"/>\n</include>#' $FS_CONF/vars.xml
```

Edit before use: the addresses and `domain` in `freesbc-vars.xml` (including `freesbc_a_ip` and `freesbc_b_ip`, which the ACL and the gateways read), the `10.77.0.10` addresses in the profiles, the gateway usernames, passwords and `proxy` values, and the `default_password`. Then restart FreeSWITCH (profiles) or `reloadxml` and `reloadacl` (dialplan, ACL, gateways via `sofia profile external rescan`).

The stock `vars.xml` resolves `external_rtp_ip` and `external_sip_ip` through `stun.freeswitch.org` at startup. The later `set` in `freesbc-vars.xml` wins, but the lookups still run and, offline, cost about 5 s each with an `[ERR] stun-set failed` log line. Comment the two `stun-set` lines out of `vars.xml` to skip them.

## Rule by rule

### The client port trusts nothing (`docs/edge.md`: "Never identify or trust a request by FreeSBC's IP on the client port")

Every client REGISTER, INVITE, SUBSCRIBE and MESSAGE reaches the `internal` profile from a FreeSBC node (`10.77.0.2` or `10.77.0.3`). If anything on that profile trusts those addresses, every client call skips digest authentication. `sip_profiles/internal.xml` therefore has:

- `auth-calls=true`, `auth-subscriptions=true`, `inbound-reg-force-matching-username=true`.
- **No `apply-inbound-acl`.** The stock profile sets `apply-inbound-acl=domains`. The `domains` list is built from the directory: a user with a `cidr=` attribute, or a `cidr`/`10.77.0.2` node added to the list, makes that address a trusted source. `acl.conf.xml` keeps the `domains` list but nothing applies it. Do not add `cidr=` to directory users either.
- No `apply-register-acl` either (same reason).
- `challenge-realm` and `force-register-domain` fixed to `$${domain}`, which `freesbc-vars.xml` sets to the name clients register with (`203.0.113.7` here, or the DNS name pointing at FreeSBC). The stock `domain` is the switch's own IP, which no client would use. Remove the `force-*` and `challenge-realm` lines if you host several domains.

Observed: an INVITE without credentials from `10.77.0.2` to `10.77.0.10:5060` is answered `407 Proxy Authentication Required`, and a REGISTER `401`. With a list containing `10.77.0.2` applied as `apply-inbound-acl`, the same INVITE gets `100 Trying` and goes straight to the dialplan (`480` for an absent callee), with no challenge.

### The carrier port is for FreeSBC only (`docs/edge.md`: "Only the carrier port may skip authentication ... Restrict it to `private.ip`")

`sip_profiles/external.xml` sets `auth-calls=false` (nothing else is delivered there) and `apply-inbound-acl=freesbc_carrier`; the list in `acl.conf.xml` allows `10.77.0.2/32` and `10.77.0.3/32` (each FreeSBC node) and denies the rest.

**The ACL is not enough on its own; also firewall port 5080.** Observed on FreeSWITCH 1.10.12 from a host that is not `10.77.0.2`:

| Request to `10.77.0.10:5080` | Answer |
|---|---|
| INVITE | `403 Forbidden` (the ACL) |
| REGISTER, SUBSCRIBE, PUBLISH | `405` |
| OPTIONS, INFO | `200 OK` |
| MESSAGE | `407` |
| NOTIFY | `481` |
| REFER | `202 Accepted` |

So only INVITE is ACL-gated. Let only FreeSBC reach the port, for example:

```sh
iptables -A INPUT -p udp --dport 5080 -s 10.77.0.2 -j ACCEPT     # node A
iptables -A INPUT -p udp --dport 5080 -s 10.77.0.3 -j ACCEPT     # node B (omit for one node)
iptables -A INPUT -p udp --dport 5080 -j DROP                    # not run in the verification below
```

The external profile also has `disable-register=true`: nothing registers on it, carrier registrations are outbound.

### Carrier gateways (`docs/edge.md`: "Point every carrier gateway ... at FreeSBC as outbound proxy", "The `edge.carriers` entry must equal the host[:port] the switch puts in the Request-URI")

```xml
<gateway name="carrier-a-n1">      <!-- node A; carrier-a-n2 is the same through node B, with its own account -->
  <param name="username" value="acct-a"/>
  <param name="password" value="CHANGE-ME"/>
  <param name="proxy" value="203.0.113.60:5060"/>            <!-- == edge.carriers entry -->
  <param name="outbound-proxy" value="10.77.0.2:5060"/>      <!-- INVITE (and in-dialog) go here -->
  <param name="register-proxy" value="10.77.0.2:5060"/>      <!-- REGISTER goes here -->
  <param name="register" value="true"/>
  <param name="expire-seconds" value="300"/>
</gateway>
```

What FreeSWITCH 1.10.12 puts on the wire, observed with `sofia global siptrace on`:

- **`outbound-proxy` alone does not route REGISTER.** With only `proxy` and `outbound-proxy`, the REGISTER went `10.77.0.10:5080 -> 203.0.113.60:5060` directly, around FreeSBC, exposing `10.77.0.10` to the carrier. `register-proxy=10.77.0.2:5060` is required for REGISTER. `outbound-proxy` is what sends the INVITEs through FreeSBC (a gateway with no `register-proxy` and `register=false`, like `carrier-b`, sends its INVITEs to `10.77.0.2:5060`). **The gateway ping (`ping`) goes to `register-proxy`, never to `outbound-proxy`**: on a gateway with `register=false` and no `register-proxy` the OPTIONS goes straight to the carrier from the switch, around FreeSBC, is not answered (the switch is on a private LAN) and the gateway is marked DOWN for good (observed: `Ping failed carrier-b-n1 with code 408`, `Status DOWN (ping)`; with `register-proxy` set the ping went through FreeSBC and the gateway was UP). So `carrier-b-n1.xml` and `-n2.xml` set `register-proxy` although they do not register.
- **Request-URI of REGISTER and INVITE is `sip:<proxy>`**, taken verbatim from `proxy` with `;transport=udp` appended: `REGISTER sip:203.0.113.60:5060;transport=udp`. FreeSBC compares `host[:port]` only, so the parameter does not matter. Include the port in both `proxy` and the `edge.carriers` entry, or in neither.
- **`realm`, `from-domain`, `register-transport` are not needed.** With none set, From and To carry the proxy host (`<sip:acct-a@203.0.113.60:5060>`) and the digest realm is taken from the carrier's challenge.
- The REGISTER `Contact` is `sip:gw+carrier-a-n1@10.77.0.10:5080;transport=udp;gw=carrier-a-n1`. FreeSBC rewrites it toward the carrier to `sip:gw+carrier-a-n1@203.0.113.7:5060;fsbc=<token>`, so the switch address never leaves the LAN.
- The 200 OK returns `Contact: ...;expires=300` (the carrier's grant, relayed by FreeSBC); FreeSWITCH refreshes on that.
- The registration shows in the FreeSBC log: `carrier registration carrier=carrier-a ... expires=300`.

`outbound-proxy` and `register-proxy` take `host:port` and are always UDP.

### Inbound carrier calls (`docs/edge.md`: "Identify inbound carrier calls ...")

FreeSBC delivers every carrier request to `10.77.0.10:5080`, so it lands in the `carrier-in` context (the `external` profile's `context`), which can only be reached from there. Three ways to tell which carrier it is, all shown in `dialplan/carrier-in.xml` and all observed:

1. **`${sip_h_X-FreeSBC-Carrier}`** is the `edge.carriers` name (`carrier-a`), or `unknown` for an `edge.carrier_sources` address that matches no entry. Works for both a registered line and a DID.
2. **The registration line.** A carrier call that uses the Contact the gateway registered is delivered with the Request-URI restored to `sip:gw+carrier-a-n1@10.77.0.10:5080;transport=udp;gw=carrier-a-n1`. sofia then sets `${sip_gateway}=carrier-a-n1` and `${sip_req_user}=gw+carrier-a-n1`. `destination_number` is the gateway `extension` param, which defaults to the **username** (`acct-a`), not `gw+carrier-a`; match `${sip_gateway}`.
3. **The DID.** A call addressed to the number (no token) arrives with the Request-URI unchanged (`sip:1555010001@203.0.113.7:5060`) and `destination_number` is the number.

`X-FreeSBC-Carrier` is added by FreeSBC on the private side and every `X-FreeSBC-*` header from the public side is stripped, so it can be trusted as long as only FreeSBC reaches the carrier port (see above).

### Outbound and failover (`docs/edge.md`: "Line selection and failover are the switch's job")

```xml
<action application="set" data="continue_on_fail=true"/>
<action application="bridge" data="sofia/gateway/carrier-a-n1/$1|sofia/gateway/carrier-a-n2/$1|sofia/gateway/carrier-b-n1/$1|sofia/gateway/carrier-b-n2/$1"/>
<action application="hangup" data="${originate_disposition}"/>
```

FreeSBC never retries on another carrier or node; the `|` does it. Verified with the failing line first: `carrier-b` answered `503` and FreeSBC relayed it, FreeSWITCH moved on to `carrier-a`, which answered (two `proxying INVITE to carrier` lines, `carrier=carrier-b` then `carrier=carrier-a`). The four legs are two carriers times two nodes; with one node keep only the `-n1` legs.

`00_freesbc_outbound.xml` lives in the `default` context (reached only by authenticated users, whose `user_context` is `default`) and is named so it sorts before the stock `01_example.com.xml`. Its number pattern is an allowlist; narrow it to what you sell.

## Two FreeSBC nodes

Two independent FreeSBC nodes, no shared state; the switch is the only place that knows both. The deployment as a whole (carriers, clients, rolling restart) is in [`docs/two-node.md`](../../../docs/two-node.md). The files in this directory are written for two nodes. **One node:** delete `carrier-a-n2.xml` and `carrier-b-n2.xml`, the `freesbc_b_ip` line in `freesbc-vars.xml`, the node B line in `acl.conf.xml`, and the `-n2` legs of the `bridge` string in `00_freesbc_outbound.xml`.

Every per-node setting on the switch:

| Setting | Where | Per node |
|---|---|---|
| `freesbc_a_ip`, `freesbc_b_ip` | `freesbc-vars.xml` | The `private.ip` of each node (`10.77.0.2`, `10.77.0.3`). Read by the ACL and the gateways. |
| `freesbc_carrier` ACL | `autoload_configs/acl.conf.xml` | One `allow` per node `private.ip`. A node missing here gets `403` on every carrier call it delivers. |
| Gateway `carrier-a-n1` / `carrier-a-n2` | `sip_profiles/external/carrier-a-n*.xml` | `outbound-proxy` and `register-proxy` = that node's `private.ip:5060`. A registered carrier needs its own account on each node (`acct-a`, `acct-a2`): a registration names the node in its Contact. `proxy` is the same on both and equals the `edge.carriers` entry. |
| Gateway `carrier-b-n1` / `carrier-b-n2` | `sip_profiles/external/carrier-b-n*.xml` | Same, IP-authenticated: no account, but `register-proxy` is still set so the ping goes through the node. The carrier allowlists both `public.ip`. |
| `ping` | every gateway | OPTIONS health check of the path through the node, every 15 s. A node that is down, or draining, takes its gateways out of the bridge. |
| `bridge` string | `dialplan/default/00_freesbc_outbound.xml` | One leg per carrier and node; the order is the preference. |
| `registered-line-a` | `dialplan/carrier-in.xml` | Matches `${sip_gateway}` `carrier-a-n1` and `carrier-a-n2`. |
| `rtp-timeout-sec` | `sip_profiles/internal.xml`, `external.xml` | 60, both profiles. Not per node, but it is what frees the channels of a node that died. |
| `multiple-registrations=false` | `sip_profiles/internal.xml` | One Contact per user. Not per node. |

`freesbc.yaml` (`edge.switch`, `edge.carriers`, `shield`) is the same on both nodes; only `public.ip` and `private.ip` differ. Clients register with a `domain` that is a name, or the IP of one node plus `force-register-domain` as here: both nodes must be able to authenticate the same `domain`.

What was observed (FreeSWITCH 1.10.12, [`test/run.sh`](test/run.sh), part "two-node failover"):

- **Bridge failover on 503.** With node A draining, a bridge whose first leg is a gateway through A got `503` and moved to the next leg, through B, and the carrier saw the call from node B's public address. Any failure of a leg moves on to the next one with `continue_on_fail=true`.
- **Bridge failover on timeout.** With node A stopped and its gateway not yet marked DOWN, the INVITE to A got no answer; after 33 s (`RECOVERY_ON_TIMER_EXPIRE`, sofia's 32 s INVITE timeout) the bridge moved to the next leg. In other runs the Docker network returned an ICMP host-unreachable and sofia failed the leg locally in 18 s (`NORMAL_TEMPORARY_FAILURE`, a sofia-made `503`); the bridge moved on either way. No `leg_timeout` or `originate_timeout` is needed for that; they would only add a shorter limit that also cuts a legitimately ringing carrier.
- **Gateway ping with OPTIONS `503` (draining node).** The gateway is marked `DOWN` on the first `503` (`Ping failed carrier-a-n1 with code 503 - count 1/0/1, state DOWN`). A registered gateway shows `State FAIL_WAIT`, `Status DOWN`; an IP-authenticated one `NOREG`, `Status DOWN (ping)`. A DOWN gateway is not used: `originate sofia/gateway/carrier-a-n1/...` returns `GATEWAY_DOWN` at once and a bridge skips the leg. After `DELETE /api/drain` the next ping (within 15 s, plus the registration retry for a registered gateway) returned `200` and the gateway was `UP`, `REGED` again within about 40 s, with no action on the switch. Registered gateways still refreshed their registration through the draining node (drain does not touch REGISTER).
- **Gateway ping with a dead node.** No answer is a `408` after sofia's 32 s timeout: the gateway went `DOWN` between 32 and 47 s after the node stopped (ping every 15 s). Until then calls still try the dead node first.
- **OPTIONS `404` (unknown `fsbc=` token), stale Contact.** The `404` applies to registered Contacts, not to gateways. After node A restarted (empty binding table) the stored Contact of the user still carried A's old token: an INVITE to the user (`user/1000@domain`, one Contact, no other to try) failed within 3-4 s with `UNALLOCATED_NUMBER` (FreeSBC `404`), and kept failing the same way until the phone registered again; the call is not retried anywhere else. The profile does not ping registrations, so nothing removes the row before the client's next REGISTER or its `Expires`.
- **Registration OPTIONS ping (`all-reg-options-ping`, `unregister-on-options-fail`): not enabled, because it is unsafe here.** With both set (`ping-mean-interval=15`/`30`) the switch's OPTIONS to the stale Contact got `404` (`Ping to sip user '1000@...' failed with code 404`), the Contact went `Unreachable` and the next ping expired the registration (`Expire sip user ... due to options failure`) within about 45 s, after which calls failed with `USER_NOT_REGISTERED` until the client registered again. But the expiry is by user: in the full two-node run the phone had already registered through node B, and the switch still expired `1000` (the ping to the dead node was in flight), so calls to a working agent failed with `USER_NOT_REGISTERED`. The cause was inferred from the log, not isolated. Leave both off.
- **Stale Contact to a dead node.** The INVITE times out after 32 s (`RECOVERY_ON_TIMER_EXPIRE`); the registration is kept until the client registers again.
- **One Contact per AoR.** `multiple-registrations=false`, set explicitly. A REGISTER for `1000` through node B replaced the Contact registered through node A: `sofia status profile internal reg` showed one row, naming B, and moving back to A replaced it again. The behaviour without the parameter was not exercised.
- **Media timeout.** `rtp-timeout-sec=60`: a carrier call (two channels, `external` and `internal`) that lost its FreeSBC node was hung up with `MEDIA_TIMEOUT` (`Reason: SIP;cause=804`) 60 s after the node stopped. FreeSBC's own watchdog (5 minutes) cannot help here, it is gone with the node. The default of the profiles here was 300; a held call keeps `rtp-hold-timeout-sec` (1800).
- **Agent clients.** The switch reaches an agent through the Contact it holds, so calls to an agent attached to a draining node still work, and so do that agent's own calls (client calls are admitted while draining).

Not exercised: `leg_timeout`/`originate_timeout` variants, a gateway ping answered `404` by a carrier, registering the same carrier account through both nodes (the carrier would hold two Contacts; that needs a real registrar), a switch pool.

## Common notes

- **UDP only toward FreeSBC.** `outbound-proxy`/`register-proxy` take no transport and both profiles bind UDP on a fixed port. FreeSBC accepts TCP, TLS, WS and WSS from the outside and converts; the switch leg is always UDP. Large INVITEs (WebRTC-sized SDP, many headers) go over UDP with IP fragmentation, so keep the path MTU clean between the switch and FreeSBC.
- **Keep the `fsbc=` parameter.** FreeSBC rewrites a client's Contact to `sip:<user>@10.77.0.2:5060;transport=udp;fsbc=<token>` and routes a call to the client by that token. sofia stores the Contact as it received it, parameter included (verified in `sofia status profile internal reg`: `Contact: "" <sip:1000@10.77.0.2:5060;transport=udp;fsbc=...>`), and a call the switch placed with `user/1000@domain` reached the client. Do not use `NDLB-*` options or a custom `dial-string` that rebuilds or strips the Contact.
- **Return an expiry in the 200 OK.** sofia does (`Contact: ...;expires=120`), and FreeSBC keeps the binding for that value. Do not rewrite the registrar's reply.
- **No NAT handling on the switch.** FreeSBC anchors all media and rewrites Contact and SDP to `10.77.0.2`/its own ports. FreeSWITCH is on a flat LAN with FreeSBC, so:
  - no `apply-nat-acl` on either profile (stock `internal`: `nat.auto`, i.e. RFC1918 minus the local LAN: a FreeSBC on another private subnet would be treated as a NAT);
  - no `aggressive-nat-detection`, `NDLB-force-rport`, `NDLB-received-in-nat-reg-contact`, no `stun:` anywhere;
  - `ext-sip-ip` and `ext-rtp-ip` pinned to the switch's private address (`10.77.0.10`), not `public.ip` and not a STUN result. FreeSBC sends RTP to the address in the switch's SDP and latches the private leg strictly on that IP, so it must be the address the RTP is sent from; on a multi-homed switch set `rtp-ip`/`sip-ip` to the interface on the FreeSBC LAN.
- **Media is plain RTP/AVP on the switch leg**, also for WebRTC clients and for SDES-SRTP carriers; leave `rtp_secure_media` and DTLS off. Codecs are PCMU, PCMA, Opus and `telephone-event` (RFC 4733, payload type taken from the offerer): `inbound-codec-prefs`/`outbound-codec-prefs` list those. FreeSBC does not transcode: with no common codec the call is a `488`. Opus needs `mod_opus` on the switch (loaded in the stock `vanilla` config; an Opus call was not placed in the verification below).
- **`rtp-timer-name=soft`** is set because the minimal profiles drop it with the rest of the stock text. In the lab a FreeSWITCH profile without it sent a 440 Hz tone as 2 RTP packets per call instead of 50 per second, while echoed media was fine.
- **100rel/PRACK, UPDATE, SUBSCRIBE/NOTIFY, REFER, MESSAGE are carried** (see `docs/edge.md`); the switch authenticates and routes them by its own policy. The profile sets `auth-subscriptions=true`, as the stock one does. `enable-100rel` stays at the stock off (the stock profile warns about crashes with it). A REFER's `Refer-To` is routed by FreeSWITCH, not FreeSBC, so it follows the dialplan context of the user (restrict that context; see toll fraud). **PUBLISH is answered `405` by FreeSBC**; phones that PUBLISH presence get that, BLF via SUBSCRIBE/NOTIFY is unaffected.
- **A switch pool needs a shared registration database** (`docs/edge.md`, "Multiple switches"): set `odbc-dsn` on the `internal` profile (and `core-db-dsn` for shared call state if you use it), identical directory and dialplan on every node, and a distinct carrier account or sub-account per node for outbound registrations (a carrier registration stays on the node that made it). Not exercised here.

## Policy FreeSBC deliberately does not do

FreeSBC only does what the edge alone can do ([scope rule](../../../docs/edge.md#scope-rule)). These stay on the switch. The `limit` on a gateway key, `sched_hangup` and the CDR below were run against the same setup; the per-user `limit` uses the same syntax and was not run.

**Per-carrier and per-user concurrent-call limits**, in the dialplan before the bridge (`mod_hash` is loaded in the stock config):

```xml
<action application="limit" data="hash outbound carrier-a 30 !NORMAL_CIRCUIT_CONGESTION"/>
<action application="limit" data="hash user ${accountcode} 3 !USER_BUSY"/>
```

With a limit of 1, a second concurrent call is refused (`limit_usage hash outbound carrier-a` shows 1; the second gets `NORMAL_CIRCUIT_CONGESTION`, recorded in the CDR).

**Whole-switch limits** in `autoload_configs/switch.conf.xml` (stock: 1000 and 30): `<param name="max-sessions" value="1000"/>` and `<param name="sessions-per-second" value="30"/>`. Keep FreeSBC's `shield.max_sessions` below the real media capacity, as `docs/edge.md` advises.

**Maximum call duration**, set before the bridge, hangs up both legs after an hour:

```xml
<action application="set" data="api_on_answer=sched_hangup +3600 ${uuid} ALLOTTED_TIMEOUT"/>
```

(with `+6` the call ended at 6 s with `ALLOTTED_TIMEOUT`). `execute_on_answer=sched_hangup +3600 ALLOTTED_TIMEOUT` does the same on a leg that executes dialplan applications.

**Toll-fraud protection.** Everything on the public side reaches the switch as an authenticated or unauthenticated request from `10.77.0.2`, so the switch's own controls are the only barrier:

- Digest authentication on the client port (above), strong passwords: `default_password` is `1234` in the stock `vars.xml`, shared by users 1000-1019, and the stock dialplan sleeps 10 s while it is `1234`. `freesbc-vars.xml` sets it to a placeholder; set a real one, or delete the stock users and create your own with per-user random passwords.
- Never route `public`, `carrier-in` or an unauthenticated context to a gateway. `carrier-in` here can only `bridge` to a local user.
- Allowlist destinations in the outbound extension (the pattern in `00_freesbc_outbound.xml`), and gate it on the `toll_allow` directory variable (it requires `domestic`) for per-user permission. Remove the stock `01_example.com.xml` (7/10/11 digit and `011` international patterns).
- Do not set `accept-blind-reg`/`accept-blind-auth`, and keep the `public` context free of gateway bridges.

**CDR.** `mod_cdr_csv` is loaded in the stock config and writes `log/cdr-csv/Master.csv` (verified: both the answered call, `ALLOTTED_TIMEOUT`, and the refused one, `NORMAL_CIRCUIT_CONGESTION`, are in it). Use `mod_xml_cdr` or `mod_cdr_pg_csv` for a database. FreeSBC's own record is the `call ended` log line and `freesbc_edge_calls_ended_total{reason}`.

## Verified with

2026-10-15 (single node: 2026-10-09), end to end in Docker by [`test/run.sh`](test/run.sh) (builds FreeSBC, derives the switch, phone and carrier configs from the image's stock config plus the files in this directory, prints `PASS`/`FAIL`, removes everything; `KEEP=1` keeps the containers) on two networks (private `10.77.0.0/24`, public `203.0.113.0/24`): two FreeSBC nodes (linux/arm64 build, one shared `freesbc.yaml` with `${PUBLIC_IP}` and `${PRIVATE_IP}`): node A `10.77.0.2` / `203.0.113.7` and node B `10.77.0.3` / `203.0.113.8`; FreeSWITCH `1.10.12-release-10222002881-a88d069d6f` (image `safarov/freeswitch:latest`, linux/amd64 under emulation, stock `vanilla` config plus the files in this directory) at `10.77.0.10`; a second FreeSWITCH as the phone (registering user `1000` through FreeSBC with a gateway) and a third as the carrier (a registrar for `acct-a` and `acct-a2` on `203.0.113.60:5060`, a profile that answers `503` on `:5061`).

- A client registered through FreeSBC with digest (`registration accepted aor=1000@203.0.113.7`) and called `9196` (echo): `407`, authenticated retry, answered, and the RTP counters on FreeSBC moved symmetrically; a call placed from the switch with `originate user/1000@203.0.113.7` reached the phone, and the stored Contact kept its `fsbc=` parameter.
- The carrier gateway REGISTERed through FreeSBC to the carrier (`carrier registration carrier=carrier-a expires=300`, gateway `carrier-a-n1` `REGED`); an outbound call (`15551230001`) reached the carrier with `Via` and `Contact` showing `203.0.113.7`; failover `carrier-b` (503) then `carrier-a` worked.
- Inbound carrier calls reached `carrier-in` with the carrier visible: `inbound carrier=carrier-a did=1555010001 ...` for a DID call (bridged on to the phone), and `${sip_gateway}=carrier-a-n1` for a call to the registered Contact (`Regex (PASS) [registered-line-a]`).
- From `10.77.0.99` (not `private.ip`), an INVITE to `10.77.0.10:5080` got `403 Forbidden`; the other methods are in the table above.
- An INVITE and a REGISTER from `10.77.0.2` to `:5060` with no credentials were challenged (`407`, `401`).

Not verified: a pool of several switches; TLS/WebSocket/WebRTC clients and SDES carriers (FreeSBC converts them before the switch); real carriers; IPv6; the `iptables` rule; Opus; SUBSCRIBE/MESSAGE/REFER/PRACK/UPDATE from a client (the profile settings are the stock ones, and FreeSBC's own interop test covers sofia's handling of the dialog headers, see `docs/edge.md`, "Verification against a real FreeSWITCH").

The two-node checks, all run by `test/run.sh`: node A restarted (stale Contact, `404`), node A stopped (the next inbound carrier call, the next agent-to-switch call and the next switch-to-agent call complete through B; the phone re-registers through B by a second gateway), media timeout of a call that lost its node, node A drained (carrier calls to A refused with `503` and bridged on through B, an agent on A still receives and places calls), gateway ping with `503` and recovery. See [Two FreeSBC nodes](#two-freesbc-nodes) for the observations.

`test/run.sh` repeats the checks above except the non-INVITE answers on 5080, the `limit`, `sched_hangup` and CDR runs, which were manual.
