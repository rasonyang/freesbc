# FreeSWITCH behind FreeSBC

Minimal FreeSWITCH configuration for the reference topology. It illustrates the normative list in [`docs/edge.md`](../../../docs/edge.md#switch-side-requirements) ("Switch-side requirements"); if the two disagree, `docs/edge.md` wins.

| | Address | Role |
|---|---|---|
| FreeSBC public side | `203.0.113.7` | `public.ip` |
| FreeSBC private side | `10.77.0.2:5060/udp` | `private.ip`, the only socket the switch talks to |
| FreeSWITCH `internal` profile | `10.77.0.10:5060` | `edge.switch`: phones and browsers (auth required) |
| FreeSWITCH `external` profile | `10.77.0.10:5080` | `edge.switch_carrier_port`: carriers and carrier gateways |

These are the addresses of [`freesbc.example.yaml`](../../../freesbc.example.yaml). The carrier lines below use `203.0.113.60:5060` and `203.0.113.60:5061` as stand-ins; use your own. The matching FreeSBC side:

```yaml
edge:
  switch: [10.77.0.10:5060]
  switch_carrier_port: 5080
  carriers:
    carrier-a: 203.0.113.60:5060   # must equal gateway "proxy" in sip_profiles/external/carrier-a.xml
    carrier-b: 203.0.113.60:5061   # must equal gateway "proxy" in sip_profiles/external/carrier-b.xml
```

## Files

Paths are relative to the FreeSWITCH conf directory (`/etc/freeswitch`, `/usr/local/freeswitch/conf`, ...). They are written against the stock `vanilla` configuration of FreeSWITCH 1.10.

| File | Purpose |
|---|---|
| `freesbc-vars.xml` | Global variables: SIP domain, pinned `ext-*-ip`, default password. Included from `vars.xml`. |
| `autoload_configs/acl.conf.xml` | `freesbc_carrier` list: only `10.77.0.2` may use the carrier port. |
| `sip_profiles/internal.xml` | Client port 5060: digest auth, no trust, no NAT handling. |
| `sip_profiles/external.xml` | Carrier port 5080: ACL, own context, owns the gateways. |
| `sip_profiles/external/carrier-a.xml` | Registered carrier line. |
| `sip_profiles/external/carrier-b.xml` | IP-authenticated carrier line (failover). |
| `dialplan/carrier-in.xml` | Context for inbound carrier calls. |
| `dialplan/default/00_freesbc_outbound.xml` | Outbound routing with failover, for authenticated users. |

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

Edit before use: the addresses and `domain` in `freesbc-vars.xml`, the `10.77.0.x` addresses in the profiles and ACL, the gateway usernames, passwords and `proxy` values, and the `default_password`. Then restart FreeSWITCH (profiles) or `reloadxml` and `reloadacl` (dialplan, ACL, gateways via `sofia profile external rescan`).

The stock `vars.xml` resolves `external_rtp_ip` and `external_sip_ip` through `stun.freeswitch.org` at startup. The later `set` in `freesbc-vars.xml` wins, but the lookups still run and, offline, cost about 5 s each with an `[ERR] stun-set failed` log line. Comment the two `stun-set` lines out of `vars.xml` to skip them.

## Rule by rule

### The client port trusts nothing (`docs/edge.md`: "Never identify or trust a request by FreeSBC's IP on the client port")

Every client REGISTER, INVITE, SUBSCRIBE and MESSAGE reaches the `internal` profile from `10.77.0.2`. If anything on that profile trusts that address, every client call skips digest authentication. `sip_profiles/internal.xml` therefore has:

- `auth-calls=true`, `auth-subscriptions=true`, `inbound-reg-force-matching-username=true`.
- **No `apply-inbound-acl`.** The stock profile sets `apply-inbound-acl=domains`. The `domains` list is built from the directory: a user with a `cidr=` attribute, or a `cidr`/`10.77.0.2` node added to the list, makes that address a trusted source. `acl.conf.xml` keeps the `domains` list but nothing applies it. Do not add `cidr=` to directory users either.
- No `apply-register-acl` either (same reason).
- `challenge-realm` and `force-register-domain` fixed to `$${domain}`, which `freesbc-vars.xml` sets to the name clients register with (`203.0.113.7` here, or the DNS name pointing at FreeSBC). The stock `domain` is the switch's own IP, which no client would use. Remove the `force-*` and `challenge-realm` lines if you host several domains.

Observed: an INVITE without credentials from `10.77.0.2` to `10.77.0.10:5060` is answered `407 Proxy Authentication Required`, and a REGISTER `401`. With a list containing `10.77.0.2` applied as `apply-inbound-acl`, the same INVITE gets `100 Trying` and goes straight to the dialplan (`480` for an absent callee), with no challenge.

### The carrier port is for FreeSBC only (`docs/edge.md`: "Only the carrier port may skip authentication ... Restrict it to `private.ip`")

`sip_profiles/external.xml` sets `auth-calls=false` (nothing else is delivered there) and `apply-inbound-acl=freesbc_carrier`; the list in `acl.conf.xml` allows `10.77.0.2/32` and denies the rest.

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
iptables -A INPUT -p udp --dport 5080 ! -s 10.77.0.2 -j DROP     # not run in the verification below
```

The external profile also has `disable-register=true`: nothing registers on it, carrier registrations are outbound.

### Carrier gateways (`docs/edge.md`: "Point every carrier gateway ... at FreeSBC as outbound proxy", "The `edge.carriers` entry must equal the host[:port] the switch puts in the Request-URI")

```xml
<gateway name="carrier-a">
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

- **`outbound-proxy` alone does not route REGISTER.** With only `proxy` and `outbound-proxy`, the REGISTER went `10.77.0.10:5080 -> 203.0.113.60:5060` directly, around FreeSBC, exposing `10.77.0.10` to the carrier. `register-proxy=10.77.0.2:5060` is required for REGISTER. `outbound-proxy` is what sends the INVITEs through FreeSBC (a gateway with no `register-proxy`, `carrier-b`, sends its INVITEs to `10.77.0.2:5060`).
- **Request-URI of REGISTER and INVITE is `sip:<proxy>`**, taken verbatim from `proxy` with `;transport=udp` appended: `REGISTER sip:203.0.113.60:5060;transport=udp`. FreeSBC compares `host[:port]` only, so the parameter does not matter. Include the port in both `proxy` and the `edge.carriers` entry, or in neither.
- **`realm`, `from-domain`, `register-transport` are not needed.** With none set, From and To carry the proxy host (`<sip:acct-a@203.0.113.60:5060>`) and the digest realm is taken from the carrier's challenge.
- The REGISTER `Contact` is `sip:gw+carrier-a@10.77.0.10:5080;transport=udp;gw=carrier-a`. FreeSBC rewrites it toward the carrier to `sip:gw+carrier-a@203.0.113.7:5060;fsbc=<token>`, so the switch address never leaves the LAN.
- The 200 OK returns `Contact: ...;expires=300` (the carrier's grant, relayed by FreeSBC); FreeSWITCH refreshes on that.
- The registration shows in the FreeSBC log: `carrier registration carrier=carrier-a ... expires=300`.

`outbound-proxy` and `register-proxy` take `host:port` and are always UDP.

### Inbound carrier calls (`docs/edge.md`: "Identify inbound carrier calls ...")

FreeSBC delivers every carrier request to `10.77.0.10:5080`, so it lands in the `carrier-in` context (the `external` profile's `context`), which can only be reached from there. Three ways to tell which carrier it is, all shown in `dialplan/carrier-in.xml` and all observed:

1. **`${sip_h_X-FreeSBC-Carrier}`** is the `edge.carriers` name (`carrier-a`), or `unknown` for an `edge.carrier_sources` address that matches no entry. Works for both a registered line and a DID.
2. **The registration line.** A carrier call that uses the Contact the gateway registered is delivered with the Request-URI restored to `sip:gw+carrier-a@10.77.0.10:5080;transport=udp;gw=carrier-a`. sofia then sets `${sip_gateway}=carrier-a` and `${sip_req_user}=gw+carrier-a`. `destination_number` is the gateway `extension` param, which defaults to the **username** (`acct-a`), not `gw+carrier-a`; match `${sip_gateway}`.
3. **The DID.** A call addressed to the number (no token) arrives with the Request-URI unchanged (`sip:1555010001@203.0.113.7:5060`) and `destination_number` is the number.

`X-FreeSBC-Carrier` is added by FreeSBC on the private side and every `X-FreeSBC-*` header from the public side is stripped, so it can be trusted as long as only FreeSBC reaches the carrier port (see above).

### Outbound and failover (`docs/edge.md`: "Line selection and failover are the switch's job")

```xml
<action application="set" data="continue_on_fail=true"/>
<action application="bridge" data="sofia/gateway/carrier-a/$1|sofia/gateway/carrier-b/$1"/>
<action application="hangup" data="${originate_disposition}"/>
```

FreeSBC never retries on another carrier; the `|` does it. Verified with the failing line first: `carrier-b` answered `503` and FreeSBC relayed it, FreeSWITCH moved on to `carrier-a`, which answered (two `proxying INVITE to carrier` lines, `carrier=carrier-b` then `carrier=carrier-a`).

`00_freesbc_outbound.xml` lives in the `default` context (reached only by authenticated users, whose `user_context` is `default`) and is named so it sorts before the stock `01_example.com.xml`. Its number pattern is an allowlist; narrow it to what you sell.

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

FreeSBC only does what the edge alone can do ([scope rule](../../../README.md#not-in-scope)). These stay on the switch. The `limit` on a gateway key, `sched_hangup` and the CDR below were run against the same setup; the per-user `limit` uses the same syntax and was not run.

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

2026-10-09, end to end in Docker by [`test/run.sh`](test/run.sh) (builds FreeSBC, derives the switch, phone and carrier configs from the image's stock config plus the files in this directory, prints `PASS`/`FAIL`, removes everything; `KEEP=1` keeps the containers) on two networks (private `10.77.0.0/24`, public `203.0.113.0/24`): FreeSBC (commit `81a50fe`, linux/arm64 build, `10.77.0.2` and `203.0.113.7`); FreeSWITCH `1.10.12-release-10222002881-a88d069d6f` (image `safarov/freeswitch:latest`, linux/amd64 under emulation, stock `vanilla` config plus the files in this directory) at `10.77.0.10`; a second FreeSWITCH as the phone (registering user `1000` through FreeSBC with a gateway) and a third as the carrier (a registrar for `acct-a` on `203.0.113.60:5060`, a profile that answers `503` on `:5061`).

- A client registered through FreeSBC with digest (`registration accepted aor=1000@203.0.113.7`) and called `9196` (echo): `407`, authenticated retry, answered, and the RTP counters on FreeSBC moved symmetrically; a call placed from the switch with `originate user/1000@203.0.113.7` reached the phone, and the stored Contact kept its `fsbc=` parameter.
- The carrier gateway REGISTERed through FreeSBC to the carrier (`carrier registration carrier=carrier-a expires=300`, gateway `REGED`); an outbound call (`15551230001`) reached the carrier with `Via` and `Contact` showing `203.0.113.7`; failover `carrier-b` (503) then `carrier-a` worked.
- Inbound carrier calls reached `carrier-in` with the carrier visible: `inbound carrier=carrier-a did=1555010001 ...` for a DID call (bridged on to the phone), and `${sip_gateway}=carrier-a` for a call to the registered Contact (`Regex (PASS) [registered-line-a] ${sip_gateway}(carrier-a)`).
- From `10.77.0.99` (not `private.ip`), an INVITE to `10.77.0.10:5080` got `403 Forbidden`; the other methods are in the table above.
- An INVITE and a REGISTER from `10.77.0.2` to `:5060` with no credentials were challenged (`407`, `401`).

Not verified: a pool of several switches; TLS/WebSocket/WebRTC clients and SDES carriers (FreeSBC converts them before the switch); real carriers; IPv6; the `iptables` rule; Opus; SUBSCRIBE/MESSAGE/REFER/PRACK/UPDATE from a client (the profile settings are the stock ones, and FreeSBC's own interop test covers sofia's handling of the dialog headers, see `docs/edge.md`, "Verification against a real FreeSWITCH").

`test/run.sh` repeats the checks above except the non-INVITE answers on 5080, the `limit`, `sched_hangup` and CDR runs, which were manual.
