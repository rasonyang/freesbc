# Asterisk (pjsip) behind FreeSBC

Minimal, copy-pasteable Asterisk configuration for the FreeSBC reference topology. [`docs/edge.md`](../../../docs/edge.md) ("Switch-side requirements") stays the normative list; these files illustrate it.

**Verified with** (2026-10-15): Asterisk 22.10.1 (`andrius/asterisk:latest`, aarch64, stock modules) behind two FreeSBC nodes at commit `694bff1` (linux/arm64 build), in Docker, by [`test/run.sh`](test/run.sh). Passed end to end:

- a client registers with digest through FreeSBC; its stored Contact keeps `;fsbc=<token>`; it calls `600` (Echo) and RTP flows both ways through the anchor; the switch calls the registered client;
- a carrier `REGISTER` (digest, `outbound_proxy`) succeeds; an outbound call to a carrier that digest-challenges the INVITE; `Dial` failover from `carrier-a` to `mobile` after a 503;
- inbound carrier calls identified by `X-FreeSBC-Carrier`, with the header visible in the dialplan (`PJSIP_HEADER(read,...)`), also by registration line (`line=yes`, a manual one-off run, not part of `test/run.sh`);
- a request to port 5080 from a LAN address other than `private.ip` is rejected by the endpoint `acl` (the switch answers a generic 401); an INVITE without credentials on 5060 is challenged; a client that sends `X-FreeSBC-Carrier` on the public side never reaches the switch with it (FreeSBC strips it);
- the per-user `GROUP_COUNT()` limit (third concurrent call gets `Busy()`);
- two FreeSBC nodes (see "Two FreeSBC nodes"): carrier calls and registrations through both nodes, both `private.ip` accepted by the `acl` and the `identify`; a drained node (`POST /api/drain`) answers carrier INVITEs 503 and `Dial` moves to the other node, while an agent attached to it still gets and makes calls; after a crash (`SIGKILL`) of a node the next carrier call in each direction and the next agent call (re-registered through the other node) complete through the survivor; `max_contacts=1` + `remove_existing=yes` replaces a stale Contact; `rtp_timeout` tears down the channels whose node died; qualify on carrier contacts, and the effect of OPTIONS `503` and `404` on it (below).

**Not verified:** TCP/TLS/WS/WSS clients and carriers, WebRTC clients, SDES-SRTP, a switch pool, SUBSCRIBE/MWI/BLF, REFER, MESSAGE, PRACK/UPDATE against a peer that needs them, `qualify_frequency` on client contacts other than the stale-Contact case, the `Dial` `L()` / `TIMEOUT(absolute)` timers actually firing (the options are accepted; the 1 h limit was not waited out), DNS-named carriers (the test substitutes IP addresses for the two `edge.carriers` entries), `opus` (accepted in `allow=`, not exercised on a call), other Asterisk versions (the option names below are for Asterisk 20+).

The test uses other subnets (10.78.0.0/24 and 198.18.0.0/24) so it does not collide with a lab on the documented ones; it rewrites the addresses with `sed` and runs the files in this directory unchanged otherwise, except for three shortened timers (`rtp_timeout` 30 to 10 s, carrier `qualify_frequency` 30 to 5 s, and qualify turned on for client 1002 only).

## Files

| File | Install as | Content |
|---|---|---|
| [`pjsip.conf`](pjsip.conf) | `/etc/asterisk/pjsip.conf` | two UDP transports, client endpoints, two carriers (one registered, one by DID), each with an endpoint per FreeSBC node |
| [`extensions.conf`](extensions.conf) | `/etc/asterisk/extensions.conf` | client, outbound (failover between carriers and between FreeSBC nodes, limits) and carrier contexts |
| [`acl.conf`](acl.conf) | `/etc/asterisk/acl.conf` | `freesbc-only`: the carrier endpoints accept only the `private.ip` of each FreeSBC node |

## Reference topology

The addresses of `freesbc.example.yaml`: FreeSBC `public.ip` 203.0.113.7, `private.ip` 10.77.0.2; this switch 10.77.0.10. For two nodes, node B is `private.ip` 10.77.0.3 with its own `public.ip`; the files carry both, and everything marked "node B" is deleted for a single node.

| | Node A | Node B | Switch |
|---|---|---|---|
| FreeSBC `private.ip` | 10.77.0.2 | 10.77.0.3 | 10.77.0.10 (ports 5060 and 5080) |
| `acl.conf` `freesbc-only` | `permit=10.77.0.2/255.255.255.255` | `permit=10.77.0.3/255.255.255.255` | one `permit` per node |
| Outbound endpoints, aors and registrations | `carrier-a`, `mobile` (`outbound_proxy` 10.77.0.2) | `carrier-a-b`, `mobile-b` (`outbound_proxy` 10.77.0.3) | one set per node |
| Registered trunk account | `acct` (`contact_user=acct`) | `acct-b` (`contact_user=acct-b`) | `[did]` has an extension for each |
| Dial order in `[via-nodes]` | first | on `CHANUNAVAIL` / `CONGESTION` of the first | |
| Inbound identification | `identify` by `X-FreeSBC-Carrier` | the same `identify` | one per carrier, not per node |

```yaml
edge:
  switch: [10.77.0.10:5060]      # client port
  switch_carrier_port: 5080      # carrier port
  carriers:
    carrier-a: sip.carrier-a.com          # = aor contact in pjsip.conf
    mobile:    223.76.90.4:16060          # = aor contact in pjsip.conf
```

The same `edge.switch` and `edge.carriers` go to both nodes (the Request-URI match and the user hash need them identical); only `public.ip` and `private.ip` differ, which one file can take from `${VAR}`.

Replace the passwords (`CHANGE-ME-*`), the carrier names and the account (`acct`). Carrier and client users are examples.

## Rule to snippet

| `docs/edge.md` rule | Where |
|---|---|
| Carrier requests arrive on `switch_carrier_port`, clients on the switch port | `[transport-clients]` 10.77.0.10:5060, `[transport-carrier]` 10.77.0.10:5080; each carrier object sets `transport=transport-carrier`, each client `transport=transport-clients` |
| Outbound proxy on every carrier object, with `;lr` | `outbound_proxy=sip:10.77.0.2:5060\;lr` on the carrier `endpoint`, `aor` and `registration` (the backslash keeps the semicolon from starting a comment); the node B objects point at `10.77.0.3` |
| The `edge.carriers` entry equals the Request-URI host[:port] | carrier `aor` `contact=sip:sip.carrier-a.com` / `sip:223.76.90.4:16060`; the `registration` `server_uri` uses the same host so the REGISTER also matches |
| Identify inbound carrier calls | `type=identify` with `match_header=X-FreeSBC-Carrier: /^carrier-a$/` (anchored, so `carrier-a2` does not match); alternative: `line=yes` + `endpoint=` on the registration (commented in `pjsip.conf`) |
| Never trust or identify by FreeSBC's IP on the client port | no `identify` with `match=`, no `ip` and no `anonymous` in `endpoint_identifier_order=header,username,auth_username`, no `[anonymous]` endpoint |
| Only the carrier port may skip authentication, restricted to `private.ip` | the carrier endpoints have no `auth=` and carry `acl=freesbc-only` (`acl.conf`); also firewall 5080 (below) |
| Subscriptions, transfers, messages are the switch's to accept | client endpoints are authenticated like calls (`allow_subscribe=yes`; MWI needs `mailboxes=`, BLF needs hints); REFER and MESSAGE follow the endpoint's context |
| Line selection and failover are the switch's job | `[outbound]` in `extensions.conf`: carrier-a through node A then node B (`[via-nodes]`), then `mobile` the same way, each step when `DIALSTATUS` is `CHANUNAVAIL` or `CONGESTION` |
| Multiple switches need a shared registration database | see "A switch pool" |

### Why the carrier is identified by header, and why that is safe

Asterisk applies `identify` and `acl` to the source address and headers of a request, not to the transport it arrived on: a request on 5060 can be identified as the carrier endpoint, and one on 5080 as a client. The split into two ports therefore does not by itself separate the two kinds of traffic. What does:

- FreeSBC strips every `X-FreeSBC-*` header from public input and sets `X-FreeSBC-Carrier` only on carrier-to-switch requests (always to port 5080). A public client cannot make the switch see it (checked: a client that sends the header on the wire is identified as itself; the switch logs no carrier call).
- The carrier endpoints carry `acl=freesbc-only`: a request that matches the header from any other address is not identified (checked from a second LAN host on 5060 and 5080: "Not match Endpoint ACL", answered 401).
- The `from-carrier` context can only ring local extensions (`[did]`): even a request that did get through could not dial out.
- Firewall the carrier port to FreeSBC as well, so no other host reaches it at all:

```sh
iptables -A INPUT -p udp --dport 5080 ! -s 10.77.0.2 -j DROP
```

`header` is first in `endpoint_identifier_order` so a carrier call whose caller ID user equals a client name (for example `1001`) is not matched by `username` and challenged. `ip` is absent on purpose: with it, `type=identify` entries of kind `match=` would identify private.ip and skip digest for every client call. `anonymous` is absent so there is no endpoint an unauthenticated request can fall back to (the equivalent of `allowguest=no`).

`line=yes` identification (`request_uri` in the order) also works, but the line token is the only secret, and a request with that token in its Request-URI is identified wherever it arrives. Use the header; keep `line=yes` only if you cannot match the header. The token changes when Asterisk restarts, so a carrier that allows one contact per account must accept the new one (the example carrier simulator uses `remove_existing=yes`).

An `unknown` value (a `carrier_sources` address matching no `edge.carriers` entry) matches no identify and is challenged like any unknown caller.

## Two FreeSBC nodes

Two independent FreeSBC nodes (no shared state, each with its own `public.ip` and `private.ip`) need these switch-side settings. The deployment as a whole (carriers, clients, rolling restart) is in [`docs/two-node.md`](../../../docs/two-node.md). Everything marked node B in the files is removed for a single node.

| Setting | File | What it does |
|---|---|---|
| `permit=` for each node's `private.ip` | `acl.conf` | the carrier endpoints accept requests from either node and from nothing else |
| One endpoint, aor and (registered trunk) registration per node, `outbound_proxy` at that node | `pjsip.conf` (`carrier-a` / `carrier-a-b`, `mobile` / `mobile-b`) | a call out through node B is a different endpoint, so `Dial` can try them one after the other |
| A separate trunk account for node B (`acct-b`, `contact_user=acct-b`, own auth) | `pjsip.conf`, `[did]` in `extensions.conf` | a carrier that keeps one Contact per account would let a second registration replace the first; the carrier calls the account that matches the node |
| `[via-nodes]`: `Dial` node A, then node B when `DIALSTATUS` is `CHANUNAVAIL` or `CONGESTION` | `extensions.conf` | failover on `503` (a drained node), on a node that does not answer (after the INVITE timer, 32 s) and on one qualify already found down (at once) |
| `qualify_frequency=30`, `qualify_timeout=3` on the carrier aors | `pjsip.conf` (`carrier-aor` template) | a crashed node's endpoint turns Unavail and `Dial` skips it without waiting for the timer |
| `rtp_timeout=30` | `pjsip.conf` (client and carrier endpoints) | a channel whose FreeSBC node died is hung up |
| `max_contacts=1` and `remove_existing=yes` | `pjsip.conf` (`client-aor` template) | one Contact per agent: the agent registering through the other node replaces the stale one |
| (none) | | an agent is reached through the node named in its stored Contact (`fsbc=` token and host), so the switch needs no per-node agent setting |

Unchanged from a single node: the `identify` blocks (the header names the carrier, not the node), the transports, the client endpoints.

What `test/run.sh` showed (Asterisk 22.10.1):

- **`Dial` failover.** A `503` ends `Dial` with `DIALSTATUS=CONGESTION` (`HANGUPCAUSE=34`) at once; a `404` ends it with `CHANUNAVAIL` (`HANGUPCAUSE=1`, at once). A node that does not answer at all (killed) ends with `CHANUNAVAIL` (`HANGUPCAUSE=18`) after 32 s, the pjsip INVITE timer, not the `Dial` timeout of 60. Both `[via-nodes]` conditions therefore cover a drained node, a missing contact and a dead node. `NOANSWER` and `BUSY` are not retried. Cost of a dead node nobody has qualified yet: up to 32 s on the call that finds it.
- **Qualify and OPTIONS `503` from a draining node.** Asterisk counts any answer, including `503` with `Retry-After`, as reachable: the contact stays `Avail`. Only a timeout makes it `Unavail`. Qualify therefore detects a crashed or unreachable node, not a drain; a drained node is handled by the INVITE `503` and the `CONGESTION` branch above (checked: a call placed while node A drained was answered `503` by A and completed through B).
- **Qualify and OPTIONS `404`.** A stale client Contact (an `fsbc=` token FreeSBC no longer holds, after a node restart) answers qualify with `404`; the contact stays `Avail` and `Dial` to it ends `CHANUNAVAIL` at once. Qualify does not clean up stale client Contacts; the client's next registration does.
- **One Contact per agent.** With `max_contacts=1` and `remove_existing=yes`, an agent that registers again through node B replaces its Contact that named node A: exactly one Contact is left, the new one.
- **`rtp_timeout`.** With a node killed (`SIGKILL`, so no BYE is sent), Asterisk logs `Disconnecting channel ... for lack of audio RTP activity in N seconds` for each channel and hangs it up, about N seconds after the last RTP (checked with N=10; shipped 30). Media that never flows is torn down the same way, so keep `rtp_timeout` above the longest silence a far end can send (hold and `rtp_timeout_hold` were not exercised; `rtp_timeout_hold` is not set).
- **Not exercised:** a carrier or client over TCP/TLS, a client other than plain UDP, a pool of two switches behind the nodes, `rtp_timeout_hold`, Asterisk versions other than 22.

## Common notes

- **Transport to FreeSBC is UDP only**: `protocol=udp` on both transports, no TCP/TLS toward the switch.
- **Keep the `fsbc=` parameter.** The stored Contact of a client is `sip:1001@10.77.0.2:5060;transport=udp;fsbc=<token>`; pjsip stores it as is and uses it as the Request-URI of calls to the client (checked in `pjsip show contacts` and on the wire). The same holds for the carrier side's `;line=` parameter. Do not enable anything that rewrites a registered Contact (`rewrite_contact=yes`).
- **The registrar must return an expiry.** The `aor` bounds are `default_expiration=300`, `minimum_expiration=60`, `maximum_expiration=3600`; the 200 OK carries `;expires=`. FreeSBC relays it, the carrier-side binding lives for the granted expiry.
- **NAT is FreeSBC's job.** FreeSBC anchors all media and rewrites Contact and SDP to `private.ip`, so on the switch: `direct_media=no`, `rewrite_contact=no`, `force_rport=no`, `rtp_symmetric=no`, `ice_support=no`, `media_encryption=no`, no `external_signaling_address`, `external_media_address` or `local_net` on the transports. Each would only matter if a public address were involved; none is. `media_address=10.77.0.10` only pins the advertised address on a multi-homed host. The switch sees the real client address in the proxy's `Via ... received=` only.
- **Plain RTP/AVP, also for WebRTC clients.** Do not set `webrtc=yes` or DTLS options on the endpoints: FreeSBC terminates ICE and DTLS-SRTP toward the browser and speaks plain RTP/AVP to the switch (the switch leg is never SRTP).
- **Codecs and DTMF.** `allow=ulaw,alaw,opus`, `dtmf_mode=rfc4733` (`telephone-event`). FreeSBC does not transcode, so a call only works when both ends share a codec, and an answer that renumbers a payload type is refused (488).
- **Reliable provisionals, UPDATE, SUBSCRIBE/NOTIFY (MWI, BLF), REFER and MESSAGE are proxied**; the defaults (`100rel`, `timers`) are fine. The switch authenticates and routes them by its own policy. PUBLISH is answered 405 by FreeSBC.
- **No qualify on clients.** `qualify_frequency=0`: a client's reachability is its registration. An OPTIONS ping to a client is routed by its `fsbc=` token like any request to it (checked with qualify on one test user: a live Contact answers 200, a stale token gets 404 from FreeSBC and the contact stays `Avail`), so it adds nothing over the registration. Carrier aors do use qualify (see "Two FreeSBC nodes").
- **Everything arrives from one address.** Every client request comes from `10.77.0.2`, so Asterisk-side address banning (fail2ban on the security log, `acl` lockouts) would ban FreeSBC itself. Rate limiting and scanner bans belong to FreeSBC's `shield`; do not use the source address in switch-side brute-force rules.
- **From/To hosts.** Toward the carrier FreeSBC rewrites a From/To/P-Asserted-Identity host equal to `private.ip` or a switch IP to `public.ip`; set `from_domain=` on a carrier endpoint only if the carrier needs a specific domain.

## Policy FreeSBC deliberately does not do

All of these are the switch's job (they pass neither of the two questions of the [scope rule](../../../README.md#not-in-scope)). `extensions.conf` carries working examples.

```asterisk
; per-user and per-carrier concurrency
exten => s,1,Set(GROUP(user)=${CALLERID(num)})
 same => n,GotoIf($[${GROUP_COUNT(${CALLERID(num)}@user)} > 2]?busy)
 same => n,Set(GROUP(carrier)=carrier-a)
 same => n,GotoIf($[${GROUP_COUNT(carrier-a@carrier)} > 30]?trynext)

; maximum call duration: whole call, and per Dial leg
 same => n,Set(TIMEOUT(absolute)=3600)
 same => n,Dial(PJSIP/${ARG1}@carrier-a,60,L(3600000:60000:30000))
```

- **Toll fraud.** Every client endpoint needs a strong password (digest auth is the only gate; FreeSBC holds no credentials). There is no anonymous or IP-trusted endpoint. `[from-clients]` routes only local extensions and 10-digit national numbers; everything else, in particular international and premium prefixes, falls into a catch-all `Hangup(21)` with a log line. `[from-carrier]` can only ring local extensions, so a stolen or forged carrier identity cannot place outbound calls. Keep the dialplan patterns narrow; a single `_X.` that reaches a carrier is the usual hole.
- **CDR/CEL.** Enable in `cdr.conf`/`cel.conf` as usual (`cdr_csv`, `cdr_adaptive_odbc`, `cdr_custom`). The caller's real address is not in the switch's view; the call's `Via ... received=` is. FreeSBC's own record of a call is the `call ended` log line and `freesbc_edge_calls_ended_total{reason}`.
- **Caller ID toward carriers** is the switch's: set `CALLERID(num)` and, if the carrier wants it, `send_pai=yes` / `trust_id_outbound=yes` on the carrier endpoint (not set in the examples).

## A switch pool

With more than one entry in `edge.switch` every node needs the same registrations: FreeSBC hashes a user to a node, and after a failover the next node re-challenges and must accept the same credentials and find the same AoR. Asterisk has no ready-made shared registrar: the options are pjsip realtime (`sorcery.conf` + `extconfig.conf` mapping `ps_endpoints`, `ps_auths`, `ps_aors`, `ps_contacts` to a shared database, `ps_contacts` being the shared registration table) or an external provisioning tool that writes identical endpoints and auth to every node. Realtime contacts across several writers has its own pitfalls (expiry, qualify, `max_contacts` races), and this example does not cover or test it. Carrier registrations and the calls delivered to them stay on the node that registered (the token names that node), so register each carrier from one node or give each node its own carrier account.

## Running the test

```sh
examples/switch/asterisk/test/run.sh
```

Needs Docker and Go. It builds FreeSBC for Linux, creates networks and containers named `ast108-*` (the switch, FreeSBC nodes A and B, two client simulators, two carrier simulators and a LAN intruder), runs the checks printed as `PASS`/`FAIL` (and `INFO` lines with the observed values), and removes everything. It takes about 8 minutes. `KEEP=1` leaves the containers for inspection.

The two-node part runs in this order: both nodes up; drain A (`POST /api/drain` on A's admin API) and call in every direction; undrain; restart A (stale Contacts); put long calls through A and `SIGKILL` it (`rtp_timeout`, `Dial` through a silent node, qualify); with A still down, the next inbound carrier calls (the carrier simulators try the second SBC address on `503` or after 3 s) and the next agent call. Client failover is modelled by a second client simulator that registers the same user through node B once node A is gone; a real client does this itself (WSS/TCP reconnect, or a UDP phone's next registration).
