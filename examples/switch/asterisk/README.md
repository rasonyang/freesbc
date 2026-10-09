# Asterisk (pjsip) behind FreeSBC

Minimal, copy-pasteable Asterisk configuration for the FreeSBC reference topology. [`docs/edge.md`](../../../docs/edge.md) ("Switch-side requirements") stays the normative list; these files illustrate it.

**Verified with** (2026-10-09): Asterisk 22.10.1 (`andrius/asterisk:latest`, aarch64, stock modules) behind FreeSBC at commit `81a50fe` (linux/arm64 build), in Docker, by [`test/run.sh`](test/run.sh). Passed end to end:

- a client registers with digest through FreeSBC; its stored Contact keeps `;fsbc=<token>`; it calls `600` (Echo) and RTP flows both ways through the anchor; the switch calls the registered client;
- a carrier `REGISTER` (digest, `outbound_proxy`) succeeds; an outbound call to a carrier that digest-challenges the INVITE; `Dial` failover from `carrier-a` to `mobile` after a 503;
- inbound carrier calls identified by `X-FreeSBC-Carrier`, with the header visible in the dialplan (`PJSIP_HEADER(read,...)`), also by registration line (`line=yes`, a manual one-off run, not part of `test/run.sh`);
- a request to port 5080 from a LAN address other than `private.ip` is rejected by the endpoint `acl` (the switch answers a generic 401); an INVITE without credentials on 5060 is challenged; a client that sends `X-FreeSBC-Carrier` on the public side never reaches the switch with it (FreeSBC strips it);
- the per-user `GROUP_COUNT()` limit (third concurrent call gets `Busy()`).

**Not verified:** TCP/TLS/WS/WSS clients and carriers, WebRTC clients, SDES-SRTP, a switch pool, SUBSCRIBE/MWI/BLF, REFER, MESSAGE, PRACK/UPDATE against a peer that needs them, `qualify_frequency`, the `Dial` `L()` / `TIMEOUT(absolute)` timers actually firing (the options are accepted; the 1 h limit was not waited out), DNS-named carriers (the test substitutes IP addresses for the two `edge.carriers` entries), `opus` (accepted in `allow=`, not exercised on a call), other Asterisk versions (the option names below are for Asterisk 20+).

The test uses other subnets (10.78.0.0/24 and 198.18.0.0/24) so it does not collide with a lab on the documented ones; it rewrites the addresses with `sed` and runs the files in this directory unchanged otherwise.

## Files

| File | Install as | Content |
|---|---|---|
| [`pjsip.conf`](pjsip.conf) | `/etc/asterisk/pjsip.conf` | two UDP transports, client endpoints, two carriers (one registered, one by DID) |
| [`extensions.conf`](extensions.conf) | `/etc/asterisk/extensions.conf` | client, outbound (failover and limits) and carrier contexts |
| [`acl.conf`](acl.conf) | `/etc/asterisk/acl.conf` | `freesbc-only`: the carrier endpoints accept only `private.ip` |

## Reference topology

The addresses of `freesbc.example.yaml`: FreeSBC `public.ip` 203.0.113.7, `private.ip` 10.77.0.2; this switch 10.77.0.10.

```yaml
edge:
  switch: [10.77.0.10:5060]      # client port
  switch_carrier_port: 5080      # carrier port
  carriers:
    carrier-a: sip.carrier-a.com          # = aor contact in pjsip.conf
    mobile:    223.76.90.4:16060          # = aor contact in pjsip.conf
```

Replace the passwords (`CHANGE-ME-*`), the carrier names and the account (`acct`). Carrier and client users are examples.

## Rule to snippet

| `docs/edge.md` rule | Where |
|---|---|
| Carrier requests arrive on `switch_carrier_port`, clients on the switch port | `[transport-clients]` 10.77.0.10:5060, `[transport-carrier]` 10.77.0.10:5080; each carrier object sets `transport=transport-carrier`, each client `transport=transport-clients` |
| Outbound proxy on every carrier object, with `;lr` | `outbound_proxy=sip:10.77.0.2:5060\;lr` on the carrier `endpoint`, `aor` and `registration` (the backslash keeps the semicolon from starting a comment) |
| The `edge.carriers` entry equals the Request-URI host[:port] | carrier `aor` `contact=sip:sip.carrier-a.com` / `sip:223.76.90.4:16060`; the `registration` `server_uri` uses the same host so the REGISTER also matches |
| Identify inbound carrier calls | `type=identify` with `match_header=X-FreeSBC-Carrier: /^carrier-a$/` (anchored, so `carrier-a2` does not match); alternative: `line=yes` + `endpoint=` on the registration (commented in `pjsip.conf`) |
| Never trust or identify by FreeSBC's IP on the client port | no `identify` with `match=`, no `ip` and no `anonymous` in `endpoint_identifier_order=header,username,auth_username`, no `[anonymous]` endpoint |
| Only the carrier port may skip authentication, restricted to `private.ip` | the carrier endpoints have no `auth=` and carry `acl=freesbc-only` (`acl.conf`); also firewall 5080 (below) |
| Subscriptions, transfers, messages are the switch's to accept | client endpoints are authenticated like calls (`allow_subscribe=yes`; MWI needs `mailboxes=`, BLF needs hints); REFER and MESSAGE follow the endpoint's context |
| Line selection and failover are the switch's job | `[outbound]` in `extensions.conf`: `Dial` on `carrier-a`, then `mobile` when `DIALSTATUS` is `CHANUNAVAIL` or `CONGESTION` |
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

## Common notes

- **Transport to FreeSBC is UDP only**: `protocol=udp` on both transports, no TCP/TLS toward the switch.
- **Keep the `fsbc=` parameter.** The stored Contact of a client is `sip:1001@10.77.0.2:5060;transport=udp;fsbc=<token>`; pjsip stores it as is and uses it as the Request-URI of calls to the client (checked in `pjsip show contacts` and on the wire). The same holds for the carrier side's `;line=` parameter. Do not enable anything that rewrites a registered Contact (`rewrite_contact=yes`).
- **The registrar must return an expiry.** The `aor` bounds are `default_expiration=300`, `minimum_expiration=60`, `maximum_expiration=3600`; the 200 OK carries `;expires=`. FreeSBC relays it, the carrier-side binding lives for the granted expiry.
- **NAT is FreeSBC's job.** FreeSBC anchors all media and rewrites Contact and SDP to `private.ip`, so on the switch: `direct_media=no`, `rewrite_contact=no`, `force_rport=no`, `rtp_symmetric=no`, `ice_support=no`, `media_encryption=no`, no `external_signaling_address`, `external_media_address` or `local_net` on the transports. Each would only matter if a public address were involved; none is. `media_address=10.77.0.10` only pins the advertised address on a multi-homed host. The switch sees the real client address in the proxy's `Via ... received=` only.
- **Plain RTP/AVP, also for WebRTC clients.** Do not set `webrtc=yes` or DTLS options on the endpoints: FreeSBC terminates ICE and DTLS-SRTP toward the browser and speaks plain RTP/AVP to the switch (the switch leg is never SRTP).
- **Codecs and DTMF.** `allow=ulaw,alaw,opus`, `dtmf_mode=rfc4733` (`telephone-event`). FreeSBC does not transcode, so a call only works when both ends share a codec, and an answer that renumbers a payload type is refused (488).
- **Reliable provisionals, UPDATE, SUBSCRIBE/NOTIFY (MWI, BLF), REFER and MESSAGE are proxied**; the defaults (`100rel`, `timers`) are fine. The switch authenticates and routes them by its own policy. PUBLISH is answered 405 by FreeSBC.
- **No qualify.** `qualify_frequency=0`: an OPTIONS ping to a client would be routed by its `fsbc=` token like any request to it; this was not tested, so a client's reachability is its registration.
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

Needs Docker and Go. It builds FreeSBC for Linux, creates networks and containers named `ast108-*` (the switch, FreeSBC, a client and two carrier simulators and a LAN intruder), runs the checks printed as `PASS`/`FAIL`, and removes everything. `KEEP=1` leaves the containers for inspection.
