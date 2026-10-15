# Edge proxy (SIP / RTP / WebRTC)

FreeSBC is a stateful SIP and media edge proxy. It provides SIP registration proxying, UDP/WebSocket transport interworking, RTP anchoring, WebRTC-to-RTP media relay and a carrier path, all in front of a SIP switch (FreeSWITCH or Asterisk). It is configured by one YAML file; every key is in [config.md](config.md). See the [README](../README.md) for the overview and the [design doc](design.md) for the implemented behaviour in detail.

```text
   Phones, browsers                    Carriers
   SIP/UDP, SIP/WS(S) + WebRTC         SIP/UDP
              \                         /
               \                       /
                public.ip / public.bind
                        FreeSBC
                      private.ip:5060
                           |   Private LAN / VPN
                           |   SIP/UDP + RTP
                      Switch (FreeSWITCH / Asterisk)
```

- **Public side**: SIP over UDP, TCP, TLS, WS and WSS on `public.bind`; RTP, optionally SDES-SRTP; WebRTC (ICE-Lite + DTLS-SRTP). Everything FreeSBC advertises there uses `public.ip`. Behind 1:1 NAT (`public.bind` != `public.ip`) the router must forward every `edge.listen` port and the `rtp` range to `public.bind` with the same port numbers; `freesbc check`, `init` and `run` print that list (docs/config.md, "1:1 NAT checklist"). A forgotten port shows as calls that end at 32 s with `reason=ack_timeout` (see [Troubleshooting](troubleshooting.md#lost-ack-reasonack_timeout)).
- **Private side**: one fixed UDP socket, `private.ip:5060`, for all SIP to and from the switch, plus plain RTP/RTCP.
- **All signaling and media stay anchored through FreeSBC.** In SDP, Contact and the Request-URI, the switch is never given a public client's address and a public client is never given the switch's. On every public leg, client or carrier, the headers are hidden too: a public party sees FreeSBC's public Via, Record-Route and Contact alone, never the switch's Via, `private.ip`, a switch address in From, To or the identity headers, or the switch's product string (see [Topology hiding](#topology-hiding-on-public-legs)). The switch does see a client's address in the Via FreeSBC annotates with `received=`, because that Via is on the private side.

It is a **proxy, not a B2BUA**: Call-ID, From/To tags and CSeq pass through, and FreeSBC stays on the path via Record-Route: the RFC 5658 pair toward the switch, FreeSBC's public entry alone toward a client or carrier. The switch is the authoritative registrar and owns all call logic. REGISTER and its digest challenge are forwarded verbatim, and FreeSBC never holds a credential, for clients or for carriers. Carrier accounts, line selection and failover live on the switch; FreeSBC is its outbound proxy.

See [`freesbc.example.yaml`](../freesbc.example.yaml) for a complete annotated configuration.

## What it does

| Area | Behaviour |
|---|---|
| Transports | Public UDP / TCP / TLS / WS / WSS; private UDP. TCP, TLS, WS and WSS to UDP is real interworking, with the connection bound to the registration: a request to such a client always uses the connection it registered on and is never dialed. |
| Methods | REGISTER, INVITE, ACK, CANCEL, BYE, OPTIONS, INFO, NOTIFY, SUBSCRIBE, REFER, MESSAGE. OPTIONS from the public side is answered locally rather than multiplied onto the switch, and only for an admitted source (see [Admission and abuse controls](#admission-and-abuse-controls)). NOTIFY from the switch is forwarded whatever its `Event` (for example BroadSoft `talk`/`hold` remote call control), including on an early dialog. SUBSCRIBE/NOTIFY (MWI, BLF), REFER (call transfer) and MESSAGE are proxied with the limits under Known limitations; PUBLISH is answered 405. |
| REGISTER | Proxied verbatim, digest and all. The Contact is rewritten toward the switch (so inbound calls route back through FreeSBC, carrying an `fsbc=` token) and restored on the way back (so sip.js accepts the registration). The binding expiry follows the registrar's grant for this device's own Contact, not the client's request. A `Contact: *` un-REGISTER is forwarded as `*` and removes every binding of the AoR. |
| SDP | A typed subsystem over `pion/sdp/v3`, with no string manipulation. Bodies are **constructed**, never derived from the other leg, which is what makes the two address-leak guarantees structural. |
| Codecs | PCMU, PCMA, Opus and RFC 4733 telephone-event, passed through with the offerer's payload numbers. **No transcoding**: no common codec means a clean 488. |
| Media | Every stream anchored on an SBC port pair, on both sides. Symmetric RTP: the destination is seeded from SDP so audio flows immediately, then corrected by the first authenticated packet. A destination is never an unspecified, multicast, broadcast or link-local address, nor a loopback one unless the SBC's own media plane is on loopback. The public leg latches loosely (a hard-NAT phone may signal an unroutable address), but ranks sources: the exact SDP address beats the SDP or SIP source IP, which beats anything else, and a better-ranked source takes the latch back. An off-path source that sends first therefore holds the call's audio only until the phone's first packet; when the SDP address is the phone's SIP address, audio is not redirected to another port for 3 s. The private leg latches strictly on the switch's signalled IP. |
| WebRTC | ICE-Lite, DTLS, SRTP/SRTCP with RTCP-mux, built directly on `pion/ice`, `pion/dtls` and `pion/srtp` (no `PeerConnection`). The DTLS identity is a per-process self-signed certificate. The peer certificate is checked against the signalled `a=fingerprint` inside the DTLS handshake, so a mismatched peer never gets SRTP keys and no media is relayed for it. Both call directions: a browser's own offer is answered, and a call the switch places to a client registered over ws or wss gets FreeSBC's own DTLS-SRTP offer (`a=setup:actpass`), whose leg starts when the browser answers. Enabled by `edge.listen.ws` or `wss`. Manual real-browser test: [`docs/smoke/webrtc-dtls.md`](smoke/webrtc-dtls.md). |
| DTMF | RFC 4733 telephone-event traverses the relay untouched; SIP INFO is proxied as signaling. |
| re-INVITE | Hold, unhold, session-timer refresh and codec changes are renegotiated with the anchor intact: the body is rebuilt for the far side on the ports the session already holds, and a WebRTC leg keeps its ICE credentials, fingerprint and DTLS role, so media is never interrupted. A re-INVITE that moves either side's media address re-points the anchor to it once the 2xx completes the exchange; one whose 2xx cannot be anchored is ACKed and the call is ended on both sides. |
| Dialogs | Identified by Call-ID and both tags (RFC 3261 §12): only a BYE that names the dialog's tags, and that its far end accepts, ends it. The dialog is on record before its 2xx is relayed, so an immediate ACK always finds it; 2xx retransmissions are relayed until Timer M. A 2xx whose ACK never arrives ends the call as `ack_timeout` (counted in `freesbc_edge_ack_missed_total{plane}`; see [Calls that end for a missing ACK](#calls-that-end-for-a-missing-ack) and [Troubleshooting](troubleshooting.md#a-call-connects-then-drops)). |
| Lifecycle | Media is released deterministically on BYE (from either side), CANCEL, a failed final response, dialog teardown, media silence (5 minutes) and shutdown. A 2xx whose SDP cannot be anchored, one from a second fork, or one that races a CANCEL is ACKed and BYEd rather than left as a zombie dialog. When media silence from either end (or a DTLS fingerprint mismatch) ends a call, both endpoints are sent a BYE. A CANCEL is relayed without holding up the caller's 487, and an INVITE that outlives its 5-minute backstop is CANCELled and answered 408. A call whose 2xx ACK does not arrive within 32 s is ended with a BYE to both ends (`ack_timeout`), unless the callee hung up first. |
| Abuse | See [Admission and abuse controls](#admission-and-abuse-controls). |

## Admission and abuse controls

- **Public out-of-dialog SUBSCRIBE and MESSAGE.** Admitted only from the exact transport address of a live registration, like an INVITE, but not from a carrier source (405). Anything else is dropped with no response and counted as `subscribe_not_admitted` or `message_not_admitted`.
- **Public BYE and INFO that name no dialog on record.** Forwarded to the hashed switch only from the exact transport address of a live registration or from a carrier source (a client or carrier whose dialog record is gone after a restart). Any other source is answered `481 Call/Transaction Does Not Exist` at the edge, nothing reaches the switch, and the refusal is counted as `dialogless_not_admitted` in `freesbc_edge_admission_drops_total{reason}` (unlike the silent drops above, the source gets the 481). A BYE or INFO that matches a dialog on record, and any request from the switch, is unchanged. Still keep the switch honest: it must answer 481 to a BYE or INFO it holds no dialog for, because a registered client can still send one (FreeSWITCH and Asterisk answer a request that matches no dialog with 481 by default; test it with a dialog-less INFO from a registered phone).
- **Public OPTIONS.** Answered (200 + `Allow`) only from the exact transport address of a live registration, from a carrier source, or when it carries a To tag naming a live dialog. Anything else is dropped with no response, nothing reaches the switch, and it is counted as `options_not_admitted` (a strike like the other drops). A scanner therefore learns neither liveness nor the method list. Trade-off, accepted and with no config switch: a phone whose binding has lapsed gets silence until it re-REGISTERs, and a client that sends OPTIONS keepalives before its first REGISTER never gets an answer. Admission is decided before drain, so a stranger gets silence while draining as well. The switch's OPTIONS on the private socket is unchanged.
- **Public out-of-dialog INVITE.** Admitted only from the exact transport address (transport + IP:port) of a live registration, or from a carrier source. Anything else is dropped with no response and never reaches the switch. A source that is both a live registration's exact address and a carrier source is treated as a registration.
- **Carrier sources** are the resolved addresses of every `edge.carriers` entry plus `edge.carrier_sources`. Carriers are limited by `shield.carrier_rate_limit` instead of `shield.rate_limit`, are never banned as scanners, and are exempt from the per-source cap on calls ringing out.
- **The switch is trusted by the local socket it reaches** (the private socket), never by its source address. A datagram from the switch's own address that reaches a public listener is an ordinary public datagram, shielded and subject to admission.
- **REGISTER enumeration.** A source whose REGISTERs the switch has rejected 403/404 for 10 distinct AoRs within 10 minutes has its further REGISTERs dropped silently until that window ends (per IPv4 address, per IPv6 /64; challenges 401/407 do not count). Drops are counted in `freesbc_edge_admission_drops_total{reason}` and logged at WARN once per source IP, then at debug.
- **REGISTER brute force.** A public source with more than `shield.register_ban` (default `10/10m`) failed REGISTER credential attempts is banned for `shield.ban`, after which its REGISTERs no longer reach the switch. A failed attempt is a REGISTER with `Authorization` that the switch answers 401, 403, 404 or 407, using a nonce FreeSBC relayed to that source; over UDP a retry that reuses the challenged Via branch counts too, although sipgo answers it from its transaction. The credential-less first REGISTER of every registration, a refresh of a live binding (same AoR and Call-ID from the same source) and carrier sources never count, and any 2xx from the source clears its count, so a NAT site whose registrations succeed is not banned. Strikes count in `freesbc_edge_register_auth_failures_total`, bans show in `/api/shield/bans` with reason `register`, and the sources being counted in `/api/shield/offenders`.
- **Distributed REGISTER brute force.** The same failed attempts are also counted per AoR (`shield.register_ban_aor`, default `10/10m`, `off` disables), so guesses against one account spread over many source IPs, each under `shield.register_ban`, still add up. Over the threshold the AoR's limit is open for `shield.ban`: a REGISTER for it from a public source that holds no live binding of it is dropped silently, with no 401 and nothing sent to the switch (`freesbc_edge_admission_drops_total{reason="register_aor_locked"}`). A live binding of the AoR (from any port of the same source) and carrier sources are exempt, and a 2xx for the AoR clears the count and lifts the limit. The counted AoRs show in `/api/shield/offenders` with reason `register_aor`.
- **Low-and-slow scanners.** A public source with more than `shield.admission_ban` (default `50/5m`) requests dropped by admission (out-of-dialog INVITE, SUBSCRIBE or MESSAGE, or a BYE or INFO naming no dialog, from a source that is neither a carrier nor registered) and malformed datagrams (a UDP datagram or WS/WSS frame sipgo's parser is certain to reject, found by a cheap scan in the read filter) taken together is banned for `shield.ban` (reason `admission`, or `malformed` when a malformed datagram makes the last strike), however many source ports it rotates through and however slowly it sends. A ban earned by UDP requests blocks that IP on UDP only (kind `udp_ip` in `/api/shield/bans`), because datagram sources are forgeable; one earned over tcp, tls, ws or wss blocks the IP on every transport. The counts are separate. Carrier sources and any IP holding a registration binding are never counted, and a 2xx REGISTER clears the count. A forged UDP flood can therefore silence an unregistered, non-carrier address on UDP, never on its stream transports. A minute-by-minute WARN (`admission drops: N in 1m0s (A admission, M malformed) from K sources, top=IP (a admission, m malformed)`) summarises the admission drops and the malformed datagrams that were counted, kept apart by kind; it is silent when there were none. The sources being counted show in `/api/shield/offenders`.
- **Shield.** A source the shield has banned gets no response at all: it is dropped before parsing, and its TCP/TLS/WS/WSS connection is closed. A scanner over UDP, whose source address can be forged, has only its source socket banned, for a minute.
- **Ringing cap.** One public IP may have at most 64 calls ringing out (media anchored, no answer yet) at once; one more is refused 503 before any port is allocated, since media is anchored before the switch has authenticated the caller. Carrier sources are exempt.
- **Global call admission control.** `shield.max_sessions` (default: the calls `rtp` can anchor) caps the calls holding a session slot, and `shield.invite_rate_limit` (default off) is a global rate on new out-of-dialog INVITEs; both are hot. A registered client, a carrier or the switch over a limit gets `503` with `Retry-After` (5 s for the cap, the seconds until a token is free for the rate) and no media port is taken; an unknown public source is still dropped silently. Re-INVITEs and retransmissions are not charged. A ringing call holds a slot from its first INVITE, not from its answer. Counted in `freesbc_edge_invite_rejects_total{reason="session_cap"|"invite_rate"}`, current count in `freesbc_edge_sessions`. A peer or switch trunk that honours RFC 3261 §21.5.4 may hold off all new traffic to FreeSBC for the whole `Retry-After`, so keep `max_sessions` below the real media capacity with headroom rather than running at the limit. Per-carrier, per-user and per-source limits and maximum call duration are the switch's job (FreeSWITCH `limit`, `max-sessions`, `sessions-per-second`, `sched_hangup`; Asterisk `GROUP_COUNT()`, `TIMEOUT(absolute)`).
- **TLS certificate expiry.** The top-level `tls` leaf is loaded once at startup and never reloaded, so a renewed certificate (ACME, a new file under the same path) is not served until FreeSBC restarts. The Overview's TLS certificate card, `GET /api/tls` and the gauge `freesbc_tls_cert_expiry_timestamp_seconds{path}` show the leaf being served and its expiry; `disk_differs: true` means a different certificate is now on disk, so restart (draining first, below) to apply it. Within 10 minutes the same fact also raises the `degraded` health condition `tls_cert_renewed` and the gauge `freesbc_tls_cert_disk_differs`. An expired certificate is accepted at startup, and WSS browsers and the remote admin UI then fail until it is replaced.
- **Drain mode (maintenance).** `POST /api/drain` makes the edge refuse every new **carrier** call with `503 Service Unavailable` and `Retry-After: 30`, before any session slot, rate token or media port is taken, so a carrier fails over to another trunk and the switch tries another gateway:

  | Direction | While draining |
  |---|---|
  | carrier to switch | 503 |
  | switch to carrier | 503 |
  | registered client to switch | admitted |
  | switch to registered client | admitted |

  A source that is both a registration and a carrier source counts as the registration. A transfer leg or callback toward a client still works; one through a carrier fails until drain ends. An out-of-dialog `OPTIONS` reports drain too: `503` + `Retry-After: 30` to a carrier source, from the switch to FreeSBC itself, and from the switch to a carrier host (answered locally, not proxied). `OPTIONS` from clients, to a live client token and inside a dialog are unchanged; a public `OPTIONS` from a source that admission drops (`options_not_admitted`) is silent, drain or not. Separately from drain, a switch `OPTIONS` to an `fsbc=` token with no live binding is `404`, as an INVITE to it is. The OPTIONS `503` is an optimisation; the INVITE `503` is the guarantee. Counted in `freesbc_edge_invite_rejects_total{reason="draining"}`; an unknown public source is still dropped silently. Unchanged while draining: calls in place (re-INVITE, BYE, CANCEL, ACK, PRACK, UPDATE, RTP), REGISTER (clients keep their bindings), client OPTIONS, SUBSCRIBE, NOTIFY, MESSAGE and REFER. `DELETE /api/drain` leaves drain mode (each actual change is an admin audit event, `drain_on` or `drain_off`), `GET /api/drain` returns `{"draining", "since", "active_calls"}`, and the gauge `freesbc_edge_draining` is 1 while draining. Drain is runtime state only: it is not a config key, a reload does not touch it and a restart starts not draining. Nothing exits the process when the calls reach zero. To restart gracefully, enter drain, poll until `active_calls` is 0 or your timeout passes, then restart:

  ```sh
  A=http://127.0.0.1:8080; O='Origin: http://127.0.0.1:8080'
  curl -su admin:PASSWORD -X POST -H "$O" $A/api/drain
  until [ "$(curl -su admin:PASSWORD $A/api/drain | jq .active_calls)" = 0 ]; do sleep 5; done
  systemctl restart freesbc
  ```

  Add a deadline to the loop if a stuck call must not block the restart. The Overview page of the WebUI has the same controls.
- **Header hygiene.** Every `X-FreeSBC-*` header arriving on a public socket is removed before anything else; only FreeSBC adds them, and only on the private side.
- A handler panic is contained, counted (`freesbc_sip_handler_panics_total`), and answered 500 only if no final response went out.

## Carrier path

Carrier accounts live on the switch. The switch uses FreeSBC as its **outbound proxy**: it addresses requests to the carrier as usual (Request-URI = the carrier's `host[:port]`) and sends them to `private.ip:5060`. FreeSBC checks the Request-URI against `edge.carriers`, forwards the request to the carrier from its public address, and keeps the switch's address out of everything the carrier sees.

### Classification of switch requests

A switch-originated out-of-dialog request is classified by Request-URI only, never by registration state:

1. The Request-URI (or the topmost remaining Route) carries `fsbc` makes it a client request. An unknown or expired token gets 404.
2. The Request-URI `host[:port]` equals an `edge.carriers` entry makes it a carrier request. Methods: REGISTER, INVITE, OPTIONS; any other method gets 405.
3. Anything else gets 404. FreeSBC is never an open relay for the switch.

There is no AoR fallback.

### Switch to carrier

- Proxied, not B2BUA. The Request-URI is never changed (a digest `uri=` covers it). 401/407 challenges and the retried request pass through untouched: the switch holds the account.
- Toward the carrier only FreeSBC's public Via and Record-Route appear: no switch Via, Contact or Record-Route, and no foreign Route. The host of From, To, P-Asserted-Identity, P-Preferred-Identity, Remote-Party-ID, Diversion, Call-Info and Alert-Info is rewritten to `public.ip` when it is `private.ip` or an `edge.switch` node's IP; users, parameters and tags are kept. Call-ID passes through.
- REGISTER: the Contact is rewritten to `sip:<user>@public.ip:<port>;fsbc=<token>` and restored on the response. The token is derived deterministically from the switch node and its original Contact, so the Contact the carrier holds stays the same across a FreeSBC restart. The binding table is in memory: after a restart an inbound call that uses the token is treated as a DID call (hash-user, Request-URI unchanged) until the switch's next REGISTER refresh restores the binding. The binding lives for the expiry the carrier granted in the 200; a 200 to `Expires: 0` removes it.
- INVITE: media is anchored on both legs and FreeSBC constructs both SDPs. PRACK, UPDATE and delayed offers are carried the same way; see [Reliable provisionals, UPDATE and delayed offers](#reliable-provisionals-update-and-delayed-offers).
- A carrier is resolved on the public side: a DNS name without a port through SRV, then A/AAAA; a name with a port through A/AAAA only. The first address is used. The SRV name follows the carrier's transport: `_sip._udp`, `_sip._tcp` or, for `tls`, `_sips._tcp`; with no SRV record the port is 5060, or 5061 for `tls`.
- **Transport.** A carrier is UDP unless its `edge.carriers` entry says `transport: tcp` or `tls`. Toward a tcp or tls carrier FreeSBC opens the connection itself, reuses it for every request to that address and dials again when it is lost; the switch leg stays UDP. Via, Record-Route and Contact name the carrier transport (`SIP/2.0/TLS`, `;transport=tls`), so the switch and the carrier leg use the existing double Record-Route.
- **TLS to a carrier** verifies the certificate against the configured host name (the SIP domain, RFC 5922; not an SRV target) and sends it as SNI. `ca_file` replaces the system roots for that carrier; without it the system roots are used. `client_cert` and `client_key` (two PEM files) are presented for mutual TLS. The minimum is TLS 1.2 and a verification failure refuses the call (the switch gets 503): there is no switch to turn verification off.
- **Contact and listeners.** An outbound connection is also how a tcp or tls carrier reaches FreeSBC when no matching `edge.listen` entry exists: requests the carrier sends on it (a BYE, a new INVITE) are handled like any other. Via then carries `;alias` (RFC 5923) and names the transport's default port, and a carrier REGISTER's Contact names that port, so the carrier must reuse the connection. With `edge.listen.tls` (or `tcp`) FreeSBC advertises that port, and the carrier may also connect to it.

### Carrier to switch

- Admitted only from a carrier source; anything else that is not a registered client is dropped silently. A carrier's resolved address counts only on that carrier's transport: a `tls` carrier is admitted only on a TLS connection, whether FreeSBC opened it or the carrier made it to `edge.listen.tls`, and its address over UDP is not a carrier source. `edge.carrier_sources` addresses match by IP on any public transport. A carrier on `tcp` or `tls` needs the matching `edge.listen` entry for its own inbound connections; without one it can only send on the connection FreeSBC opened.
- Every carrier to switch request is sent to `<node IP>:<edge.switch_carrier_port>`, never to the client port.
- A Request-URI carrying an outbound-registration token goes to the node that registered, with the Request-URI restored to that node's original Contact (so Asterisk `line=yes` and FreeSWITCH `${sip_gateway}` identification work).
- With no token (the carrier addressed the DID) the request goes to a node chosen by the `hash-user` pool, Request-URI unchanged. An unknown or expired token is treated as no token.
- FreeSBC adds `X-FreeSBC-Carrier: <name>`. A request from a `carrier_sources` address that matches no entry by address gets `X-FreeSBC-Carrier: unknown`.

## Topology hiding on public legs

Every public leg is hidden, for clients and carriers alike ([design §6.6](design.md)). What a public party never sees:

- the switch's Via headers (it gets FreeSBC's public Via only; the switch gets its own Vias back on every response), `private.ip`, and `received=` for the private side;
- a switch or `private.ip` host in From, To, P-Asserted-Identity, P-Preferred-Identity, Remote-Party-ID, Diversion, History-Info, Referred-By, Refer-To, Call-Info, Alert-Info and Error-Info: the host becomes `public.ip` (user, parameters and tags stay), and the switch sees its original From and To in every response and in the in-dialog requests the party sends back;
- the switch's Contact, on any request or response (FreeSBC's public address replaces it; a REGISTER response keeps the client's own bindings);
- Record-Route and Route entries of the private side.

On a client leg only, every header outside an allowlist is also dropped, toward the client only (a client's own User-Agent or `X-` headers still reach the switch): Server, User-Agent, Warning, Organization, every `X-` header, every `P-` header except P-Asserted-Identity and P-Preferred-Identity, and Path, Service-Route and P-Associated-URI on a REGISTER 200. A carrier leg keeps the switch's other headers, because carriers use `P-Charge-Info` and account headers. A digest challenge passes verbatim, so use a domain name as the realm, not the switch's IP.

## Calls that end for a missing ACK

FreeSBC watches the ACK of every initial INVITE's 2xx. When the ACK does not
return, the callee gives up after 64·T1 (32 s) and BYEs a call that never
really started; FreeSBC reports it as `reason=ack_timeout` in the `call ended`
line (`terminated_by=callee` when the callee's BYE came first, `proxy` when
FreeSBC's own 32 s timer fired and BYEd both ends) and counts it in
`freesbc_edge_ack_missed_total{plane}`, where `plane` is the side whose ACK
was missing. It is not a normal hangup. The usual cause is that the ACK
cannot reach the address FreeSBC advertises in the 2xx Contact and
Record-Route: a firewall or NAT that drops or rewrites it, a UDP/TCP/TLS
mismatch, or an ALG. `plane="public"` means the endpoint's ACK did not reach
the public listener; `plane="private"` means the switch's ACK did not reach
`private.ip:5060`. FreeSBC logs a WARN with the address to check for the first
miss of each plane and at most once a minute after that, and the health
condition `ack_missed:<plane>` is raised at 3 misses within 10 minutes.
Re-INVITE ACKs are not watched. The symptom, the checks for each plane and the other ways a call drops are in [Troubleshooting](troubleshooting.md#a-call-connects-then-drops).

## Switch-side requirements

FreeSBC enforces an allowlist and rewrites addresses; the switch must be set up so that this is safe. Verified FreeSWITCH and Asterisk configurations that follow this list are in [`examples/switch/`](../examples/switch/README.md); this list stays normative.

- **Point every carrier gateway, endpoint and registration at FreeSBC as outbound proxy.**
  - FreeSWITCH, standard two-profile layout: the `internal` profile (5060, `auth-calls=true`) is the `edge.switch` port, for phones and browsers. The `external` profile (5080, `auth-calls=false`) is `edge.switch_carrier_port`; its gateways set `proxy=<carrier host[:port]>`, `outbound-proxy=<private.ip>:5060` and `register-proxy=<private.ip>:5060`. Without `register-proxy` the REGISTER goes straight to the carrier, around FreeSBC.
  - Asterisk: `outbound_proxy = sip:<private.ip>:5060\;lr` on the endpoint, aor and registration. `;lr` is required. The aor `contact` must equal the `edge.carriers` entry.
- **The `edge.carriers` entry must equal the host[:port] the switch puts in the Request-URI** (FreeSWITCH gateway `proxy`, Asterisk aor `contact`); that equality is what routes the request to a carrier.
- **Identify inbound carrier calls** by `X-FreeSBC-Carrier` (Asterisk `identify` with `match_header`, FreeSWITCH `${sip_h_X-FreeSBC-Carrier}`), by registration line (Asterisk `line=yes`, FreeSWITCH `${sip_gateway}`), or by DID.
  - FreeSWITCH: for a registered line `destination_number` is the gateway's `extension` (by default its username), not `gw+<name>`; match `${sip_gateway}` instead.
  - Asterisk applies `identify` and `acl` to the source address and headers, not to the transport a request arrived on, so the 5060/5080 split alone does not separate clients from carriers. `X-FreeSBC-Carrier` can be trusted only because FreeSBC strips `X-FreeSBC-*` from public input and only `private.ip` reaches the switch. Put `header` first in `endpoint_identifier_order`, with no `ip` and no `anonymous`.
  - Asterisk's `line=` token changes on every Asterisk restart; the carrier must accept the new Contact.
- **Never identify or trust a request by FreeSBC's IP on the client port.** Client calls also arrive from `private.ip`. In Asterisk, no `identify match=<private.ip>` and no `ip` in `endpoint_identifier_order`. In FreeSWITCH, no inbound ACL for `private.ip` on the `internal` profile. Otherwise client calls bypass digest authentication.
- Only the carrier port may skip authentication, because FreeSBC delivers nothing else there. Restrict it to `private.ip` so no other LAN host reaches it: FreeSWITCH `apply-inbound-acl` on the `external` profile gates INVITE only (OPTIONS, INFO, REFER, MESSAGE and others from other hosts are still answered), and Asterisk needs `acl` on the carrier endpoints, so also firewall the carrier port in both cases.
- **Subscriptions, transfers and messages are the switch's to accept and route.** A client's SUBSCRIBE (MWI, BLF), REFER and MESSAGE reach the switch from `private.ip` on the client port like its calls, and the switch authenticates and routes them by its own policy (for REFER, including where a `Refer-To` may point). The switch sends its NOTIFYs back with the dialog's own tags, to the Contact FreeSBC gave it, and addresses an unsolicited NOTIFY or MESSAGE to a client by the `fsbc=` token in its Request-URI.
- **Generate a host-free Call-ID, or accept that the switch's own name leaves with every call.** FreeSBC forwards the Call-ID unchanged ([Known limitations](#known-limitations)): putting a host into it would take a per-dialog alias map, which is a B2BUA's job and not this proxy's. FreeSWITCH and Asterisk with pjsip need no setting to get this right; Asterisk with the legacy chan_sip does leak, and no setting removes it.
  - FreeSWITCH: sofia's Call-ID is an opaque, host-free word. `outbound-use-uuid-as-callid` (off in the stock profile) only ties it to the channel UUID, so leaving it off is not a leak either way.
  - Asterisk 21 and later are pjsip-only, and a pjsip Call-ID is a bare random word with no host. The driver that leaks one is the legacy chan_sip: `build_callid_pvt` writes `<32 random hex>@<the peer's fromdomain, else the local address the switch uses toward it>` (`channels/chan_sip.c`), and that `@host` is a fixed part of the format, so `fromdomain` changes which name leaks rather than removing it. Upgrade off chan_sip (removed in Asterisk 21); nothing on the edge can take the host back out.
- **Give the switch the public name as its own domain, so the bodies it writes name FreeSBC and not the switch.** FreeSBC forwards a `message-summary`, `dialog-info`, pidf or sipfrag body, and the headers that carry it, exactly as the switch wrote it: a body naming `10.77.0.10`, the switch's hostname or a private FQDN hands the public party the address the edge exists to hide.
  - FreeSWITCH: the host in an MWI `Message-Account` is the domain the `voicemail` app was called with (the stock dialplan passes `${domain_name}`, that is `$${domain}`), and a sofia profile `domain` replaces it when one is set (`sofia_presence.c`). The host can therefore come from the user's directory domain or from the profile. Keep `$${domain}` at `public.ip` or the DNS name that points at it, as [`freesbc-vars.xml`](../examples/switch/freeswitch/freesbc-vars.xml) does, then capture an MWI NOTIFY (for example with sngrep) and confirm that `Message-Account` names FreeSBC's public name. A `dialog-info` body is `entity="sip:<user>@<host>"` for the entity the watcher subscribed to (`sip_subscriptions`), so a BLF key aimed at the public name keeps it there.
  - Asterisk: an MWI NOTIFY's `Message-Account` is built from that NOTIFY's own From URI, with the user replaced by the mailbox or the endpoint's `voicemail_extension` (`res_pjsip_mwi.c`), so the host in it is the endpoint's `from_domain`. Set `from_domain` to the public name: when it is unset the host falls back to an address of the switch's own, which leaks. A `dialog-info` body takes its domain from the subscription. Point `from_domain`, and the clients' BLF and hint targets, at the public name.
  - A MESSAGE body is whatever the sender or its application wrote. FreeSBC answers a MESSAGE body over 1300 bytes with 413 and relays a smaller one unread. That cap covers MESSAGE only: NOTIFY bodies (`message-summary`, `dialog-info`, pidf, sipfrag) have no size or content check and are relayed unchanged.
- **Switch-side address-based brute-force protection (fail2ban, IP bans) sees every client request as coming from `private.ip`** and would ban FreeSBC itself. Leave source banning to FreeSBC's shield.
- **Line selection and failover are the switch's job**: FreeSWITCH `bridge sofia/gateway/a/N|sofia/gateway/b/N`, Asterisk sequential `Dial` on `DIALSTATUS`. FreeSBC never retries a carrier request on another carrier.

### The private socket's ingress rule

On Linux the private socket installs a BPF receive filter: a datagram is delivered only when it arrived on the interface that owns `private.ip` (the kernel reads `skb->dev->ifindex`), or on loopback for a switch co-located with FreeSBC. This closes the weak-host path where a datagram addressed to `private.ip` and sent into the public NIC reached the trusted socket with a spoofed switch source (issue #90). The send path is untouched, so dialing and passive failover are unchanged.

- **Switch traffic must arrive on the interface that owns `private.ip`, or over loopback.** A datagram that arrives on another device — a VRF (the kernel rewrites the device to the VRF master while the address stays on the slave), asymmetric routing, or a tunnel (WireGuard/GRE, or `private.ip` on a dummy device) — is dropped silently and shows up only as upstream timeouts.
- **The interface is resolved once at startup.** Recreating the interface that owns `private.ip` (a new VLAN/bond/bridge ifindex) drops wire traffic until FreeSBC restarts.
- **The filter is Linux-only.** Elsewhere the private socket is unfiltered and strict `rp_filter=1` or a firewall rule dropping traffic to `private.ip` on the public interface remains the mitigation; loose `rp_filter=2` is not sufficient when the spoofed source is routable.

## UDP socket buffers

FreeSBC asks the kernel for a 4 MiB receive buffer and a 1 MiB send buffer on every UDP SIP socket (the public `edge.listen.udp` socket and the private `private.ip:5060` socket). The sizes are fixed, not configurable, and `rmem_default` need not be raised because the size is set explicitly. RTP sockets are not resized. The kernel caps the request at `net.core.rmem_max` and `net.core.wmem_max` (Linux) or `kern.ipc.maxsockbuf` (macOS), so raise them to at least 4 MiB and 1 MiB:

```sh
sysctl -w net.core.rmem_max=8388608 net.core.wmem_max=8388608
# persistent: /etc/sysctl.d/90-freesbc.conf
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
```

Apply it before FreeSBC starts (a running socket keeps the size it got). If the grant falls short FreeSBC still starts and logs one warning per socket, `udp socket receive buffer below request; datagrams may drop under bursts` (or `... send buffer below request`), with the address, `requested` and `effective` bytes. Without the larger buffer a burst or a GC pause overflows the socket and the kernel drops datagrams silently; the signal is the `RcvbufErrors` counter, `nstat -az UdpRcvbufErrors`, `freesbc_udp_receive_buffer_errors_total` on `/metrics` (Linux), or the `RcvbufErrors` column of the `Udp:` lines in `/proc/net/snmp`.

## Multiple switches (`edge.switch`)

`edge.switch` with one entry is a single upstream. With more than one it is a pool: the proxy picks a node per user. This is the OpenSIPS dispatcher's `hash-user` algorithm (alg 10), applied at the edge.

```yaml
edge:
  switch: [10.77.0.10:5060, 10.77.0.11:5060]
```

Selection is FNV-1a 64 over the **lower-cased** SIP user part, modulo the pool size. A user's REGISTER, its refresh, and the calls it places all start on the same node, and the other nodes see none of that traffic. The hash is a pure function of the user and the node list: every request the same caller causes recomputes the same answer, with no shared state. For an inbound carrier call with no registration token the user is the Request-URI user (the DID).

Once a call is up, **the dialog record beats the hash**. A call that node 2 placed to a phone (the phone's user may hash to node 1) is carried by node 2, and the phone's ACK and BYE return to node 2 because that is what the dialog record says. A dialog never migrates between switches mid-call. An ACK, BYE or INFO from a phone or carrier whose dialog is not on record falls back to re-hashing the caller's identity, which lands on the same node the INVITE went to, and the switch answers honestly. A public BYE or INFO with no dialog on record is forwarded this way only from a live registration's exact transport address or a carrier source; any other source is answered 481 at the edge (see Admission and abuse controls). A re-INVITE is the exception: it has to be re-anchored on the dialog's media, so without a record it is answered 481.

What the pool requires of the switch: a **shared registration database**. Registration digests are forwarded verbatim, so after a failover the new node re-challenges and the phone's answer is valid there too: one extra round trip, not a broken registration. The switches must also be interchangeable for calls: the proxy hashes to a switch, it does not choose a dialplan. A carrier registration and the calls delivered to it stay on the node that registered.

Failover is passive and transport-driven. A node that fails to accept the datagram (an unreachable route, a closed port that resets) is penalised for 30 s and retried only when no healthy alternative remains, never hard-blocked. On UDP a silent node is indistinguishable from a slow one, so a whole REGISTER attempt with zero responses is also penalised; the phone's own retry then skips that node. A node that leaves 3 REGISTER attempts in a row unanswered is not dialed for REGISTER at all for 30 s (then 1 m, then 5 m while it keeps failing); the phone gets `503` with `Retry-After: 30` from FreeSBC instead of waiting out the 32 s budget, and a pool still tries the other nodes first. After the window the next REGISTER is sent as a probe, and any response, a 401 included, closes the breaker. Watch `freesbc_edge_register_unanswered_total`, `freesbc_edge_register_breaker_rejects_total` and `/api/switch-nodes` (`cooling_down` while open). The breaker covers REGISTER only; INVITE keeps the 30 s reorder-only cooldown. Any final response, including a 401 challenge, is a real judgement and ends the attempt series; it is relayed, never retried on another node. Because the pool is modulo-hashed, a change in the node set reshuffles users between nodes; with a shared database that is a re-registration, not an outage.

## RTCP and call quality in HOMER

FreeSBC mirrors SIP to HOMER ([`homer.md`](homer.md)) but does not report RTCP (HEP type 5). The switch already sees the RTCP of every call in plain form, so a reporter on the switch covers both legs, and reporting it is not something only the edge can do (issue #134 is the scope rule; issue #129 was closed as won't-do).

**What reaches the switch.** FreeSBC anchors every stream and relays RTCP in both directions on the RTP+1 port of each leg. A browser (DTLS-SRTP) leg and an SDES-SRTP leg are decrypted from SRTCP before the switch leg and re-protected in the other direction, so the switch always receives plain RTCP. Compounds are relayed uninterpreted: no SSRC or report-block rewriting. The RTCP the switch reports comes from FreeSBC's `private.ip`, not from the public endpoint, and it is only as informative as the far end's own reports.

**Asterisk.** `res_hep` with `res_hep_rtcp` sends RTCP statistics to HOMER as HEP type 5. Set `uuid_type = call-id` in `hep.conf` so the RTCP correlates with the SIP mirrored from FreeSBC:

```ini
; hep.conf
[general]
enabled = yes
capture_address = 10.77.0.50:9060
uuid_type = call-id
```

Check the option names against the sample `hep.conf` of your Asterisk version.

**FreeSWITCH.** FreeSWITCH has no native HEP RTCP reporter. Run [heplify](https://github.com/sipcapture/heplify) on the switch host, on the interface facing FreeSBC (`any` also works, including in a container sharing the switch's network namespace). It reads the SDP in the private SIP and reports the RTCP on the announced ports, rtcp-mux or RTP+1, as HEP type 5 tagged with the Call-ID. FreeSWITCH sends no RTCP by default: turn it on per profile with the sofia parameter `rtcp-audio-interval-msec`, or per call with the `rtcp_audio_interval_msec` channel variable:

```xml
<!-- sofia profile -->
<param name="rtcp-audio-interval-msec" value="5000"/>
```

```
heplify -i <private-interface> -m SIPRTCP -hs 10.77.0.50:9060 -hi 42 -hn fs1
```

`-m SIPRTCP` (heplify's default mode) sends SIP and RTCP; `SIPRTP` reports the same RTCP. `-hi` and `-hn` name the node in HOMER; add `-nt tcp` if the collector takes HEP over TCP only. In SIPRTCP mode heplify's periodic stats may show `rtcp_fail` counts for rtcp-mux calls while the reports still arrive. The SIP heplify captures on the private side duplicates what FreeSBC already mirrors, so HOMER shows the private-side messages twice, once from each source.

Checked with FreeSWITCH 1.11.3, heplify 2.0.28 and HOMER 11: an SR from each end, in both directions, under the call's Call-ID, with rtcp-mux and with RTCP on RTP+1.

## Non-goals

- Business routing, dial plans, least-cost routing and number transformation: the switch's job.
- Holding credentials, registering to carriers on its own, or terminating digest authentication.
- A B2BUA: no leg-splitting, no Call-ID rewriting, no transcoding.
- SRV failover across targets, NAPTR, or carrier OPTIONS keep-alive of its own.
- RTCP reporting to HOMER: the switch does it, see [RTCP and call quality in HOMER](#rtcp-and-call-quality-in-homer).
- A kernel firewall integration, persistence, or clustering. State is in memory and lost on restart.
- PUBLISH, and any use of the proxy as a presence server: SUBSCRIBE is carried, but the presence logic stays on the switch.
- TURN and full ICE.

## SDES-SRTP on public legs

SDES (RFC 4568) keys SRTP with `a=crypto` lines carried in the SDP. FreeSBC can use it on the public leg of a call with a registered client (`edge.srtp`) or a carrier (the carrier's `srtp`). The default is `off`: `a=crypto` is ignored and the leg is plain RTP. A WebRTC leg (ws/wss) is always DTLS-SRTP and ignores `srtp`.

The public leg is SRTP/SRTCP on its usual media port pair; the switch leg is always plain `RTP/AVP`. FreeSBC decrypts what the public side sends and encrypts what it sends to it. There is no transcoding, and the switch sees plain RTP only.

**Suites.** `AES_CM_128_HMAC_SHA1_80`, `AES_CM_128_HMAC_SHA1_32` and `AEAD_AES_128_GCM`. FreeSBC generates its own master keys with `crypto/rand`; keys are never copied across legs. An answer must select exactly one of the lines offered (by tag and suite), and its key is the peer's.

**Insecure transports.** The keys travel in the SDP, so SDES is used only where the signaling is encrypted. A client leg qualifies when the client registered over TLS or WSS, decided per call by that registration transport. A carrier qualifies when its `transport` is `tls`, which `check` enforces for a non-`off` `srtp`. `edge.allow_insecure_sdes: true` lifts the rule for both.

| Policy | Behavior |
|---|---|
| `off` | `a=crypto` lines are ignored and the answer is plain, as before: an `RTP/SAVP` offer is answered `RTP/AVP`. |
| `optional` | FreeSBC offers `RTP/SAVP` with three lines (one per suite) to a public callee and accepts a plain `RTP/AVP` answer as plain. An `RTP/SAVP` offer is answered with SRTP and an `RTP/AVP` offer with plain RTP. An `RTP/SAVP` offer with no usable line is refused 488. On an insecure transport without `allow_insecure_sdes` the effective policy is `off`. |
| `required` | `RTP/SAVP` only. A plain offer is refused 488. If the callee answers our offer in plain RTP, the 2xx is ACKed and then BYEd and the other leg gets 488. On an insecure transport without `allow_insecure_sdes`, every offer and answer is refused 488: `required` is never silently downgraded. |

**Re-INVITE, UPDATE, PRACK and delayed offers** follow the same rules. The same `a=crypto` line again keeps the state (no re-key; the rollover counter and replay window are kept). A new key re-keys the leg in place, without changing ports or the latch. FreeSBC repeats its own key in its re-offers. An offer that would drop SRTP on an SRTP leg is refused 488 and the keys in force stay; the refusal is decided before anything is forwarded, and keys take effect only when the exchange does.

**Media.** There is no `a=rtcp-mux` on an SDES leg: RTCP stays on RTP+1. An SDES leg that does not yet have both keys drops packets in both directions (fail closed) rather than send or accept plaintext. A packet that fails authentication never latches the leg and never feeds the silence watchdog.

**The switch leg is plain RTP/AVP.** A switch offer or answer of `RTP/SAVP` (or `RTP/SAVPF`) is refused 488: an out-of-dialog offer with 488 to the switch (counted `media_failed`), an in-dialog re-offer with 488 and the call and keys unchanged, and an answer to our plain offer with the same ACK-then-BYE path as any unusable answer. Its `a=crypto` lines are never read, copied or logged.

**Keys are not logged.** The edge log handler and the sipgo logger rewrite `inline:<key>` to `inline:[redacted]` in every message and string attribute. Keys do not appear in admin output.

Known limitation: there is no automatic retry after a 488 to our `RTP/SAVP` offer under `optional`. An `RTP/SAVP` offer to a plain-only endpoint fails (RFC 3264), and the 488 is relayed as it is; set `srtp: off` for such a peer.

## Reliable provisionals, UPDATE and delayed offers

PRACK, UPDATE and an INVITE or re-INVITE without SDP work on client, switch and carrier legs, with the same guarantees as an ordinary INVITE: media anchored on SBC ports, every SDP built by FreeSBC, nothing of either side's SDP crossing.

- **`100rel`.** `Supported`, `Require`, `RSeq` and `RAck` pass unchanged, and `Allow` lists PRACK and UPDATE. FreeSBC never makes a provisional reliable itself. A PRACK is forwarded in the early or confirmed dialog its tags name; with no matching dialog it is answered 481.
- **UPDATE.** Without SDP (a session-timer refresh) it is forwarded and answered in either direction, early or confirmed. With SDP it is an offer, rebuilt like a re-INVITE's; its 2xx answer is rebuilt the same way and the media follows only a 2xx. A 488 or 491 from the far end leaves the session as it was. In an early dialog it works on the fork's media, and the later 18x and 2xx restate the answer it produced.
- **Glare.** An UPDATE offer is answered 491 by FreeSBC, and not forwarded, while another UPDATE or a re-INVITE offer is pending or an answer is owed (below); a re-INVITE is answered 491 while an UPDATE offer or an owed answer is pending. Crossing re-INVITEs are left to the endpoints.
- **Delayed offers.** An INVITE or re-INVITE without SDP is forwarded as it is. The offer is the callee's first SDP, in the 2xx or in a reliable 18x; FreeSBC relays it as its own offer and the caller's answer, in the ACK or the PRACK, as its own answer. No media is pointed or latched before the answer is applied.
- **Unreliable 18x with SDP in an offerless call is not an offer:** its body is removed before the 18x is relayed.
- **ACK bodies.** An ACK body is used only as the answer to an owed offer; any other ACK body is dropped. A retransmitted ACK (the first never reached the callee) is restated with the same answer. SDP in a response to a PRACK, UPDATE (other than the rebuilt answer to an UPDATE with SDP), INFO, NOTIFY or BYE is removed rather than relayed. An ACK cannot be refused: when the owed answer is missing, unparsable, without a common codec or renumbered, the ACK is forwarded without a body and both ends are sent a BYE.
- **Owed-answer backstop.** If the ACK that should carry the answer never arrives, the call is ended on both sides after 32 s (Timer H).

## Known limitations

These are structural rather than scheduled, except those that link an issue.

- **A locked AoR can be abused (`shield.register_ban_aor`).** An attacker can lock a legitimate AoR by failing on purpose from many IPs. The AoR's live bindings keep refreshing and a 2xx clears the count, but a new device, or a re-register after the binding expired, is silently dropped until the limit ends (`shield.ban`, default 1 h). This is accepted in exchange for stopping a distributed brute force; set `shield.register_ban_aor: "off"` if it bites.
- **A public call must come from a registered transport address or a carrier source.** An out-of-dialog INVITE on a public listener is relayed only when its transport, source IP and port match a live registration, or its source IP is a carrier source; anything else is dropped with no response. A device that calls without registering through FreeSBC, or that sends its INVITE from a different socket than its REGISTER (a NAT mapping that changed since the last refresh, a new WebSocket connection), is refused until it registers again from that address. Inbound carrier calls from addresses that are neither resolved carriers nor listed in `edge.carrier_sources` are dropped the same way (look for `invite_not_admitted` in `freesbc_edge_admission_drops_total`).
- **A datagram that misses the private socket's ingress rule is dropped silently.** On Linux, switch traffic that does not arrive on the interface owning `private.ip` (or loopback) is discarded in the kernel: no log, no metric, only upstream timeouts. VRF, asymmetric routing, tunnels and an interface recreated at runtime all hit this (see [The private socket's ingress rule](#the-private-sockets-ingress-rule)).
- **Topology hiding on public legs has two limits.** The digest realm in a 401/407 challenge passes verbatim, because the client's digest covers it: if the realm is the switch's IP address, the client sees it, so configure a domain name as the realm. A header value that names the switch outside a SIP URI (free text in `Subject` or a `Reason` text, an `X-` header's value on a carrier leg) is not rewritten. On a client leg every header outside the allowlist is dropped (Server, User-Agent, Warning, Organization, `X-`, `P-` other than the identity ones, Path, Service-Route, P-Associated-URI); a carrier leg keeps the switch's other headers, since carriers act on `P-Charge-Info` and account headers.
- **Call-ID passes through.** FreeSBC does not rewrite it, so a carrier or client sees the Call-ID the switch generated, host and all. FreeSWITCH and pjsip generate host-free ones; the legacy chan_sip driver appends its own name and has no setting that removes it. What the switch can do about it is under [Switch-side requirements](#switch-side-requirements).
- **NOTIFY and MESSAGE bodies are the switch's own text, forwarded byte for byte.** `Message-Account` in a `message-summary` NOTIFY, the `<dialog-info>` entity, a pidf body and the body of a MESSAGE are written by the switch, and any address the switch puts in them reaches the public party unchanged. FreeSBC cannot edit a body without becoming an endpoint of the dialog it belongs to; the settings that decide those names are the switch's ([Switch-side requirements](#switch-side-requirements)).
- **A switch 3xx redirect is not usable by a client.** Every Contact toward a client is FreeSBC's public address, a 3xx included, so a client cannot follow the redirect target the switch named.
- **The switch's own From and To are restored only when FreeSBC holds the record.** On the way to a public party the switch's host is rewritten to `public.ip`, and the party echoes that in its in-dialog requests. FreeSBC maps it back from the dialog or subscription record; a request that matches no record is forwarded as received, naming `public.ip`.
- **No failover across SRV targets inside FreeSBC.** A carrier name that resolves to several addresses uses the first; failover between carriers belongs to the switch. A DNS failure at startup is not fatal: FreeSBC logs it, retries, and keeps the last good answer when a refresh fails.
- **The REGISTER brute-force ban does not count everything.** A REGISTER the switch never answers is not counted: at the edge it is indistinguishable from a switch outage, and banning phones that keep retrying would prolong one. A source holding one valid credential can reset its count with a successful registration every few attempts. An attempt with a nonce FreeSBC did not relay to that source (a forged datagram, or a nonce learned elsewhere) is never counted, and after a FreeSBC restart nothing is counted until the switch challenges again. Credentials guessed against the switch from behind FreeSBC's private side are the switch's to police.
- **The carrier registration token is deterministic and can in principle be brute-forced.** It is derived from the switch node and its original Contact so that it survives a restart. An attacker who guessed a token could address a request to the registered Contact and so learn the switch's original Contact. This is accepted; keep carrier sources restricted and the switch's carrier port closed to everything else.
- **A call the switch places to a browser needs `edge.listen.ws` or `wss`.** A client registered over ws or wss is offered FreeSBC's own DTLS-SRTP offer (`UDP/TLS/RTP/SAVPF`, `a=ice-lite`, one host candidate at the public media address, FreeSBC's fingerprint, `a=rtcp-mux`, `a=setup:actpass`), and ICE/DTLS start when the browser answers. A browser answer that is not a DTLS-SRTP body with `a=rtcp-mux` is refused 488.
- **An answer that renumbers a payload type is refused (488).** RFC 3264 §6.1 says an answerer SHOULD reuse the offer's numbers; it does not require it. FreeSBC relays RTP without rewriting the payload-type byte, so an answer that moves an offered codec to a number the offer never gave it (`sdp.ErrRenumbered`) fails the call rather than being bridged.
- **A browser offer without `a=rtcp-mux` is refused (488).** The WebRTC leg is a single ICE component carrying RTP and RTCP together, and RFC 5761 §5.1.1 lets an answer say `a=rtcp-mux` only when the offer did. Every current browser offers it.
- **`a=fmtp` carries only allowlisted parameters.** Codec parameters cross legs re-rendered from a per-codec allowlist (opus, telephone-event events, and a few others); anything else in an fmtp line is dropped, so the far side uses the codec's defaults for it.
- **One media session per call.** Dialogs are identified by Call-ID and both tags, and each early dialog of a forking far end gets its own answer; the anchored media follows the fork that answered last and, once one sends a 2xx, that fork. A 2xx from a second fork after that is ACKed and BYEd rather than relayed: two confirmed dialogs would need two sessions, a B2BUA's problem.
- **Switches are UDP at literal addresses.** One or a pool, with per-user hashing and passive failover between pool members, but no SRV, no TCP/TLS toward the switch, and no failover to a switch outside the pool. Carriers may use UDP, TCP or TLS.
- **IPv6 is untested**, though the code paths are address-family agnostic.
- **PRACK with SDP is accepted only as the answer to a pending offer.** A PRACK that carries SDP when no offer of a reliable 18x is owed on its fork is refused 488, and so is one that arrives after the 2xx confirmed the dialog (the answer can still come in the ACK). An offer in a PRACK is not supported; use UPDATE.
- **SUBSCRIBE, REFER and MESSAGE are proxied; PUBLISH is answered 405.** A SUBSCRIBE (RFC 6665) from a registered client goes to the switch node hashed from the subscriber, with FreeSBC's own Contact and a Record-Route (the pair toward the switch, the public entry alone in the 2xx to the subscriber), so its NOTIFYs come back through the proxy; a SUBSCRIBE from the switch is delivered to the client its `fsbc=` token names (unknown token 404, a carrier destination 405). Without an `Event` header it is refused 489. FreeSBC keeps one small record per subscription and routes a NOTIFY or a refresh only when its Call-ID and both tags match a record, from either plane; a public NOTIFY, REFER or MESSAGE that names no dialog or subscription is answered 481 and never reaches the switch. A record is bound to the registration it was made under and ends with it (un-REGISTER, WebSocket close, expiry), on a terminated NOTIFY, on a 481, on any non-2xx final to the first SUBSCRIBE, or at its own deadline (the granted `Expires` plus 32 s; an hour if none was given). A NOTIFY or SUBSCRIBE that carries a subscription's tags from the wrong side (a client NOTIFYing its own subscription, the switch refreshing it) matches nothing and is answered 481. A binding removed while its SUBSCRIBE is being set up ends the record, and the requester gets 480 (public) or 404 (switch). Requests toward a client follow its NAT: a public subscriber's later requests update where its NOTIFYs go, and a switch-initiated subscription resolves the client's binding at send time. A 2xx that cannot confirm its record is still relayed (Debug log only). There are at most 32 records per registration and 20000 in all; a SUBSCRIBE over either cap gets 503 with `Retry-After: 30` before anything is forwarded, logged at WARN at most once per 30 s per cap. These two limits are code constants, not config keys, and a cap reject is not an admission drop. MWI (`message-summary`) and BLF (`dialog`) therefore work end to end when the switch accepts the subscription. Behind one NAT or WebSocket source shared by several registrations, the per-registration cap is charged to the binding whose user equals the From user, else the first live binding at that source, so it can be charged to another user's binding.
- **REFER is in-dialog only and is not interpreted.** It is forwarded unchanged, so `Refer-To`, `Referred-By` and `Replaces` reach the other end as written; the transfer target's call is that endpoint's own INVITE, admitted like any other, and the sipfrag NOTIFYs ride the call's dialog. A REFER with no To tag or no matching dialog is answered 481. A REFER on a carrier dialog is declined 603 and never forwarded, because its `Refer-To` would name an address behind the topology hiding; transfers on carrier calls stay on the switch. The switch must route a `Refer-To` target by its own policy: FreeSBC neither rewrites nor vets it.
- **MESSAGE (RFC 3428) is proxied with its body untouched, up to 1300 bytes.** A larger body (or `Content-Length`) is answered 413, so a registered client cannot push large payloads at the switch; the check follows admission, so an unregistered source still gets silence. A MESSAGE from the switch with no To tag is delivered to the client its token names (unknown token 404). A `Content-Length` longer than the body makes the message unparsable and it is dropped silently; a shorter one truncates the body to the declared length, which is what the cap sees. A Contact in a response (a 3xx) is rewritten to FreeSBC's side, out of dialog and in a call. Delivery of a public MESSAGE to another user is the switch's routing, as for any request from that user.
- **NOTIFY is proxied.** A NOTIFY on a subscription FreeSBC carried is forwarded along it; an in-dialog NOTIFY in either direction is forwarded whatever its `Event`, and the switch's in-dialog NOTIFY (BroadSoft `talk`/`hold`) reaches the client even on an early dialog, routed by the `fsbc=` token in its Request-URI. An out-of-dialog NOTIFY (no To tag) from the switch is forwarded when its Request-URI carries the token of a binding FreeSBC holds, and answered 404 otherwise; one from a client that names no subscription or dialog is answered 481. A NOTIFY from the switch whose tags match no dialog is not refused on that account: if its Call-ID names a dialog FreeSBC holds, it is forwarded to that dialog's client with its To header untouched, whatever its To and From tags (the newest such dialog when several share the Call-ID), and it is answered 481 only when no dialog with that Call-ID has a client side to send to. This is for FreeSWITCH's `uuid_phone_event` NOTIFY, whose To is copied from the `sip_full_to` channel variable and can carry another leg's tag; the first one per dialog is logged at WARN, later retries at Debug. It applies to NOTIFY from the switch only: BYE, INFO and ACK, and every NOTIFY from a client, still need tags that name the dialog.
- **SIP over UDP is sent above the RFC 3261 §18.1.1 size guidance.** A realistic switch INVITE plus the proxy's own headers clears 1300 bytes, and the RFC's remedy, switching to TCP, is not available when both the switch and the phone are UDP. FreeSBC raises the send ceiling to 8 KiB and relies on IP fragmentation, as production SIP elements do.
- **Stream connections are bounded by constants.** TCP, TLS, WS and WSS share a per-source cap (256), a global cap (10000; connections to and from carriers count against a separate 1024 cap), a 10 s TLS handshake / WebSocket upgrade, a 15 s bound on a started message (the slow-loris guard), a 60 s idle timeout (measured from the last SIP message, so CRLF or WebSocket ping keep-alives do not defer it) and 24 KiB per SIP message; none is a config key. The idle timeout never closes a connection with a live registration binding, a dialog routed to it, or a carrier source, so a registered phone whose refresh interval is longer than a minute keeps its connection. A phone that does not keep its flow alive with CRLF pings or REGISTER refreshes inside its NAT's TCP timeout loses it in the NAT and re-registers on a new connection, which replaces the binding. A binding made over a new connection with a different Call-ID than the old one (a phone that picks a new Call-ID per boot) coexists with the old one until that connection closes or the binding expires.
- **TCP and TLS are for registered clients only.** A call the switch places to such a client rides its registered connection; if the connection is gone the call fails 480 and nothing is dialed. Carriers have their own transport (`edge.carriers`), and the switch leg is always UDP. A request URI toward a TLS client carries `;transport=tls` rather than the `sips:` scheme, because a `sips:` URI would demand TLS on the switch leg too.

## Verification against a real FreeSWITCH

The suite includes an opt-in interop pass that runs against a live switch rather than a fake one, because the questions that decide whether this works in production are questions about sofia's behaviour:

```sh
FREESBC_FS_INTEROP=1 FREESBC_FS_ADDR=<fs-ip>:5060 FREESBC_FS_LOCAL=<this-host-ip> FREESBC_FS_USER=1000 FREESBC_FS_PASS=<password> go test ./internal/edge/ -run TestFreeSWITCH -v
```

It confirms that sofia accepts a proxied REGISTER and **preserves the `fsbc=` binding token** in the contact it stores (the whole inbound-call path depends on this), that a switch-originated call and its hangup both traverse the proxy, and that audio survives a round trip through the anchor into FreeSWITCH's `echo` application and back. The tests drive the switch through `/usr/local/freeswitch/bin/fs_cli`, so run them on the FreeSWITCH host.
