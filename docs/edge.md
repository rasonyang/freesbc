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

- **Public side**: SIP over UDP, WS and WSS on `public.bind`; RTP; WebRTC (ICE-Lite + DTLS-SRTP). Everything FreeSBC advertises there uses `public.ip`.
- **Private side**: one fixed UDP socket, `private.ip:5060`, for all SIP to and from the switch, plus plain RTP/RTCP.
- **All signaling and media stay anchored through FreeSBC.** In SDP, Contact and the Request-URI, the switch is never given a public client's address and a public client is never given the switch's. On client calls the Via stack is ordinary proxy behaviour: FreeSBC prepends its own Via and annotates the sender's with `received=`, so the switch does see the client's address there. On carrier legs nothing private crosses to the carrier (see [Carrier path](#carrier-path)).

It is a **proxy, not a B2BUA**: Call-ID, From/To tags and CSeq pass through, and FreeSBC stays on the path via RFC 5658 double Record-Route. The switch is the authoritative registrar and owns all call logic. REGISTER and its digest challenge are forwarded verbatim, and FreeSBC never holds a credential, for clients or for carriers. Carrier accounts, line selection and failover live on the switch; FreeSBC is its outbound proxy.

See [`freesbc.example.yaml`](../freesbc.example.yaml) for a complete annotated configuration.

## What it does

| Area | Behaviour |
|---|---|
| Transports | Public UDP / WS / WSS; private UDP. WS to UDP is real interworking, with the WebSocket connection bound to the registration. |
| Methods | REGISTER, INVITE, ACK, CANCEL, BYE, OPTIONS, INFO, NOTIFY. OPTIONS from the public side is answered locally rather than multiplied onto the switch. NOTIFY from the switch is forwarded whatever its `Event` (for example BroadSoft `talk`/`hold` remote call control), including on an early dialog. |
| REGISTER | Proxied verbatim, digest and all. The Contact is rewritten toward the switch (so inbound calls route back through FreeSBC, carrying an `fsbc=` token) and restored on the way back (so sip.js accepts the registration). The binding expiry follows the registrar's grant for this device's own Contact, not the client's request. A `Contact: *` un-REGISTER is forwarded as `*` and removes every binding of the AoR. |
| SDP | A typed subsystem over `pion/sdp/v3`, with no string manipulation. Bodies are **constructed**, never derived from the other leg, which is what makes the two address-leak guarantees structural. |
| Codecs | PCMU, PCMA, Opus and RFC 4733 telephone-event, passed through with the offerer's payload numbers. **No transcoding**: no common codec means a clean 488. |
| Media | Every stream anchored on an SBC port pair, on both sides. Symmetric RTP: the destination is seeded from SDP so audio flows immediately, then corrected by the first authenticated packet. A destination is never an unspecified, multicast, broadcast or link-local address, nor a loopback one unless the SBC's own media plane is on loopback. The public leg latches loosely (a hard-NAT phone may signal an unroutable address), but ranks sources: the exact SDP address beats the SDP or SIP source IP, which beats anything else, and a better-ranked source takes the latch back. An off-path source that sends first therefore holds the call's audio only until the phone's first packet; when the SDP address is the phone's SIP address, audio is not redirected to another port for 3 s. The private leg latches strictly on the switch's signalled IP. |
| WebRTC | ICE-Lite, DTLS, SRTP/SRTCP with RTCP-mux, built directly on `pion/ice`, `pion/dtls` and `pion/srtp` (no `PeerConnection`). The DTLS identity is a per-process self-signed certificate. The peer certificate is checked against the signalled `a=fingerprint` inside the DTLS handshake, so a mismatched peer never gets SRTP keys and no media is relayed for it. Both call directions: a browser's own offer is answered, and a call the switch places to a client registered over ws or wss gets FreeSBC's own DTLS-SRTP offer (`a=setup:actpass`), whose leg starts when the browser answers. Enabled by `edge.listen.ws` or `wss`. Manual real-browser test: [`docs/smoke/webrtc-dtls.md`](smoke/webrtc-dtls.md). |
| DTMF | RFC 4733 telephone-event traverses the relay untouched; SIP INFO is proxied as signaling. |
| re-INVITE | Hold, unhold, session-timer refresh and codec changes are renegotiated with the anchor intact: the body is rebuilt for the far side on the ports the session already holds, and a WebRTC leg keeps its ICE credentials, fingerprint and DTLS role, so media is never interrupted. A re-INVITE that moves either side's media address re-points the anchor to it once the 2xx completes the exchange; one whose 2xx cannot be anchored is ACKed and the call is ended on both sides. |
| Dialogs | Identified by Call-ID and both tags (RFC 3261 §12): only a BYE that names the dialog's tags, and that its far end accepts, ends it. The dialog is on record before its 2xx is relayed, so an immediate ACK always finds it; 2xx retransmissions are relayed until Timer M. |
| Lifecycle | Media is released deterministically on BYE (from either side), CANCEL, a failed final response, dialog teardown, media silence (5 minutes) and shutdown. A 2xx whose SDP cannot be anchored, one from a second fork, or one that races a CANCEL is ACKed and BYEd rather than left as a zombie dialog. When media silence from either end (or a DTLS fingerprint mismatch) ends a call, both endpoints are sent a BYE. A CANCEL is relayed without holding up the caller's 487, and an INVITE that outlives its 5-minute backstop is CANCELled and answered 408. |
| Abuse | See [Admission and abuse controls](#admission-and-abuse-controls). |

## Admission and abuse controls

- **Public out-of-dialog INVITE.** Admitted only from the exact transport address (transport + IP:port) of a live registration, or from a carrier source. Anything else is dropped with no response and never reaches the switch. A source that is both a live registration's exact address and a carrier source is treated as a registration.
- **Carrier sources** are the resolved addresses of every `edge.carriers` entry plus `edge.carrier_sources`. Carriers are limited by `shield.carrier_rate_limit` instead of `shield.rate_limit`, are never banned as scanners, and are exempt from the per-source cap on calls ringing out.
- **The switch is trusted by the local socket it reaches** (the private socket), never by its source address. A datagram from the switch's own address that reaches a public listener is an ordinary public datagram, shielded and subject to admission.
- **REGISTER enumeration.** A source whose REGISTERs the switch has rejected 403/404 for 10 distinct AoRs within 10 minutes has its further REGISTERs dropped silently until that window ends (per IPv4 address, per IPv6 /64; challenges 401/407 do not count). Both drops are counted in `freesbc_edge_admission_drops_total{reason}` and logged at WARN once per source IP, then at debug.
- **Shield.** A source the shield has banned gets no response at all: it is dropped before parsing, and its TCP/TLS/WS/WSS connection is closed. A scanner over UDP, whose source address can be forged, has only its source socket banned, for a minute.
- **Ringing cap.** One public IP may have at most 64 calls ringing out (media anchored, no answer yet) at once; one more is refused 503 before any port is allocated, since media is anchored before the switch has authenticated the caller. Carrier sources are exempt.
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
- A carrier is resolved on the public side: a DNS name without a port through SRV, then A/AAAA; a name with a port through A/AAAA only. The first address is used.

### Carrier to switch

- Admitted only from a carrier source; anything else that is not a registered client is dropped silently.
- Every carrier to switch request is sent to `<node IP>:<edge.switch_carrier_port>`, never to the client port.
- A Request-URI carrying an outbound-registration token goes to the node that registered, with the Request-URI restored to that node's original Contact (so Asterisk `line=yes` and FreeSWITCH `gw+<name>` identification work).
- With no token (the carrier addressed the DID) the request goes to a node chosen by the `hash-user` pool, Request-URI unchanged. An unknown or expired token is treated as no token.
- FreeSBC adds `X-FreeSBC-Carrier: <name>`. A request from a `carrier_sources` address that matches no entry by address gets `X-FreeSBC-Carrier: unknown`.

## Switch-side requirements

FreeSBC enforces an allowlist and rewrites addresses; the switch must be set up so that this is safe.

- **Point every carrier gateway, endpoint and registration at FreeSBC as outbound proxy.**
  - FreeSWITCH, standard two-profile layout: the `internal` profile (5060, `auth-calls=true`) is the `edge.switch` port, for phones and browsers. The `external` profile (5080, `auth-calls=false`) is `edge.switch_carrier_port`; its gateways set `outbound-proxy=<private.ip>:5060` and `proxy=<carrier host[:port]>`.
  - Asterisk: `outbound_proxy = sip:<private.ip>:5060\;lr` on the endpoint, aor and registration. `;lr` is required. The aor `contact` must equal the `edge.carriers` entry.
- **The `edge.carriers` entry must equal the host[:port] the switch puts in the Request-URI** (FreeSWITCH gateway `proxy`, Asterisk aor `contact`); that equality is what routes the request to a carrier.
- **Identify inbound carrier calls** by `X-FreeSBC-Carrier` (Asterisk `identify` with `match_header`, FreeSWITCH `${sip_h_X-FreeSBC-Carrier}`), by registration line (Asterisk `line=yes`, FreeSWITCH `gw+<name>`), or by DID.
- **Never identify or trust a request by FreeSBC's IP on the client port.** Client calls also arrive from `private.ip`. In Asterisk, no `identify match=<private.ip>` and no `ip` in `endpoint_identifier_order`. In FreeSWITCH, no inbound ACL for `private.ip` on the `internal` profile. Otherwise client calls bypass digest authentication.
- Only the carrier port may skip authentication, because FreeSBC delivers nothing else there. Restrict it to `private.ip` (FreeSWITCH `external` profile `apply-inbound-acl`, or a host firewall) so no other LAN host reaches it.
- **Line selection and failover are the switch's job**: FreeSWITCH `bridge sofia/gateway/a/N|sofia/gateway/b/N`, Asterisk sequential `Dial` on `DIALSTATUS`. FreeSBC never retries a carrier request on another carrier.

### The private socket's ingress rule

On Linux the private socket installs a BPF receive filter: a datagram is delivered only when it arrived on the interface that owns `private.ip` (the kernel reads `skb->dev->ifindex`), or on loopback for a switch co-located with FreeSBC. This closes the weak-host path where a datagram addressed to `private.ip` and sent into the public NIC reached the trusted socket with a spoofed switch source (issue #90). The send path is untouched, so dialing and passive failover are unchanged.

- **Switch traffic must arrive on the interface that owns `private.ip`, or over loopback.** A datagram that arrives on another device — a VRF (the kernel rewrites the device to the VRF master while the address stays on the slave), asymmetric routing, or a tunnel (WireGuard/GRE, or `private.ip` on a dummy device) — is dropped silently and shows up only as upstream timeouts.
- **The interface is resolved once at startup.** Recreating the interface that owns `private.ip` (a new VLAN/bond/bridge ifindex) drops wire traffic until FreeSBC restarts.
- **The filter is Linux-only.** Elsewhere the private socket is unfiltered and strict `rp_filter=1` or a firewall rule dropping traffic to `private.ip` on the public interface remains the mitigation; loose `rp_filter=2` is not sufficient when the spoofed source is routable.

## Multiple switches (`edge.switch`)

`edge.switch` with one entry is a single upstream. With more than one it is a pool: the proxy picks a node per user. This is the OpenSIPS dispatcher's `hash-user` algorithm (alg 10), applied at the edge.

```yaml
edge:
  switch: [10.77.0.10:5060, 10.77.0.11:5060]
```

Selection is FNV-1a 64 over the **lower-cased** SIP user part, modulo the pool size. A user's REGISTER, its refresh, and the calls it places all start on the same node, and the other nodes see none of that traffic. The hash is a pure function of the user and the node list: every request the same caller causes recomputes the same answer, with no shared state. For an inbound carrier call with no registration token the user is the Request-URI user (the DID).

Once a call is up, **the dialog record beats the hash**. A call that node 2 placed to a phone (the phone's user may hash to node 1) is carried by node 2, and the phone's ACK and BYE return to node 2 because that is what the dialog record says. A dialog never migrates between switches mid-call. An ACK, BYE or INFO from a phone whose dialog is not on record falls back to re-hashing the caller's identity, which lands on the same node the INVITE went to; the proxy never answers it 481 for lack of a record, and the switch answers honestly. A re-INVITE is the exception: it has to be re-anchored on the dialog's media, so without a record it is answered 481.

What the pool requires of the switch: a **shared registration database**. Registration digests are forwarded verbatim, so after a failover the new node re-challenges and the phone's answer is valid there too: one extra round trip, not a broken registration. The switches must also be interchangeable for calls: the proxy hashes to a switch, it does not choose a dialplan. A carrier registration and the calls delivered to it stay on the node that registered.

Failover is passive and transport-driven. A node that fails to accept the datagram (an unreachable route, a closed port that resets) is penalised for 30 s and retried only when no healthy alternative remains, never hard-blocked. On UDP a silent node is indistinguishable from a slow one, so a whole REGISTER attempt with zero responses is also penalised; the phone's own retry then skips that node. Any final response, including a 401 challenge, is a real judgement and ends the attempt series; it is relayed, never retried on another node. Because the pool is modulo-hashed, a change in the node set reshuffles users between nodes; with a shared database that is a re-registration, not an outage.

## Non-goals

- Business routing, dial plans, least-cost routing and number transformation: the switch's job.
- Holding credentials, registering to carriers on its own, or terminating digest authentication.
- A B2BUA: no leg-splitting, no Call-ID rewriting, no transcoding.
- Carrier TCP/TLS, SRV failover across targets, or carrier OPTIONS keep-alive of its own.
- A kernel firewall integration, persistence, or clustering. State is in memory and lost on restart.
- TURN and full ICE.

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

These are structural rather than scheduled.

- **A public call must come from a registered transport address or a carrier source.** An out-of-dialog INVITE on a public listener is relayed only when its transport, source IP and port match a live registration, or its source IP is a carrier source; anything else is dropped with no response. A device that calls without registering through FreeSBC, or that sends its INVITE from a different socket than its REGISTER (a NAT mapping that changed since the last refresh, a new WebSocket connection), is refused until it registers again from that address. Inbound carrier calls from addresses that are neither resolved carriers nor listed in `edge.carrier_sources` are dropped the same way (look for `invite_not_admitted` in `freesbc_edge_admission_drops_total`).
- **A datagram that misses the private socket's ingress rule is dropped silently.** On Linux, switch traffic that does not arrive on the interface owning `private.ip` (or loopback) is discarded in the kernel: no log, no metric, only upstream timeouts. VRF, asymmetric routing, tunnels and an interface recreated at runtime all hit this (see [The private socket's ingress rule](#the-private-sockets-ingress-rule)).
- **Call-ID passes through.** FreeSBC does not rewrite it, so a carrier sees the Call-ID the switch generated.
- **Carrier-originated in-dialog requests carry the masked public host in From and To.** On the way to the carrier the switch's host is rewritten to `public.ip`; a request the carrier sends back in the dialog therefore names that host, and the switch sees it as is.
- **No failover across SRV targets inside FreeSBC.** A carrier name that resolves to several addresses uses the first; failover between carriers belongs to the switch. A DNS failure at startup is not fatal: FreeSBC logs it, retries, and keeps the last good answer when a refresh fails.
- **The carrier registration token is deterministic and can in principle be brute-forced.** It is derived from the switch node and its original Contact so that it survives a restart. An attacker who guessed a token could address a request to the registered Contact and so learn the switch's original Contact. This is accepted; keep carrier sources restricted and the switch's carrier port closed to everything else.
- **A call the switch places to a browser needs `edge.listen.ws` or `wss`.** A client registered over ws or wss is offered FreeSBC's own DTLS-SRTP offer (`UDP/TLS/RTP/SAVPF`, `a=ice-lite`, one host candidate at the public media address, FreeSBC's fingerprint, `a=rtcp-mux`, `a=setup:actpass`), and ICE/DTLS start when the browser answers. A browser answer that is not a DTLS-SRTP body with `a=rtcp-mux` is refused 488.
- **An answer that renumbers a payload type is refused (488).** RFC 3264 §6.1 says an answerer SHOULD reuse the offer's numbers; it does not require it. FreeSBC relays RTP without rewriting the payload-type byte, so an answer that moves an offered codec to a number the offer never gave it (`sdp.ErrRenumbered`) fails the call rather than being bridged.
- **A browser offer without `a=rtcp-mux` is refused (488).** The WebRTC leg is a single ICE component carrying RTP and RTCP together, and RFC 5761 §5.1.1 lets an answer say `a=rtcp-mux` only when the offer did. Every current browser offers it.
- **`a=fmtp` carries only allowlisted parameters.** Codec parameters cross legs re-rendered from a per-codec allowlist (opus, telephone-event events, and a few others); anything else in an fmtp line is dropped, so the far side uses the codec's defaults for it.
- **One media session per call.** Dialogs are identified by Call-ID and both tags, and each early dialog of a forking far end gets its own answer; the anchored media follows the fork that answered last and, once one sends a 2xx, that fork. A 2xx from a second fork after that is ACKed and BYEd rather than relayed: two confirmed dialogs would need two sessions, a B2BUA's problem.
- **Switches are UDP at literal addresses.** One or a pool, with per-user hashing and passive failover between pool members, but no SRV, no TCP/TLS toward the switch, and no failover to a switch outside the pool. Carriers are UDP only.
- **IPv6 is untested**, though the code paths are address-family agnostic.
- **PRACK with SDP is accepted only as the answer to a pending offer.** A PRACK that carries SDP when no offer of a reliable 18x is owed on its fork is refused 488, and so is one that arrives after the 2xx confirmed the dialog (the answer can still come in the ACK). An offer in a PRACK is not supported; use UPDATE.
- **SUBSCRIBE (and MESSAGE, REFER, PUBLISH) is answered 405, not proxied.** NOTIFY is proxied: an in-dialog NOTIFY in either direction is forwarded whatever its `Event`, and the switch's in-dialog NOTIFY (BroadSoft `talk`/`hold`) reaches the client even on an early dialog, routed by the `fsbc=` token in its Request-URI. An out-of-dialog NOTIFY (no To tag) from the switch is forwarded when its Request-URI carries the token of a binding FreeSBC holds, and answered 404 otherwise; one from a client is answered 481. A NOTIFY from the switch whose tags match no dialog is not refused on that account: if its Call-ID names a dialog FreeSBC holds, it is forwarded to that dialog's client with its To header untouched, whatever its To and From tags (the newest such dialog when several share the Call-ID), and it is answered 481 only when no dialog with that Call-ID has a client side to send to. This is for FreeSWITCH's `uuid_phone_event` NOTIFY, whose To is copied from the `sip_full_to` channel variable and can carry another leg's tag; the first one per dialog is logged at WARN, later retries at Debug. It applies to NOTIFY from the switch only: BYE, INFO and ACK, and every NOTIFY from a client, still need tags that name the dialog. Message-waiting NOTIFY (`Event: message-summary`) is therefore forwarded to the phone, but MWI still does not work end to end, and BLF not at all, because the client's SUBSCRIBE is answered 405.
- **SIP over UDP is sent above the RFC 3261 §18.1.1 size guidance.** A realistic switch INVITE plus the proxy's own headers clears 1300 bytes, and the RFC's remedy, switching to TCP, is not available when both the switch and the phone are UDP. FreeSBC raises the send ceiling to 8 KiB and relies on IP fragmentation, as production SIP elements do.
- **WS/WSS listeners have no connection cap and no idle timeout.**

## Verification against a real FreeSWITCH

The suite includes an opt-in interop pass that runs against a live switch rather than a fake one, because the questions that decide whether this works in production are questions about sofia's behaviour:

```sh
FREESBC_FS_INTEROP=1 FREESBC_FS_ADDR=<fs-ip>:5060 FREESBC_FS_LOCAL=<this-host-ip> FREESBC_FS_USER=1000 FREESBC_FS_PASS=<password> go test ./internal/edge/ -run TestFreeSWITCH -v
```

It confirms that sofia accepts a proxied REGISTER and **preserves the `fsbc=` binding token** in the contact it stores (the whole inbound-call path depends on this), that a switch-originated call and its hangup both traverse the proxy, and that audio survives a round trip through the anchor into FreeSWITCH's `echo` application and back. The tests drive the switch through `/usr/local/freeswitch/bin/fs_cli`, so run them on the FreeSWITCH host.
