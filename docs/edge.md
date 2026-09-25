# Edge proxy plane (SIP / RTP / WebRTC)

The edge plane is a stateful SIP and media edge proxy that provides SIP
registration proxying, UDP/WebSocket transport interworking, RTP anchoring,
WebRTC-to-RTP media relay, and peer-to-peer PSTN trunking for FreeSWITCH.
It is configured with `network:`, `sip.public/private`, `sip.upstream` (or
`sip.upstreams` for a pool), an optional `sip.pstn`, `rtp.public/private`
and `webrtc:`. It is enabled independently of the [trunk
plane](trunk.md) — either or both may run in one process.

See the [README](../README.md) for the project overview and the [design
doc](design.md) for the implemented behaviour in detail.

FreeSBC sits on the network boundary in front of FreeSWITCH:

```text
                     Public Internet
                           │
          ┌────────────────┴────────────────┐
          │                                 │
    SIP Phone                         Browser / sip.js
    SIP/UDP + RTP                     SIP/WSS + WebRTC
          │                                 │
          └──────────────┐   ┌──────────────┘
                         ▼   ▼
                    ┌────────────┐
                    │  FreeSBC   │
                    │ SIP Proxy  │
                    │ RTP Proxy  │
                    │ WebRTC GW  │
                    └─────┬──────┘
                          │ Private LAN/VPN
                          │ SIP/UDP + RTP
                          ▼
                    FreeSWITCH
```

- **Public side**: SIP over UDP, WS and WSS; RTP; WebRTC (ICE-Lite +
  DTLS-SRTP).
- **Private side**: SIP over UDP and plain RTP/RTCP to FreeSWITCH.
- **All signaling and media stay anchored through FreeSBC.** In SDP, in
  Contact and in the Request-URI, FreeSWITCH is never given a public
  endpoint's address and a public client is never given FreeSWITCH's. The
  Via stack is ordinary proxy behaviour, not hidden: FreeSBC prepends its
  own Via and annotates the sender's with `received=`, so FreeSWITCH does
  see the public client's address there. From and To pass through
  untouched, by design.

It is a **proxy, not a B2BUA**: Call-ID, From/To tags and CSeq pass through
untouched, and FreeSBC stays on the path via RFC 5658 double Record-Route.
FreeSWITCH remains the authoritative registrar — REGISTER and its digest
challenge are forwarded verbatim, and FreeSBC never holds a credential.

See [`edge.example.yaml`](../edge.example.yaml) for a complete annotated
configuration, and the "Edge proxy plane" section of
[`sbc.example.yaml`](../sbc.example.yaml) for running it alongside trunks.

## What it does

| Area | Behaviour |
|---|---|
| Transports | Public UDP / WS / WSS; upstream UDP. WS↔UDP is real interworking, with the WebSocket connection bound to the registration. |
| Methods | REGISTER, INVITE, ACK, CANCEL, BYE, OPTIONS, INFO. OPTIONS is answered locally rather than multiplied onto FreeSWITCH. |
| REGISTER | Proxied verbatim, digest and all. The Contact is rewritten toward FreeSWITCH (so inbound calls route back through the SBC) and restored on the way back (so sip.js accepts the registration). The binding expiry follows the registrar's grant for this device's own Contact, not the client's request. A `Contact: *` un-REGISTER is forwarded as `*` and removes every binding of the AoR. |
| SDP | A typed subsystem over `pion/sdp/v3` — no string manipulation. Bodies are **constructed**, never derived from the other leg, which is what makes the two address-leak guarantees structural. |
| Codecs | PCMU, PCMA, Opus and RFC 4733 telephone-event, passed through with the offerer's payload numbers. **No transcoding**: no common codec means a clean 488. |
| Media | Every stream anchored on an SBC port pair. Symmetric RTP: on this (edge) plane the destination is seeded from SDP so audio flows immediately, then corrected by the first authenticated packet; the trunk plane seeds only the answering side (from its answer), so media toward the caller flows once the caller sends. A destination is never an unspecified, multicast, broadcast or link-local address, nor a loopback one unless the SBC's own media plane is on loopback. The public leg latches loosely (a hard-NAT phone may signal an unroutable address), but ranks sources: the exact SDP address beats the SDP or SIP source IP, which beats anything else, and a better-ranked source takes the latch back. An off-path source that sends first therefore holds the call's audio only until the phone's first packet; when the SDP address is the phone's SIP address, audio is not redirected to another port for 3 s. The private leg latches strictly on FreeSWITCH's signalled IP. |
| WebRTC | ICE-Lite → DTLS → SRTP/SRTCP with RTCP-mux, built directly on `pion/ice`, `pion/dtls` and `pion/srtp` — no `PeerConnection`. The peer certificate is checked against the signalled `a=fingerprint` inside the DTLS handshake, so a mismatched peer never gets SRTP keys and no media is relayed for it. Manual real-browser test: [`docs/smoke/webrtc-dtls.md`](smoke/webrtc-dtls.md). |
| DTMF | RFC 4733 telephone-event traverses the relay untouched; SIP INFO is proxied as signaling. |
| re-INVITE | Hold, unhold, session-timer refresh and codec changes are renegotiated with the anchor intact: the body is rebuilt for the far side on the ports the session already holds, and a WebRTC leg keeps its ICE credentials, fingerprint and DTLS role — in answers to the browser and in re-offers FreeSWITCH makes to it — so media is never interrupted. A re-INVITE that moves either side's media address re-points the anchor to it once the 2xx completes the exchange; one whose 2xx cannot be anchored is ACKed and the call is ended on both sides. |
| Dialogs | Identified by Call-ID and both tags (RFC 3261 §12): only a BYE that names the dialog's tags, and that its far end accepts, ends it. The dialog is on record before its 2xx is relayed, so an immediate ACK always finds it; 2xx retransmissions are relayed until Timer M. |
| Lifecycle | Media is released deterministically on BYE (from either side), CANCEL, a failed final response, dialog teardown, media silence, and shutdown. A 2xx whose SDP cannot be anchored — or one from a second fork, or one that races a CANCEL — is ACKed and BYEd rather than left as a zombie dialog. When media silence from either end (or a DTLS fingerprint mismatch) ends a call, both endpoints are sent a BYE. A CANCEL is relayed without holding up the caller's 487, and an INVITE that outlives its 5-minute backstop is CANCELled and answered 408; a client that never answers FreeSWITCH is answered 408/480 for it. |
| Abuse | A source the shield has banned gets no response at all — it is dropped before parsing, so even what the SIP stack would answer on its own stays silent, and its TCP/TLS/WS/WSS connection is closed. A scanner over UDP, whose source address can be forged, has only its source socket banned, for a minute. Trunk peers get no exemption on this plane. One public IP may have at most 64 calls ringing out (media anchored, no answer yet) at once; one more is refused 503 before any port is allocated, since media is anchored before FreeSWITCH has authenticated the caller. A handler panic is contained, counted (`freesbc_sip_handler_panics_total`), and answered 500 only if no final response went out. |

## PSTN trunk

An optional peer-to-peer outbound trunk: a carrier gateway that never
registers (and is never pinged) can be reached by FreeSWITCH bridging
calls to it through the proxy, so PSTN numbers dial from the same
FreeSWITCH the phones register to:

```text
FreeSWITCH ──bridge──▶ FreeSBC public UDP ──▶ PSTN carrier gateway
```

Configure `sip.pstn`: either the single-gateway shorthand (`address` =
the gateway) or the multi-gateway form (`gateways` = named carriers,
`routes` = called-number patterns selecting which gateways a call fails
over across, in `to:` order; a number no route matches is refused 503).
`match` is the address FreeSWITCH's dialplan dials PSTN prefixes to in
both forms. A bridged call is
classified by its source (FreeSWITCH itself) **and** its Request-URI
naming the match, then forwarded exactly like a call to a registered
client: media anchored on both legs, each side offered only the SBC's own
port, and in-dialog requests routed by Record-Route in both directions.
A phone dialling the match address from the public side is unaffected —
the source check fails and the call is proxied upstream as usual.

```yaml
sip:
  pstn:
    match: 10.77.0.2:16060
    # attempt_timeout: 32s     # per-gateway attempt budget (default 32s)
    # cooldown: 30s            # passive health penalty window (default 30s)
    gateways:
      gw-mobile: { address: 223.76.90.4:16060 }   # transport: udp implied
      gw-fixed:   { address: 223.76.90.5:16060 }
    routes:                  # first match wins; multiple catch-alls legal
      - match: "^1[3-9]\\d{9}$"  # Go regexp on the called number
        to: [gw-mobile]
      - to: [gw-fixed, gw-mobile]  # no match = catch-all
```

Failover: a call retries the next gateway on a transport error, a silent
gateway (attempt budget expiry — the current attempt is CANCELled first),
a 5xx/408, or an unanchorable answer; a 4xx like 486, an auth challenge or
a 6xx (a global failure, e.g. 603 Decline) is relayed to FreeSWITCH
immediately, never retried. When every gateway
fails, FreeSWITCH sees 488 if an answer could not be anchored, else the
last genuine carrier code, else 408, else 503.
Health is passive cooldown: a gateway that answered nothing before its
budget expired is penalized for `cooldown` and dialed only when no
healthy alternative remains (never a hard block); a successful call
recovers it.
`attempt_timeout` and `cooldown` hot-reload for the next call; the
gateways, routes and `match` are read once at startup. A reload that
removes `sip.pstn` leaves the running gateways in place, under the budgets
they started with.

On the FreeSWITCH side (no gateway definition needed — this is a plain
peer-to-peer bridge):

```xml
<action application="bridge"
        data="sofia/internal/sip:${destination_number}@10.77.0.2:16060"/>
```

Inbound carrier→FreeSWITCH calls need no trunk configuration: they arrive
on the public side like any other unregistered caller and are proxied
upstream unchanged. Note that they are also subject to the same
[`shield`](trunk.md#configuration) rate limiting as any unregistered source — a
chatty carrier can be throttled like an attacker; raise its budget if
needed.

## Multiple FreeSWITCHes (`sip.upstreams`)

The single-upstream shorthand (`sip.upstream.address`) is also available as
a pool: `sip.upstreams.nodes` names two or more switches and the proxy
picks one per user. This is the OpenSIPS dispatcher's `hash-user`
algorithm (alg 10) — the same placement rule, applied at the edge.

```yaml
sip:
  # upstream: { address: 10.77.0.10:5060 }   # the v1 shorthand; XOR with nodes
  upstreams:
    algorithm: hash-user     # the only value; the field is reserved for others
    cooldown: 30s            # passive health penalty window (default 30s)
    nodes:
      fs-1: { address: 10.77.0.10:5060 }   # literal IP:port; transport: udp implied
      fs-2: { address: 10.77.0.11:5060 }
```

Selection is FNV-1a 64 over the **lower-cased** SIP user part, modulo the
pool size. A user's REGISTER, its refresh, and the calls it places all
start on the same node, and the other nodes see none of that traffic. The
hash is a pure function of the user and the sorted node set: every request
the same caller causes recomputes the same answer, with no shared state.

Once a call is up, **the dialog record beats the hash**. A call that fs-2
placed to a phone (the phone's user may hash to fs-1) is carried by fs-2,
and the phone's ACK and BYE return to fs-2 because that is what the dialog
record says — a dialog never migrates between switches mid-call. A record
that is missing (an ACK racing the 2xx commit, or an evicted dialog) falls
back to re-hashing the caller's identity, which lands on the same node the
INVITE went to; it never answers 481 for lack of a record.

What the pool requires of FreeSWITCH: a **shared registration database**
(same `odbc-db`/`sofia` profile view on every node). Registration digests
are forwarded verbatim, so after a failover the new node re-challenges and
the phone's answer is valid there too — one extra round trip, not a broken
registration. The switches must also be interchangeable for calls: the
proxy hashes to a switch, it does not choose a dialplan.

Failover is passive and transport-driven. A node that fails to accept the
datagram (an unreachable route, a closed port that resets) is penalized for
`cooldown` and retried only when no healthy alternative remains — never
hard-blocked. On UDP a silent node is indistinguishable from a slow one, so
a whole REGISTER attempt with zero responses is also penalized; the phone's
own retry then skips that node. Any final response — including a 401
challenge — is a real judgement and ends the attempt series; it is relayed,
never retried on another node. Because the nodes are named and the pool is
modulo-hashed, a change in the node set reshuffles users between nodes
(follow-up: consistent hashing); with a shared database that is a
re-registration, not an outage.

## Known limitations

These are structural rather than scheduled.

- **An inbound call to a browser is offered plain RTP**, which a browser will
  reject: FreeSBC cannot make a DTLS-SRTP *offer*, because a WebRTC offer
  needs the answerer's fingerprint and ICE credentials and an offer by
  definition has not seen them. FreeSWITCH-originated calls therefore reach
  SIP/UDP phones, not WebRTC clients. Browser-originated calls are
  unaffected.
- **Offerless INVITE is refused (488)** in both directions.
- **An answer that renumbers a payload type is refused (488).** RFC 3264
  §6.1 says an answerer SHOULD reuse the offer's numbers; it does not
  require it. FreeSBC relays RTP without rewriting the payload-type byte, so
  an answer that moves an offered codec to a number the offer never gave it
  (`sdp.ErrRenumbered`) fails the call rather than being bridged.
- **A browser offer without `a=rtcp-mux` is refused (488).** The WebRTC leg
  is a single ICE component carrying RTP and RTCP together, and RFC 5761
  §5.1.1 lets an answer say `a=rtcp-mux` only when the offer did. Every
  current browser offers it.
- **`a=fmtp` carries only allowlisted parameters.** Codec parameters cross
  legs re-rendered from a per-codec allowlist (opus, telephone-event events,
  and a few others); anything else in an fmtp line is dropped, so the far
  side uses the codec's defaults for it.
- **One media session per call.** Dialogs are identified by Call-ID and both
  tags, and each early dialog of a forking far end gets its own answer; the
  anchored media follows the fork that answered last and, once one sends a
  2xx, that fork. A 2xx from a second fork after that is ACKed and BYEd
  rather than relayed — two confirmed dialogs would need two sessions, a
  B2BUA's problem, not a proxy's.
- **Upstreams are UDP FreeSWITCHes at literal addresses.** One or a pool
  (`sip.upstreams`), with per-user hashing and passive failover between
  pool members — but no SRV, no TCP/TLS upstream, and no failover to a
  switch outside the pool.
- **IPv6 is untested** on the proxy plane, though the code paths are
  address-family agnostic.
- **No TURN and no full ICE.** FreeSBC is ICE-Lite and needs a publicly
  reachable media address; a client that can only reach it via a relay is
  out of scope.
- **PRACK and UPDATE are answered 405, not proxied**, so FreeSBC never
  lets either end advertise them: it removes `PRACK`, `UPDATE` (and every
  other method it does not proxy) from `Allow` and `100rel` from
  `Supported` on everything it forwards or relays, and answers an INVITE
  with `Require: 100rel` with `420 Bad Extension`. Provisional responses
  are therefore never reliable, and session timers (`Supported: timer`
  still passes) are refreshed with re-INVITE.
- **SUBSCRIBE/NOTIFY (and MESSAGE, REFER, PUBLISH) are answered
  405, not proxied.** FreeSWITCH sends a NOTIFY for message-waiting
  indication after a registration; MWI and BLF therefore do not reach
  phones through the proxy. The event framework is
  not implemented.
- **SIP over UDP is sent above the RFC 3261 §18.1.1 size guidance.** A
  realistic FreeSWITCH INVITE plus the proxy's own headers clears 1300
  bytes, and the RFC's remedy — switch to TCP — is not available when both
  the upstream and the phone are UDP. FreeSBC raises the send ceiling to
  8 KiB and relies on IP fragmentation, as production SIP elements do.
- **WS/WSS listeners have no connection cap and no idle timeout.** The
  trunk plane's TCP/TLS listener limits do not apply to them.

## Verification against a real FreeSWITCH

The suite includes an opt-in interop pass that runs against a live switch
rather than a fake one, because the questions that decide whether this works
in production are questions about sofia's behaviour:

```sh
FREESBC_FS_INTEROP=1 FREESBC_FS_ADDR=<fs-ip>:5060 FREESBC_FS_LOCAL=<this-host-ip> FREESBC_FS_USER=1000 FREESBC_FS_PASS=<password> go test ./internal/edge/ -run TestFreeSWITCH -v
```

It confirms that sofia accepts a proxied REGISTER and **preserves the
`fsbc=` binding token** in the contact it stores (the whole inbound-call
path depends on this), that a switch-originated call and its hangup both
traverse the proxy, and that audio survives a round trip through the anchor
into FreeSWITCH's `echo` application and back. The tests drive the switch
through `/usr/local/freeswitch/bin/fs_cli`, so run them on the FreeSWITCH
host.
