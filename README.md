# FreeSBC

An all-in-one open-source Session Border Controller with the Caddy experience: **one binary, one YAML file, `./freesbc run`.**

FreeSBC is written in pure Go and ships as a single static binary with zero external dependencies — no database, no Redis, no kernel modules, no container orchestration, and **no external media process**. It targets small/medium businesses and ITSPs running a single node with hundreds to a few thousand concurrent calls.

It runs two independent planes, either or both of which may be enabled:

- **Trunk B2BUA** — carrier/PBX interconnect over UDP/TCP/TLS, with routing,
  failover, outbound REGISTER and SRTP (SDES). Configured with `peers:` and
  `routes:`.
- **Edge proxy** — a stateful SIP and media edge proxy that provides SIP
  registration proxying, UDP/WebSocket transport interworking, RTP anchoring,
  WebRTC-to-RTP media relay, and peer-to-peer PSTN trunking for FreeSWITCH.
  Configured with `network:`, `sip.public/private`, `sip.upstream` (or
  `sip.upstreams` for a pool), an optional `sip.pstn`, `rtp.public/private`
  and `webrtc:`.

## Why

Deploying a traditional SBC stack (FreeSWITCH + Redis + Python + Lua + nftables + Ansible) means many components, four languages, and a config pipeline that spans four layers. FreeSBC collapses all of that into one process with a declarative config file as the single source of truth.

## Features

- **SIP trunk interconnect** — UDP, TCP and TLS transports (real certificate or a self-signed fallback, optional mTLS), IP-authenticated peers, and registration-based trunks via outbound REGISTER with digest auth
- **B2BUA with topology hiding** — two independent call legs with their own Call-ID, From-tag and Via, and full SDP rewrite
- **Routing engine** — regex matching, number transformation, ordered failover with passive per-endpoint cooldown, and DNS SRV resolution (RFC 3263 priority/weight ordering, cached)
- **RTP relay + SRTP (SDES)** — media anchoring, `a=crypto` negotiation with a per-peer `disabled`/`optional`/`required` policy, SRTP↔RTP interworking in both directions, NAT traversal via hardened first-packet latching; **no transcoding** (left to the softswitch behind)
- **Edge proxy plane** — registration proxying to FreeSWITCH, UDP/WS/WSS interworking, RTP anchoring, WebRTC (ICE-Lite, DTLS-SRTP, RTCP-mux) relayed to plain RTP, a multi-upstream pool with per-user hashing and dialog stickiness, and an optional peer-to-peer PSTN trunk with gateway failover
- **Built-in security** — per-IP rate limiting, scanner fingerprinting against known-tool User-Agent signatures, auto-ban, optional nftables integration (auto-detected, degrades to in-memory bans, never a hard dependency)
- **Embedded WebUI + REST API** — a live dashboard and an editor for the same YAML file, with validated atomic write-back, hot reload, Prometheus metrics and bcrypt Basic Auth
- Carrier interop baseline: OPTIONS answering and session-timer negotiation (RFC 4028), including the 422/Min-SE exchange on both legs; no timer tears a call down on session expiry

Explicit non-goals: transcoding, CDR, clustering, and being a registrar in
its own right — the edge proxy PROXIES registrations to FreeSWITCH rather
than owning users or credentials. See the [design doc](docs/design.md).

## Edge proxy (SIP / RTP / WebRTC)

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
- **All signaling and media stay anchored through FreeSBC.** FreeSWITCH is
  never given a public endpoint's address, and a public client is never given
  FreeSWITCH's.

It is a **proxy, not a B2BUA**: Call-ID, From/To tags and CSeq pass through
untouched, and FreeSBC stays on the path via RFC 5658 double Record-Route.
FreeSWITCH remains the authoritative registrar — REGISTER and its digest
challenge are forwarded verbatim, and FreeSBC never holds a credential.

See [`edge.example.yaml`](edge.example.yaml) for a complete annotated
configuration, and the "Edge proxy plane" section of
[`sbc.example.yaml`](sbc.example.yaml) for running it alongside trunks.

### What it does

| Area | Behaviour |
|---|---|
| Transports | Public UDP / WS / WSS; upstream UDP. WS↔UDP is real interworking, with the WebSocket connection bound to the registration. |
| Methods | REGISTER, INVITE, ACK, CANCEL, BYE, OPTIONS, INFO. OPTIONS is answered locally rather than multiplied onto FreeSWITCH. |
| REGISTER | Proxied verbatim, digest and all. The Contact is rewritten toward FreeSWITCH (so inbound calls route back through the SBC) and restored on the way back (so sip.js accepts the registration). The binding expiry follows the registrar's grant, not the client's request. |
| SDP | A typed subsystem over `pion/sdp/v3` — no string manipulation. Bodies are **constructed**, never derived from the other leg, which is what makes the two address-leak guarantees structural. |
| Codecs | PCMU, PCMA, Opus and RFC 4733 telephone-event, passed through with the offerer's payload numbers. **No transcoding**: no common codec means a clean 488. |
| Media | Every stream anchored on an SBC port pair. Symmetric RTP: the destination is seeded from SDP so audio flows immediately, then corrected by the first authenticated packet. Strict source latching resists off-path hijacking. |
| WebRTC | ICE-Lite → DTLS → SRTP/SRTCP with RTCP-mux, built directly on `pion/ice`, `pion/dtls` and `pion/srtp` — no `PeerConnection`. The peer certificate is checked against the signalled `a=fingerprint`. |
| DTMF | RFC 4733 telephone-event traverses the relay untouched; SIP INFO is proxied as signaling. |
| re-INVITE | Hold, unhold, session-timer refresh and codec changes are renegotiated with the anchor intact: the body is rebuilt for the far side on the ports the session already holds, and a WebRTC leg keeps its ICE credentials, fingerprint and DTLS role so media is never interrupted. |
| Lifecycle | Media is released deterministically on BYE (from either side), CANCEL, a failed final response, dialog teardown, media silence, and shutdown. A 2xx whose SDP cannot be anchored is ACKed and BYEd rather than left as a zombie dialog. |

### PSTN trunk

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
a 5xx/408, or an unanchorable answer; a 4xx like 486 or an auth challenge
is relayed to FreeSWITCH immediately, never retried. When every gateway
fails, FreeSWITCH sees 488 if an answer could not be anchored, else the
last genuine carrier code, else 408, else 503.
Health is passive cooldown: a gateway that answered nothing before its
budget expired is penalized for `cooldown` and dialed only when no
healthy alternative remains (never a hard block); a successful call
recovers it.

On the FreeSWITCH side (no gateway definition needed — this is a plain
peer-to-peer bridge):

```xml
<action application="bridge"
        data="sofia/internal/sip:${destination_number}@10.77.0.2:16060"/>
```

Inbound carrier→FreeSWITCH calls need no trunk configuration: they arrive
on the public side like any other unregistered caller and are proxied
upstream unchanged. Note that they are also subject to the same
[`shield`](#configuration) rate limiting as any unregistered source — a
chatty carrier can be throttled like an attacker; raise its budget if
needed.

### Multiple FreeSWITCHes (`sip.upstreams`)

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

### Known limitations

- **An inbound call to a browser is offered plain RTP**, which a browser will
  reject: FreeSBC cannot make a DTLS-SRTP *offer*, because a WebRTC offer
  needs the answerer's fingerprint and ICE credentials and an offer by
  definition has not seen them. FreeSWITCH-originated calls therefore reach
  SIP/UDP phones, not WebRTC clients. Browser-originated calls are
  unaffected.
- **Offerless INVITE is refused (488)** in both directions.
- **One media session per Call-ID.** An upstream that forked one Call-ID into
  two dialogs would need two sessions — a B2BUA's problem, not a proxy's.
- **Upstreams are UDP FreeSWITCHes at literal addresses.** One or a pool
  (`sip.upstreams`), with per-user hashing and passive failover between
  pool members — but no SRV, no TCP/TLS upstream, and no failover to a
  switch outside the pool.
- **IPv6 is untested** on the proxy plane, though the code paths are
  address-family agnostic.
- **No TURN and no full ICE.** FreeSBC is ICE-Lite and needs a publicly
  reachable media address; a client that can only reach it via a relay is
  out of scope.
- **SUBSCRIBE/NOTIFY (and UPDATE, MESSAGE, REFER, PUBLISH) are answered
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

### Verification against a real FreeSWITCH

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


## Quick start

Requires Go ≥ 1.25.7.

> **Read before exposing to the public internet:** [`docs/design.md`](docs/design.md) (the networking and deployment topology section and the security model section).

```sh
go build -o freesbc ./cmd/freesbc
cp sbc.example.yaml sbc.yaml   # edit peers/routes for your setup
./freesbc check -c sbc.yaml    # validate: errors name the line and field
./freesbc run   -c sbc.yaml
```

The config file is watched: edits are validated and hot-swapped atomically. A bad edit never takes down the process — the previous config stays active and the error is logged. Listener sockets, TLS certificates, the edge topology (upstreams, PSTN gateways, WebRTC) and the `admin` listener are read once at startup and need a restart.

## Configuration

Three top-level concepts — `listen`, `peers`, `routes` — plus optional `shield` and `admin` sections with sensible defaults:

```yaml
listen:
  sip: [udp://0.0.0.0:5060]

peers:
  carrier-a:
    address: sip.carrier-a.com:5060
    auth: { username: acct01, password: "${CARRIER_A_PASS}" }
    register: true
    allowed_ips: [203.0.113.0/24]
  internal-pbx:
    address: 10.0.0.10:5060
    allowed_ips: [10.0.0.0/8]

routes:
  - name: outbound
    from: internal-pbx
    match: { to: "^9(\\d+)$" }
    transform: { to: "$1" }
    to: [carrier-a]          # list order = failover order
  - name: inbound
    from: carrier-a
    to: [internal-pbx]
```

`${ENV_VAR}` references are expanded at load time only — secrets are never written back to disk and never appear in error output. See [`sbc.example.yaml`](sbc.example.yaml) for the full annotated example.

For NAT/VPN deployments (private bind address, public advertised address), the optional `sip:`/`rtp:` sections replace `listen.sip` and split the bind and advertised planes independently:

```yaml
sip:
  bind_ip: 10.77.0.2        # where the SIP listener actually binds
  bind_port: 16060
  advertised_ip: <PUBLIC>   # what Contact/From/REGISTER claim (defaults to bind values)
  advertised_port: 16060
rtp:
  bind_ip: 10.77.0.2        # RTP/RTCP sockets bind here (empty = every interface)
  advertised_ip: <PUBLIC>   # what SDP c=/o= claim
  port_min: 20000           # explicit RTP port range (both or neither); replaces
  port_max: 20100           #   listen.media.port_range, which it cannot be combined with
```

The two sections are mutually independent: SIP can advertise one public address and RTP another. `advertised_ip`/`advertised_port` default to their bind counterparts; when `sip.bind_ip` is set, `rtp.advertised_ip` is required unless `listen.media.public_ip` is a literal address (otherwise SDP would advertise `127.0.0.1`).

## Roadmap

Items not yet implemented. See also the edge proxy's [known
limitations](#known-limitations), which are structural rather than scheduled.

- **100rel/PRACK** — an INVITE carrying `Require: 100rel` is answered `420 Bad Extension` today, and the trunk plane neither advertises 100rel nor handles PRACK
- **Mid-call re-INVITE on the trunk plane** — hold/resume and codec renegotiation are answered `501`; only session-timer refresh re-INVITEs are handled (the edge proxy does re-anchor re-INVITEs)
- **Inbound digest challenge** — the SBC answers challenges but never issues one; trunk peers are authenticated by source IP, plus TLS/mTLS where configured
- **Active peer qualification** — outbound OPTIONS keepalives; peer liveness is passive cooldown today
- **`listen.media.public_ip: auto`** — STUN-detected public address; a literal address is required for now
- **Scanner heuristics beyond User-Agent** — method and traffic-shape fingerprinting
- **SUBSCRIBE/NOTIFY through the edge proxy** — needed before MWI and BLF reach phones
- **Consistent hashing for `sip.upstreams`** — the pool is modulo-hashed, so changing the node set reshuffles users between switches
- **Configurable TCP/TLS listener limits and TLS certificate hot rotation** — the connection cap and idle timeout are compiled in, and certificate changes need a restart

## Admin & WebUI

Enable the optional `admin` block (a bcrypt `password_hash` — generate with
`htpasswd -bnBC 10 "" 'your-password' | tr -d ':\n'`), then:

- browse `http://<admin.listen>/` (HTTP Basic Auth) for the live dashboard
  (active calls, peers, port/registration status) and the raw-config editor
  (edits are validated, written atomically, and hot-reloaded; keep secrets as
  `${ENV}` references),
- scrape `http://<admin.listen>/metrics` with Prometheus (`basic_auth` in the
  scrape config),
- tear down a stuck call: `curl -u admin:… -X DELETE
  http://<admin.listen>/api/calls/<call-id>` (204 killed, 404 already gone) —
  the `<call-id>` is the `id` from `GET /api/calls`. The call list and
  teardown cover trunk-plane calls only; edge-proxy dialogs are not listed.

Bind the admin listener **private** — front it with a reverse proxy for remote
access, or serve HTTPS directly with `admin.tls_cert` / `admin.tls_key`.
Validation rejects a non-loopback `admin.listen` unless
`admin.allow_remote: true` is set; read the security model section of
[`docs/design.md`](docs/design.md) before setting it.

## Layout

```text
cmd/freesbc/          argv parsing, signal handling, exit codes
internal/
  app/                construction and lifecycle: builds every component and runs it
  config/             sbc.yaml: parse, validate, hot reload
  sip/                SIP protocol primitives shared by both planes
  sip/sdp/            SDP subsystem (parse, codec negotiation, construction)
  trunk/              trunk plane: B2BUA between carriers and a PBX
  edge/               edge plane: SIP/RTP/WebRTC proxy in front of FreeSWITCH
  media/              RTP/RTCP relay, port pools, WebRTC leg (ICE/DTLS/SRTP)
  shield/             per-IP rate limiting, scanner fingerprinting, auto-ban
  admin/              operator HTTP API, Prometheus metrics, embedded WebUI
test/interop/         SIPp scenarios and config for manual interop runs
```

`trunk` and `edge` are the two SIP planes and are named for the side each
serves, not the protocol both speak. Neither imports the other: besides
the protocol primitives (`sip`, `sip/sdp`) they share only `config`,
`media` and `shield`; dependencies run one way, and only `app` wires the
planes and `admin` together. Everything is under `internal/`: the only consumer is
`cmd/freesbc`, so no package here carries an API promise.

## Development

```sh
go vet ./...
go test ./... -race
```

Some trunk and edge tests bind `127.0.0.2`. Linux routes all of
`127.0.0.0/8` to loopback; on macOS add the alias first
(`sudo ifconfig lo0 alias 127.0.0.2 up`) or those tests fail.

The design document is [`docs/design.md`](docs/design.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
