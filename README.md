# FreeSBC

An all-in-one open-source Session Border Controller with the Caddy experience: **one binary, one YAML file, `./freesbc run`.**

FreeSBC is written in pure Go and ships as a single static binary with zero external dependencies — no database, no Redis, no kernel modules, no container orchestration, and **no external media process**. It targets small/medium businesses and ITSPs running a single node with hundreds to a few thousand concurrent calls.

It runs two independent planes, either or both of which may be enabled:

- **Trunk B2BUA** — carrier/PBX interconnect over UDP/TCP/TLS, with routing,
  failover, outbound REGISTER and SRTP (SDES). Configured with `peers:` and
  `routes:`.
- **Edge proxy** — a stateful SIP and media edge proxy that provides SIP
  registration proxying, UDP/WebSocket transport interworking, RTP anchoring,
  and WebRTC-to-RTP media relay for FreeSWITCH. Configured with
  `network:`, `sip.public/private/upstream`, `rtp.public/private` and
  `webrtc:`.

## Why

Deploying a traditional SBC stack (FreeSWITCH + Redis + Python + Lua + nftables + Ansible, as in LibreSBC) means many components, four languages, and a config pipeline that spans four layers. FreeSBC collapses all of that into one process with a declarative config file as the single source of truth.

## Planned feature set (MVP)

- **SIP trunk interconnect** — UDP/TCP/TLS, IP-authenticated and registration-based trunks (outbound REGISTER with digest auth)
- **B2BUA with topology hiding** — full SDP rewrite, two independent call legs
- **Routing engine** — regex matching, number transformation, ordered failover, DNS SRV
- **RTP relay + SRTP (SDES)** — media anchoring, NAT traversal via hardened first-packet latching; **no transcoding** (left to the softswitch behind)
- **Built-in security** — per-IP rate limiting, scanner fingerprinting, auto-ban, optional nftables integration (not a hard dependency)
- **Embedded WebUI + REST API** — an editor for the same YAML file, with hot reload
- Carrier-grade interop baseline: OPTIONS answering, session timers (RFC 4028), 100rel/PRACK passthrough

Explicit non-goals: transcoding, CDR, clustering, and being a registrar in
its own right — the edge proxy PROXIES registrations to FreeSWITCH rather
than owning users or credentials. See the [design doc](freesbc-allinone-design.md) (Chinese).

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
| Lifecycle | Media is released deterministically on BYE, CANCEL, a failed final response, dialog teardown, media silence, and shutdown. |

### Known limitations

- **re-INVITE does not renegotiate media.** An in-dialog INVITE is proxied as
  signaling and the media session stays on the ports it holds. The
  architecture is ready for it (`Session.Relatch` exists and the latch
  distinguishes seeded from latched state), but the offer/answer path is not
  wired up.
- **Offerless INVITE is refused (488)** in both directions.
- **An inbound call to a browser is offered plain RTP**, which a browser will
  reject. FreeSWITCH-originated calls therefore reach SIP/UDP phones, not
  WebRTC clients; that needs the same re-INVITE machinery.
- **One media session per Call-ID.** An upstream that forked one Call-ID into
  two dialogs would need two sessions — a B2BUA's problem, not a proxy's.
- **Upstream is a single UDP FreeSWITCH** at a literal address. No SRV, no
  failover, no TCP/TLS upstream.
- **IPv6 is untested** on the proxy plane, though the code paths are
  address-family agnostic.


## Quick start

Requires Go ≥ 1.22.

> **公网部署前必读** [`docs/DEPLOYMENT-SECURITY.md`](docs/DEPLOYMENT-SECURITY.md)（部署安全基线：公网暴露策略 + admin 监听基线）。

```sh
go build -o freesbc .
cp sbc.example.yaml sbc.yaml   # edit peers/routes for your setup
./freesbc check -c sbc.yaml    # validate: errors name the line and field
./freesbc run   -c sbc.yaml
```

The config file is watched: edits are validated and hot-swapped atomically. A bad edit never takes down the process — the previous config stays active and the error is logged.

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

| Milestone | Scope | Status |
|---|---|---|
| M1 | Config foundation: schema, validation, atomic hot reload, `run`/`check` CLI | ✅ done |
| M2 | Media plane: RTP port pool, relay engine, latching hardening | ✅ done |
| M3 | Signaling core: SIP server, B2BUA, SDP rewrite, routing — first end-to-end call | ✅ done |
| ├ M3.1 | SIP front door: listeners, OPTIONS, source-IP identification | ✅ done |
| ├ M3.2 | Routing engine: match / transform / failover | ✅ done |
| └ M3.3 | B2BUA bridge: leg pairing, SDP rewrite, media wiring, Relatch | ✅ done |
| M4 | Trunk interop: From/CLI, outbound REGISTER, session timers, PRACK, DNS SRV | ✅ done |
| ├ M4.1 | Outbound-INVITE realism: From/CLI, ring cap, response codes | ✅ done |
| ├ M4.2 | Outbound REGISTER | ✅ done |
| ├ M4.3 | Session timers (RFC 4028) + 100rel/PRACK | ✅ done |
| └ M4.4 | DNS SRV + peer health/cooldown | ✅ done |
| M5 | SRTP (SDES): a=crypto negotiation, SRTP↔RTP interworking, per-peer policy | ✅ done |
| M6 | Shield: per-IP rate limiting, scanner fingerprinting, auto-ban (optional nftables) | ✅ done |
| M7 | Operability: admin API, metrics, embedded WebUI | ✅ done |
| ├ M7.1 | Admin API + Prometheus metrics (read-only, bcrypt Basic Auth) | ✅ done |
| ├ M7.2 | Config write-back (`PUT /api/config`, atomic, `${ENV}`-preserving) | ✅ done |
| └ M7.3 | Embedded WebUI (dashboard + config editor) | ✅ done |
| M8 | Edge proxy: public/private topology, REGISTER proxy, WS/WSS interworking, RTP anchoring, WebRTC (ICE-Lite/DTLS-SRTP) | ✅ done |

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
  the `<call-id>` is the `id` from `GET /api/calls`.

Bind the admin listener **private** (there is no TLS on it) — front it with a
reverse proxy for remote/TLS access. Deployment baseline: loopback-only by
policy; non-loopback requires the checklist in
[`docs/DEPLOYMENT-SECURITY.md`](docs/DEPLOYMENT-SECURITY.md) (G-2).

## Development

```sh
go vet ./...
go test ./... -race
```

Design and implementation plans live in [`freesbc-allinone-design.md`](freesbc-allinone-design.md) and [`docs/superpowers/plans/`](docs/superpowers/plans/).
