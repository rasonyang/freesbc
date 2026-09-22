# FreeSBC

An all-in-one open-source Session Border Controller with the Caddy experience: **one binary, one YAML file, `./freesbc run`.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.25.7-00ADD8.svg)](go.mod)

- **Pure Go, one static binary, zero external dependencies** — no database, no Redis, no kernel modules, no container orchestration, and **no external media process**.
- **Two independent planes, either or both** — a [**Trunk B2BUA**](docs/trunk.md) for carrier/PBX interconnect, and an [**Edge proxy**](docs/edge.md) that keeps FreeSWITCH on the private LAN: SIP phones and browsers reach FreeSBC's public address, and FreeSBC is the only thing that talks to FreeSWITCH.
- **Embedded WebUI, REST API and Prometheus metrics** — a live dashboard and a validated editor for the same YAML file, behind bcrypt Basic Auth.

Deploying a traditional SBC stack (FreeSWITCH + Redis + Python + Lua + nftables + Ansible) means many components, four languages, and a config pipeline that spans four layers. FreeSBC collapses all of that into one process with a declarative config file as the single source of truth.

## Install

Requires Go ≥ 1.25.7.

```sh
go build -o freesbc ./cmd/freesbc
```

## Quick start

> **Read before exposing to the public internet:** [`docs/design.md`](docs/design.md) (the networking and deployment topology section and the security model section).

**Trunk** — carrier/PBX interconnect (`cp sbc.example.yaml sbc.yaml`, then edit peers/routes for your setup):

```yaml
listen:
  sip: [udp://0.0.0.0:5060]
peers:
  carrier-a:    { address: sip.carrier-a.com:5060, allowed_ips: [203.0.113.0/24] }
  internal-pbx: { address: 10.0.0.10:5060, allowed_ips: [10.0.0.0/8] }
routes:
  - { name: outbound, from: internal-pbx, to: [carrier-a] }
```

**Edge** — proxy in front of FreeSWITCH (`cp edge.example.yaml edge.yaml`):

```yaml
network:
  public:  { bind_ip: 0.0.0.0, advertised_ip: 203.0.113.7 }
  private: { bind_ip: 10.77.0.2 }
sip:
  public:
    udp: { enabled: true, bind: 0.0.0.0:16060 }
  private:
    bind: 10.77.0.2:5060
  upstream:
    address: 10.77.0.10:5060
rtp:
  public:  { bind_ip: 0.0.0.0, advertised_ip: 203.0.113.7, port_min: 30000, port_max: 39999 }
  private: { bind_ip: 10.77.0.2, port_min: 40000, port_max: 49999 }
```

Then validate and run:

```sh
./freesbc check -c sbc.yaml    # validate: errors name the line and field (use edge.yaml for the edge deployment)
./freesbc run   -c sbc.yaml
```

The config file is watched: edits are validated and hot-swapped atomically. A bad edit never takes down the process — the previous config stays active and the error is logged. Listener sockets, TLS certificates, the edge topology (upstreams, PSTN gateways, WebRTC) and the `admin` listener are read once at startup and need a restart.

## Keep FreeSWITCH off the public internet

The edge plane exists so that FreeSBC is the only element with a public address. FreeSWITCH is a literal private `IP:port` upstream and never needs a public IP, a port forward, or NAT handling of its own.

```text
  Internet ──▶ FreeSBC  203.0.113.7   public: SIP/UDP, WS/WSS, RTP, WebRTC
                  │
                  │ private LAN/VPN: plain SIP/UDP + RTP, sent from 10.77.0.2
                  ▼
              FreeSWITCH  10.77.0.10:5060   no public IP, no port forward
```

What the SBC absorbs, so FreeSWITCH never sees it:

- **Public traffic itself.** Every request FreeSWITCH receives is sent from FreeSBC's private socket (`sip.private.bind`), so its sofia profile only has to accept that one address. In the other direction the edge's pre-parse read filter drops anything arriving on the private bind whose source is not a configured upstream.
- **Scanners and floods.** Per-IP rate limiting and the scanner User-Agent signature list (instant ban) run on every public request; the private plane is exempt from the shield entirely, and every denial is a silent drop rather than a response that confirms the SBC exists. Edge-plane bans are in-memory — the optional nftables backend is wired to the trunk plane only.
- **Its own addresses.** Every SDP body the edge plane emits is constructed, never derived from the other leg, so a public client is never given FreeSWITCH's address and FreeSWITCH is never given the client's; the REGISTER Contact is rewritten toward the SBC and restored on the way back, and all media is anchored on FreeSBC ports. The Via stack is ordinary proxy behaviour, not hidden: FreeSBC annotates the sender's Via with `received=`, so FreeSWITCH does see the public client's address there.
- **Transport and NAT variety.** WS/WSS and WebRTC (ICE-Lite, DTLS-SRTP, RTCP-mux) are terminated at the edge and relayed to FreeSWITCH as plain SIP over UDP and plain RTP. `received=`/`rport` handling and symmetric-RTP latching happen at the SBC.

What stays with FreeSWITCH: it remains the authoritative registrar and owns users, credentials, dial plans and all call logic. REGISTER and its digest challenge are proxied verbatim and FreeSBC never holds a credential. The private plane is trusted and unmetered by design — FreeSBC does not enforce that; your network must keep it unreachable from anywhere else.

Details: [`docs/edge.md`](docs/edge.md) (topology, behaviour table, known limitations) and [`docs/design.md`](docs/design.md) (§12 networking and deployment topology, §14 security model).

## Which plane do I need?

| Goal | Plane | Configure |
|---|---|---|
| Interconnect carriers with a PBX/softswitch over SIP trunks | [Trunk B2BUA](docs/trunk.md) | `peers:` and `routes:` |
| Put SIP phones and sip.js browsers in front of FreeSWITCH, keeping FreeSWITCH itself on the private LAN | [Edge proxy](docs/edge.md) | `network:`, `sip.public/private`, `sip.upstream` (or `sip.upstreams`), `rtp.public/private`, `webrtc:` |
| Both at once, in one process | Both | both sets of sections in one file |

## Features

- **SIP trunk interconnect** — UDP, TCP and TLS transports, real certificate or a self-signed fallback, optional mTLS, IP-authenticated peers, and registration-based trunks via outbound REGISTER with digest auth
- **B2BUA with topology hiding** — two independent call legs with their own Call-ID, From-tag and Via, and full SDP rewrite
- **Routing engine** — regex matching, number transformation, ordered failover with passive per-endpoint cooldown, and DNS SRV resolution with RFC 3263 priority/weight ordering, cached
- **RTP relay + SRTP (SDES)** — media anchoring, `a=crypto` negotiation with a per-peer `disabled`/`optional`/`required` policy on the trunk plane, SRTP↔RTP interworking in both directions, and NAT traversal via hardened first-packet latching
- **Edge proxy plane** — the only public-facing element in front of a FreeSWITCH that stays on the private LAN: registration proxying to FreeSWITCH, UDP/WS/WSS interworking, RTP anchoring, WebRTC (ICE-Lite, DTLS-SRTP, RTCP-mux) relayed to plain RTP, a multi-upstream pool with per-user hashing and dialog stickiness, and an optional peer-to-peer PSTN trunk with gateway failover
- **Built-in security** — per-IP rate limiting, scanner fingerprinting against known-tool User-Agent signatures with an instant ban, and optional nftables integration: auto-detected, degrades to in-memory bans, never a hard dependency
- **Embedded WebUI + REST API** — a live dashboard and an editor for the same YAML file, with validated atomic write-back, hot reload, Prometheus metrics and bcrypt Basic Auth
- **Carrier interop baseline** — OPTIONS answering and session-timer negotiation (RFC 4028), including the 422/Min-SE exchange on both legs

## Documentation

- [`docs/trunk.md`](docs/trunk.md) — trunk plane: `peers`/`routes` configuration, NAT/VPN bind vs advertised addresses, trunk features and roadmap
- [`docs/edge.md`](docs/edge.md) — edge plane: topology, behaviour table, PSTN trunk, multiple FreeSWITCHes, known limitations, interop verification
- [`docs/design.md`](docs/design.md) — the design document: what the code does, as implemented
- [`sbc.example.yaml`](sbc.example.yaml) — full annotated example, trunk plane plus an optional edge section
- [`edge.example.yaml`](edge.example.yaml) — full annotated example, proxy-only deployment

## Admin & WebUI

Enable the optional `admin` block (a bcrypt `password_hash` — generate with `htpasswd -bnBC 10 "" 'your-password' | tr -d ':\n'`), then:

- browse `http://<admin.listen>/` (HTTP Basic Auth) for the live dashboard (active calls, peers, port/registration status) and the raw-config editor — edits are validated, written atomically, and hot-reloaded; keep secrets as `${ENV}` references,
- scrape `http://<admin.listen>/metrics` with Prometheus (`basic_auth` in the scrape config),
- tear down a stuck call: `curl -u admin:… -X DELETE http://<admin.listen>/api/calls/<call-id>` (204 killed, 404 already gone) — the `<call-id>` is the `id` from `GET /api/calls`.

Bind the admin listener **private** — front it with a reverse proxy for remote access, or serve HTTPS directly with `admin.tls_cert` / `admin.tls_key`. Validation rejects a non-loopback `admin.listen` unless `admin.allow_remote: true` is set; read the security model section of [`docs/design.md`](docs/design.md) before setting it.

## Status & limitations

FreeSBC targets small/medium businesses and ITSPs running a single node; hundreds to a few thousand concurrent calls is the design target, not a measured result — the repo carries no benchmarks and no load-test harness.

Explicit non-goals: transcoding, CDR, clustering, and being a registrar in its own right — the edge proxy PROXIES registrations to FreeSWITCH rather than owning users or credentials. See the [design doc](docs/design.md).

- **No transcoding**, on either plane — left to the softswitch behind.
- The multi-failure auto-ban counter (`shield.auto_ban`) is implemented but not yet wired — nothing in the shipped planes feeds it.
- Session timers are negotiated, but no timer tears a call down on session expiry.
- The edge plane never offers or reads `a=crypto`: a SIP phone there gets plain RTP, and only browser legs get DTLS-SRTP.
- The call list and teardown in the admin API cover trunk-plane calls only; edge-proxy dialogs are not listed.
- The edge proxy has further structural limits — inbound calls to browsers, offerless INVITE, UDP-only literal upstreams, no TURN/full ICE, no SUBSCRIBE/NOTIFY, and more: see [known limitations](docs/edge.md#known-limitations).

## Roadmap

Items not yet implemented. Trunk-plane items are listed in [`docs/trunk.md`](docs/trunk.md#roadmap-trunk-plane); the edge proxy's [known limitations](docs/edge.md#known-limitations) are structural rather than scheduled.

- **Scanner heuristics beyond User-Agent** — method and traffic-shape fingerprinting
- **SUBSCRIBE/NOTIFY through the edge proxy** — needed before MWI and BLF reach phones
- **Consistent hashing for `sip.upstreams`** — the pool is modulo-hashed, so changing the node set reshuffles users between switches

## Development

```sh
go vet ./...
go test ./... -race
```

Some trunk and edge tests bind `127.0.0.2`. Linux routes all of `127.0.0.0/8` to loopback; on macOS add the alias first (`sudo ifconfig lo0 alias 127.0.0.2 up`) or those tests fail.

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

`trunk` and `edge` are the two SIP planes and are named for the side each serves, not the protocol both speak. Neither imports the other: besides the protocol primitives (`sip`, `sip/sdp`) they share only `config`, `media` and `shield`; dependencies run one way, and only `app` wires the planes and `admin` together. Everything is under `internal/`: the only consumer is `cmd/freesbc`, so no package here carries an API promise.

## License

Apache License 2.0. See [LICENSE](LICENSE).
