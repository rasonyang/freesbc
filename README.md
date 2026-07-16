# FreeSBC

An all-in-one open-source Session Border Controller with the Caddy experience: **one binary, one YAML file, `./freesbc run`.**

FreeSBC is written in pure Go and ships as a single static binary with zero external dependencies — no database, no Redis, no kernel modules, no container orchestration. It targets small/medium businesses and ITSPs running a single node with hundreds to a few thousand concurrent calls.

> **Status: early development.** Milestone 1 (config foundation) is complete: the binary loads, validates, and hot-reloads its configuration. SIP signaling and media relay are the next milestones — FreeSBC does not process calls yet.

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

Explicit non-goals: transcoding, registrar (serving phone registrations), CDR, clustering, WebRTC gateway. See the [design doc](freesbc-allinone-design.md) (Chinese).

## Quick start

Requires Go ≥ 1.22.

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

## Roadmap

| Milestone | Scope | Status |
|---|---|---|
| M1 | Config foundation: schema, validation, atomic hot reload, `run`/`check` CLI | ✅ done |
| M2 | Media plane: RTP port pool, relay engine, latching hardening | ✅ done |
| M3 | Signaling core: SIP server, B2BUA, SDP rewrite, routing — first end-to-end call | ✅ done |
| ├ M3.1 | SIP front door: listeners, OPTIONS, source-IP identification | ✅ done |
| ├ M3.2 | Routing engine: match / transform / failover | ✅ done |
| └ M3.3 | B2BUA bridge: leg pairing, SDP rewrite, media wiring, Relatch | ✅ done |
| M4 | Trunk interop: digest auth, outbound REGISTER, session timers, PRACK, DNS SRV | in progress |
| ├ M4.1 | Outbound-INVITE realism: From/CLI, ring cap, response codes | ✅ done |
| ├ M4.2 | Outbound REGISTER | next |
| ├ M4.3 | Session timers (RFC 4028) + 100rel/PRACK | |
| └ M4.4 | DNS SRV + peer health/cooldown | |
| M5 | SRTP (SDES) | |
| M6 | Shield: rate limiting, scanner detection, auto-ban | |
| M7 | Admin API, embedded WebUI, Prometheus metrics | |

## Development

```sh
go vet ./...
go test ./... -race
```

Design and implementation plans live in [`freesbc-allinone-design.md`](freesbc-allinone-design.md) and [`docs/superpowers/plans/`](docs/superpowers/plans/).
