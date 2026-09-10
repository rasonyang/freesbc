# FreeSBC — All-in-One Open Source SBC Design

Background: modeled on LibreSBC, aimed squarely at its core pain points — complex deployment and a high barrier to entry.

## 1. Background and Motivation

### LibreSBC Architecture Analysis

| Component | Technology | Responsibility |
|------|------|------|
| FreeSWITCH | C | Signaling B2BUA + media processing (RTP, transcoding) |
| callng | Lua (embedded in FreeSWITCH) | Call routing logic, CDR events, security events |
| liberator | Python (FastAPI) | Management API, config generation (Jinja2 → XML), CDR, nftables management |
| Redis | — | Configuration and state storage |
| webui | Static JS | Management interface |
| ansible + docker | — | Deployment orchestration |

**Strengths**: inherits FreeSWITCH's carrier-grade interoperability and transcoding; clean separation of control plane and media plane; a complete security feature set (nftables shield, topology hiding); MIT licensed.

**Weaknesses (what this project sets out to fix)**: too many deployment components (FreeSWITCH + Redis + Python + Lua + nftables + ansible), where a version mismatch anywhere breaks the system; four languages to maintain; a long configuration path (API → Redis → Jinja2 → XML → reload) that forces troubleshooting across four layers; no single-binary delivery; FreeSWITCH itself is hard to install.

### Product Thesis

Match the Caddy experience: **an open source SBC that runs from one downloaded binary, one configuration file, and `./FreeSBC run`.**

## 2. Scope Decisions (Confirmed)

- **Media depth**: RTP relay plus SRTP encryption/decryption only — **no transcoding**. Transcoding is left to the softswitch behind the SBC. This covers the mainstream SBC scenarios: topology hiding, media security, NAT traversal. SRTP key negotiation is **SDES only** (SDP `a=crypto`, signaling over TLS); DTLS-SRTP is excluded along with the WebRTC scope.
- **Positioning**: single node first, for SMBs and ITSPs, at hundreds to a few thousand concurrent calls per host. HA via active/standby or VRRP comes later.
- **In the MVP**: SIP trunk interop (including **outbound trunk registration**: sending REGISTER with digest authentication to the carrier, covering registration-based trunks), routing engine, topology hiding (B2BUA + SDP rewrite), RTP relay + SRTP (SDES), built-in security protection, embedded WebUI.
- **Not in the MVP** (later releases): registration proxy / registrar (that is, **serving** phone and endpoint registrations — a different thing from the outbound registration above), CDR, transcoding, clustering.
- **Configuration model**: a declarative YAML file is the single source of truth, with hot reload; the WebUI and API are editors for that file.

### Technology Selection

- **Option A (selected): pure Go, built from scratch** — sipgo (SIP stack) + pion (SRTP/SDP) + go:embed WebUI. A true single binary, zero dependencies, cross-compilable. The cost: SIP interoperability has to be learned the hard way (focusing the MVP on trunk interop bounds that risk — the far end is a carrier or PBX, whose behavior is better specified than a phone's).
- Option B (rejected): Go control plane with FreeSWITCH embedded in a single container. Interoperability comes free, but it is not a true single binary — FreeSWITCH's complexity is merely hidden, and the product differentiation is weak.
- Option C (rejected): Go signaling + rtpengine. The strongest performance, but it requires a kernel module, and that deployment barrier contradicts the goal.

## 3. Overall Architecture

Four planes in a single process:

```
┌─────────────────────────────────────────────────┐
│              FreeSBC (single process)           │
│  ┌─────────────┐   ┌──────────────────────────┐ │
│  │ Mgmt Plane  │   │ Signaling Plane (sipgo)  │ │
│  │ HTTP API    │──▶│ SIP B2BUA                │ │
│  │ WebUI       │   │ UDP/TCP/TLS :5060/:5061  │ │
│  │ (embed)     │   └──────────┬───────────────┘ │
│  └─────────────┘              │                 │
│  ┌─────────────┐   ┌──────────▼───────────────┐ │
│  │ Shield Plane│   │ Media Plane              │ │
│  │ Rate/Ban    │──▶│ RTP Relay + SRTP (pion)  │ │
│  │ Scan Detect │   │ UDP port pool 16384-32768│ │
│  └─────────────┘   └──────────────────────────┘ │
│  Truth source: sbc.yaml (fsnotify hot reload)   │
│  Runtime state: in-memory (call state table)    │
└─────────────────────────────────────────────────┘
```

### Key Design Decisions

1. **B2BUA, not proxy**: one inbound leg and one outbound leg, with the SDP fully rewritten to point at our own media ports, which delivers topology hiding and media security. sipgo provides the transaction and dialog layers; the B2BUA logic is our own (referencing diago).
2. **Runtime state in memory only**: for a single-node product, call state is never written to disk, and a process restart drops in-flight calls (the same as Kamailio's default). The configuration file is the only persistent state.
3. **Hot-reload semantics**: change → validate → atomic swap (`atomic.Pointer[Config]`) → new calls use the new configuration while in-flight calls are unaffected. A failed validation keeps the old configuration; the process never dies from a bad config.
4. **Shield plane implemented in the application**: per-IP rate limiting, scanner UA fingerprints, automatic ban on a failure threshold, an in-memory ban table, and optional nftables integration (`auto/on/off`). nftables is not a hard dependency (unlike libresbc).
5. **Media plane security (hardened latching)**: first-packet latching applies only before the media stream is established, and by default the first packet's source IP must match the signaling IP from the SDP (each peer can select `strict` or `loose` for hostile NAT). Once media is established there is **no re-latching**, which blocks RTP hijacking. **Arming semantics (confirmed 2026-07-15)**: initial media uses strict per-side arming — in strict mode a side **drops every packet** until the signaling plane arms it with the SDP source IP (preventing an attacker from claiming the early-media window, which would be hijacking plus DoS). Later media address changes (re-INVITE, hold/resume) can only be authorized by an explicit re-latch call (`Relatch`) from the SIP/SDP state machine, and the local port stays unchanged across re-INVITEs.

### Signaling Interop Baseline (MVP Mandatory)

The minimum required to interoperate with real carriers and PBXs; all of it is in the MVP:

- **Answer inbound OPTIONS**: carriers use OPTIONS as a trunk health check and will mark a silent trunk dead.
- **Session timers (RFC 4028)**: support `Session-Expires`/`Min-SE` negotiation and periodic refresh; many carriers require it.
- **100rel/PRACK pass-through**: correctly relay reliable provisional responses between the two legs (the carrier 183 early-media case).
- **Digest authentication client**: answer 401/407 challenges on outbound INVITE and REGISTER (using the peer's configured `auth` credentials).
- **Outbound REGISTER**: when a peer sets `register: true`, register with the carrier periodically (refresh before expiry, back off and retry on failure); a peer whose registration fails is marked unavailable and counted in metrics.
- **DNS SRV**: peer addresses support SRV resolution, with priority/weight results folded into the failover list; fall back to A/AAAA when there is no SRV record.

## 4. Module Layout

```
FreeSBC/
├── main.go                  # Entry point: flag parsing, startup orchestration
├── config/
│   ├── schema.go            # YAML structs + validation rules
│   └── reload.go            # fsnotify watch, atomic hot reload
├── sig/                     # Signaling plane
│   ├── server.go            # sipgo assembly (UDP/TCP/TLS), inbound OPTIONS replies
│   ├── b2bua.go             # Leg pairing, state machine, re-INVITE/BYE forwarding, PRACK pass-through, session timers
│   ├── routing.go           # Route match → gateway selection → failover (incl. DNS SRV resolution)
│   ├── auth.go              # Digest authentication client (401/407, shared by INVITE and REGISTER)
│   ├── register.go          # Outbound trunk registration state machine (periodic refresh, failure backoff)
│   ├── sdp.go               # SDP parsing and rewriting
│   └── normalize.go         # Number transformation (regex replacement)
├── media/
│   ├── portpool.go          # RTP port pool allocation and release
│   ├── relay.go             # UDP forwarding engine (one goroutine pair per call)
│   └── srtp.go              # SRTP↔RTP (pion/srtp)
├── shield/
│   ├── ratelimit.go         # Per-IP token bucket
│   ├── scanner.go           # Scanner UA fingerprint database
│   ├── banlist.go           # In-memory ban table + optional nftables integration
│   └── acl.go               # IP allowlist/blocklist
├── admin/
│   ├── api.go               # REST API (net/http, no framework)
│   ├── webui/               # Frontend static files (go:embed)
│   └── metrics.go           # Prometheus /metrics
└── callstate/               # In-memory call state table (API query / call teardown)
```

### Inter-Module Interfaces

1. **sig → media**: `media.Allocate(ctx) (Session, error)` — request a media session (two port pairs) on INVITE, and write the addresses into the rewritten SDP; `Session.Close()` releases them at the end. media knows nothing about SIP, and sig never touches media packets.
2. **sig → shield**: a sipgo middleware calls `shield.Check(srcIP, msg) Verdict` — every inbound request passes the shield plane first, which returns reject, silent drop, or allow.
3. **All modules → config**: read-only `config.Current()` returns a snapshot (a lock-free atomic dereference); a single call uses one snapshot throughout, which guarantees configuration consistency.

### Dependency List

`emiago/sipgo` (SIP stack), `pion/srtp` + `pion/rtp` (SRTP), `pion/sdp` (SDP), `fsnotify` (hot reload), `goccy/go-yaml` (configuration, preserves comments), `prometheus/client_golang` (metrics). No database, no Redis, no web framework.

## 5. Configuration File Shape and Routing Model

Design goal: a newcomer gets their first call working from a 20-line example. libresbc's five-layer reference model (interconnection / media class / capacity class / translation class / routing table) is flattened into three top-level concepts: **listen / peers / routes**.

```yaml
listen:
  sip:
    - udp://0.0.0.0:5060
    - tls://0.0.0.0:5061          # self-signed if no certificate is configured
  media:
    port_range: 16384-32768
    public_ip: auto                # auto = STUN discovery, or hard-code it

peers:
  carrier-a:
    address: sip.carrier-a.com:5060  # DNS SRV supported, falls back to A/AAAA
    transport: udp
    auth: { username: acct01, password: "${CARRIER_A_PASS}" }
    register: true                 # registration-based trunk: periodic REGISTER + digest auth
    allowed_ips: [203.0.113.0/24]  # inbound calls identify the peer by source IP
  internal-pbx:
    address: 10.0.0.10:5060
    allowed_ips: [10.0.0.0/8]

routes:
  - name: outbound
    from: internal-pbx
    match: { to: "^9(\\d+)$" }
    transform: { to: "$1" }
    to: [carrier-a]                # list order is the failover order
  - name: inbound
    from: carrier-a
    to: [internal-pbx]

shield:                            # sensible defaults; the whole block may be omitted
  rate_limit: 20/s per_ip
  auto_ban: { failures: 5, window: 60s, duration: 1h }
  nftables: auto

admin:
  listen: 127.0.0.1:8080
  auth: { username: admin, password_hash: "..." }
```

### Routing Semantics

- **Inbound identification**: the source IP matches a peer's `allowed_ips` → that determines `from`; no match is handed to shield (silent drop by default).
- **Matching**: `routes` are evaluated in order, and the first entry whose `from` and `match` regex both hit is used — no priority numbers.
- **Failover**: the `to` list is tried in order, moving to the next entry on 5xx or timeout; peers carry passive health checking (cooldown after consecutive failures) plus optional OPTIONS probing.
- **Transformation**: `transform` supports regex capture groups and is inline in the route, so nothing needs to be defined separately and then referenced.
- **Codec filtering**: the SDP codec list is filtered per peer configuration (purely an SDP-layer operation, no transcoding involved).

### WebUI and the Configuration File

The WebUI reads and writes the same YAML (`GET/PUT /api/config`: validate → write file → hot reload). Hand edits and WebUI edits are visible to each other. **Write-back strategy**: WebUI edits apply as structured PATCHes against the YAML AST (the `ast` package of goccy/go-yaml), touching only the target nodes instead of re-serializing the whole document, so comments and layout survive. `${ENV_VAR}` references are stored and returned verbatim; the expanded plaintext is **never** written back to disk.

## 6. Call Data Flow

```
1. INVITE arrives (carrier-a → :5060)
2. shield.Check(srcIP)            → rate limit / ban / ACL; silent drop on failure
3. Peer identification            → source IP ∈ carrier-a.allowed_ips
4. config.Current()               → take a config snapshot, bound to this call
5. routing.Match(from, to-number) → route hit → target peer
6. media.Allocate()               → allocate two RTP/RTCP port pairs (A and B sides)
7. SDP rewrite                    → the A leg answer SDP points at our A-side port
8. Build the B leg INVITE, SDP pointing at our B-side port
9. B leg answers → state machine bridges the legs (180/183/200 mapped back to the A leg)
10. Media flows both ways through the relay; first-packet latching: the actual source address of the far end's first RTP packet wins (NAT traversal; hardening rules in §3 key design decision 5)
11. BYE from either side → forwarded to the other → Session.Close() releases the ports → state table entry removed
```

re-INVITEs (hold, resume, codec change) are passed through with the SDP rewritten to match. The relay is payload-agnostic.

## 7. Error Handling

| Scenario | Behavior |
|------|------|
| Bad config (at startup) | Report the error and exit, naming the line number and cause |
| Bad config (hot reload) | Keep running on the old configuration, log it, raise a metrics alarm flag |
| All B leg failover targets failed | Return the last error code to the A leg (or a configurable fixed code) |
| Media ports exhausted | Reject the INVITE with 503, increment a metric |
| Panic inside a single call | Per-call goroutine recover: kill that call and release its resources; the process survives |
| Half-dead call (BYE lost) | RTP silence timeout (5 minutes by default) tears the call down automatically |
| Outbound REGISTER failure | Exponential backoff retry; the peer is marked unavailable (skipped by routing) and a metrics alarm is raised |

## 8. Test Strategy

- **Unit tests**: routing match and transform, SDP rewriting, shield verdicts (mostly pure functions).
- **SIP integration tests**: sipgo simulates a UAC and a UAS inside the test over real UDP loopback, covering the full state machine — setup, failover, re-INVITE, BYE.
- **Interop acceptance**: sipp scenario scripts against real FreeSWITCH and Asterisk endpoints in docker-compose, run in CI.
- **Media verification**: bidirectional relay send/receive plus packet-level SRTP end-to-end assertions.
- **Performance baseline**: **on Linux**, 1000 concurrent calls of RTP forwarding on one host at under 50% CPU (`SO_REUSEPORT` + `sendmmsg`/`recvmmsg` batch syscalls, a Linux-only optimization), used as a regression gate. darwin and windows builds take the ordinary send/receive path: fully functional, but with no performance commitment.

## 9. Non-Goals (Explicitly Excluded)

- Audio transcoding (G.729/AMR/opus conversion)
- Registration proxy / registrar — serving phone registrations (to be evaluated after the MVP; outbound trunk registration **is** in the MVP)
- DTLS-SRTP key negotiation (the MVP is SDES only)
- CDR (to be evaluated after the MVP)
- Distributed clustering / seamless failover
- K8s Operator
- Video / WebRTC gateway
