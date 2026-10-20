# FreeSBC

An open-source SIP/WebRTC edge proxy with the Caddy experience: **one binary, one YAML file, `./freesbc run`.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.27.2-00ADD8.svg)](go.mod)

- **Pure Go, one static binary, zero external dependencies**: no database, no Redis, no kernel modules, and **no external media process**.
- **Keeps your switch off the public internet**: FreeSBC is the only element with a public address. FreeSWITCH or Asterisk stays on a private LAN and only ever talks to FreeSBC.
- **Phones, browsers and carriers through one public address**: SIP/UDP, SIP/TCP and SIP/TLS phones, WS/WSS WebRTC browsers, and carriers (the switch uses FreeSBC as its outbound proxy).
- **Embedded WebUI, REST API and Prometheus metrics** behind a bcrypt-checked admin login (a login form for the WebUI, Basic Auth for the API and metrics).

## Install

```sh
curl -fsSL https://github.com/rasonyang/freesbc/releases/latest/download/install.sh | sh
```

Linux or macOS, amd64 or arm64. It installs the latest release in `/usr/local/bin` after checking it against the release's `SHA256SUMS`. Run as root on a systemd host, it also sets up the `freesbc` user, `/etc/freesbc` and the unit (not started), and prints the steps left to start the service ([details](docs/install.md#run-as-a-systemd-service)).

Then write a config and run it:

```sh
freesbc init  -c freesbc.yaml    # asks for the switch, detects the addresses
freesbc check -c freesbc.yaml    # validate; errors name the line and key
freesbc run   -c freesbc.yaml    # SIGINT/SIGTERM to stop
```

To read the script before it runs: `curl -fsSLo install.sh https://github.com/rasonyang/freesbc/releases/latest/download/install.sh; less install.sh; sh install.sh`.

Manual download and checksum, building from source, the systemd layout and the full `freesbc init` reference: [`docs/install.md`](docs/install.md).

> **Read before exposing to the public internet:** [`docs/design.md`](docs/design.md) (topology, security model) and [`docs/edge.md`](docs/edge.md) (switch-side requirements).

## How it fits together

```text
  Internet ──> FreeSBC  203.0.113.7   public: SIP/UDP/TCP/TLS, WS/WSS, RTP, WebRTC
                  │
                  │ private LAN/VPN: plain SIP/UDP + RTP
                  │ one fixed socket, 10.77.0.2:5060
                  v
              switch (FreeSWITCH / Asterisk)  10.77.0.10   no public IP, no port forward
                  │
                  └── carriers: the switch sends carrier traffic to FreeSBC as its outbound proxy
```

- **Clients.** REGISTER is proxied to the switch verbatim (the switch is the registrar; FreeSBC holds no credential) with the Contact rewritten to carry an `fsbc=` token. Calls to clients and from clients are proxied with FreeSBC on the path.
- **Carriers.** The switch owns carrier accounts, line selection and failover, and points each gateway at FreeSBC as outbound proxy. Requests to a host listed in `edge.carriers` are proxied to that carrier with the switch's private addresses hidden; inbound carrier requests are delivered to the switch's carrier port with an `X-FreeSBC-Carrier` header.
- **Topology hiding.** Every SDP body is constructed by FreeSBC, never copied from the other leg, and all media is anchored on FreeSBC ports. No SDP, Contact or Request-URI carries the switch's address to a public party, or the public party's address to the switch. Every public leg, client or carrier, also hides the switch in Via, Record-Route, Contact and identity headers; client legs additionally drop the switch's Server, User-Agent, Warning, `X-` and other `P-` headers. The Call-ID and the NOTIFY and MESSAGE bodies are the switch's own text and pass through, so set the switch to keep its name out of them: [switch-side requirements](docs/edge.md#switch-side-requirements).
- **Shield.** Per-IP rate limiting (separate limits for carrier sources) and scanner fingerprinting with an in-memory ban; every denial is a silent drop. FreeSBC touches no kernel firewall state. The private socket is trusted and exempt, so keep it unreachable from anywhere else.

Details: [`docs/edge.md`](docs/edge.md) (behaviour, switch-side requirements, limitations) and [`docs/design.md`](docs/design.md).

## Features

- **Edge proxy**: SIP/UDP, TCP, TLS, WS and WSS interworking in front of a private switch; REGISTER proxying; a multi-switch pool with per-user hashing.
- **Carrier path**: carrier directory by literal IP or DNS (SRV/A/AAAA, cached), switch-to-carrier proxying with topology hiding, inbound carrier delivery to the switch's carrier port, and deterministic carrier registration tokens.
- **Media anchoring**: RTP relay on FreeSBC ports with hardened first-packet latching and a silence watchdog; no transcoding.
- **WebRTC**: ICE-Lite, DTLS-SRTP and RTCP-mux terminated for browsers (any of `edge.listen.ws`/`wss`), relayed to plain RTP.
- **Built-in security**: per-IP rate limiting, scanner fingerprinting, in-memory bans, admission control for public INVITEs and REGISTER enumeration.
- **Embedded WebUI + REST API**: a live dashboard, a read-only config view with candidate validation and diff, Prometheus metrics, bcrypt admin login (form for the WebUI, Basic Auth for the API).

## Performance

One small cloud VM carries 5000 concurrent calls with media, 3500 call setups per second, and an 8 hour soak with zero failed calls and no memory growth.

### System under test

| | |
|---|---|
| FreeSBC host | cloud VM, Intel Xeon 6982P-C, **4 vCPU (2 cores + HT), 8 GiB**, Ubuntu 24.04 |
| FreeSBC | v0.5.0 (sipgo v1.6.0, Go 1.27.2), one process, `GOMEMLIMIT=6GiB` |
| Load generator | separate 8 vCPU host: SIPp 3.6.1 (UDP SIP, G.711 RTP) and `webrtcload` (ICE-Lite, DTLS-SRTP over ws/wss) |
| Switch | separate 8 vCPU host on a private network: SIPp UAS echoing RTP, or FreeSWITCH 1.10 |
| Media | G.711 20 ms in both directions, anchored by FreeSBC on both legs (public and private) |
| Pass line | under 0.1% failed calls, FreeSBC under 80% of its CPU, RTP sent = RTP received, no kernel receive drops |

### Results

| Test | Result |
|---|---|
| Concurrent calls with media | **5000** at 80% CPU, 500k packets/s each way, 373 MB RSS |
| A commercial SBC's published test: 1000 calls held 600 s | passes on **one vCPU**, about 120 MB RSS, 0 of 2000 calls failed, 0% RTP loss |
| Call setup rate (no media) | **3500 CPS** carrier to switch, **3250 CPS** switch to carrier, 2250+ CPS client to switch |
| Soak: 3500 concurrent calls for 8 hours | **432,000 calls, 0 failed**; goroutines, RSS, file descriptors and ports flat |
| Registrations | **19,000** held, **20,000+ REGISTER/s** at refresh using 13% of the CPU |
| WebRTC | 100+ DTLS handshakes/s, 600+ concurrent SRTP calls (limited by the generator, not FreeSBC) |
| With FreeSWITCH as the switch | 3000+ concurrent calls, 1500+ CPS (limited by FreeSWITCH) |
| Latency FreeSBC adds | **under 1 ms** |

A "+" marks a lower bound: the generator, the switch or the test range ran out before FreeSBC did. Method, profiles, sizing (memory follows the call rate: about 1.25 MB per sustained CPS) and the raw reports are in [docs/performance.md](docs/performance.md) and issue [#109](https://github.com/rasonyang/freesbc/issues/109); the harness to repeat it is in [test/perf/](test/perf/README.md).

## Documentation

- [`docs/install.md`](docs/install.md): install script, manual download, source build, systemd service, `freesbc init`
- [`docs/config.md`](docs/config.md): every key, default, validation rule and reload class
- [`docs/edge.md`](docs/edge.md): topology, behaviour, switch-side requirements, non-goals, known limitations
- [`docs/two-node.md`](docs/two-node.md): two independent FreeSBC nodes for failover and rolling restarts (carriers, switch, clients; FreeSWITCH and Asterisk examples)
- [`docs/homer.md`](docs/homer.md): mirror SIP signaling to a HOMER collector over HEP (setup, what is mirrored, security notes)
- [`docs/troubleshooting.md`](docs/troubleshooting.md): calls that connect and then drop (`call ended` reasons, lost ACK, RTP silence, session timers)
- [`docs/design.md`](docs/design.md): the design document, what the code does as implemented
- [`examples/switch/`](examples/switch/README.md): verified FreeSWITCH and Asterisk configurations for the reference topology
- [`freesbc.example.yaml`](freesbc.example.yaml): annotated example

## Admin & WebUI

Enable the optional `admin` block (a bcrypt `password_hash`; generate with `freesbc hash-password`; the user is always `admin`), then:

- browse `http://<admin.listen>/` (the login form, a cookie session; Basic Auth remains for `/metrics` and `/api/*`) for the live dashboard and the Config tab: the running file read-only, a candidate editor with Validate (the same checks as `freesbc check`, listing restart-only keys the candidate changes) and a line diff against the running file. The admin API never writes the config: edit the file, run `freesbc check -c freesbc.yaml`, and the watcher reloads it, as with nginx. Keep secrets as `${ENV}` references,
- the Audit tab (`GET /api/audit`) lists the last 256 admin events: sign-ins (first successful login, failed login, rate-limited), logouts and drain changes (`drain_on`, `drain_off`); `freesbc_admin_auth_failures_total` counts the failures. The source is the connecting address, so behind a reverse proxy it is the proxy's,
- the Health tab and header badge (`GET /api/health`, `GET /api/health/history`) show whether anything needs attention: a switch node cooling down, carrier DNS failing, the RTP pool at 90 % or more, the shield ban table at its cap, 2xx ACKs not coming back from one side (3 in 10 min), the TLS certificate under 30 days from expiry or expired, plus the last 200 raise and clear events (in memory; thresholds are fixed, alerting stays in Prometheus; `freesbc_admin_health_status` exposes the status as 0, 1 or 2),
- scrape `http://<admin.listen>/metrics` with Prometheus (`basic_auth` in the scrape config),
- set `admin.pprof: true` to also serve Go pprof under `http://<admin.listen>/debug/pprof/` behind the same auth (Basic Auth; off by default; restart-only),
- read live state from `/api/status` (including a `reload` object: restart-only keys pending and the last failed reload), `/api/calls`, `/api/health` (overall status and the active conditions), `/api/audit`, `/api/tls` (the loaded TLS certificate, its expiry and whether the file on disk has been renewed; also the Overview's TLS card, `freesbc_tls_cert_expiry_timestamp_seconds` and `freesbc_tls_cert_disk_differs`, and the `tls_cert_renewed` health condition) and `/api/config`, and the live tables `/api/registrations`, `/api/carrier-registrations`, `/api/shield/bans`, `/api/switch-nodes` and `/api/carriers` (read-only; the WebUI's State tab shows them), and check a candidate file with `POST /api/config/validate` (body: the YAML; response `{"valid", "errors", "restart_required"}`; it writes nothing),
- drain the node before a restart: `POST /api/drain` refuses new carrier calls (and carrier-facing OPTIONS) with `503` and `Retry-After: 30`, client calls still go through, while calls and registrations in place continue, `GET /api/drain` reports `active_calls`, `DELETE /api/drain` leaves drain mode (runtime state only; see [`docs/edge.md`](docs/edge.md) and, for a rolling restart of two nodes, [`docs/two-node.md`](docs/two-node.md)).

Bind the admin listener **private**. Validation rejects a non-loopback `admin.listen` unless `admin.allow_remote: true` is set, which also requires the top-level `tls` identity and then serves HTTPS. Read the security model section of [`docs/design.md`](docs/design.md) before setting it.

## Not in scope

FreeSBC does only what is necessary to make one switch on a private LAN safely reachable from the public internet. Anything the switch (FreeSWITCH or Asterisk) already does well, FreeSBC does not do.

A feature is in scope only if it passes one of these:

1. Only the edge can see or do it: the public wire before rewrite, TLS/WSS/WebRTC termination, NAT and latching, topology hiding, media anchoring, public-side admission, or FreeSBC's own state (sockets, ports, bindings, bans, reloads).
2. The switch cannot do it well from behind the edge.

Everything else stays on the switch; FreeSBC's contribution is a documented switch-side example (see [`examples/switch/`](examples/switch/README.md)), not a feature. Concrete examples that stay on the switch:

- Per-carrier and per-user concurrency and CPS limits: FreeSWITCH `limit`, `max-sessions`, `sessions-per-second`; Asterisk `GROUP()` / `GROUP_COUNT()`.
- Maximum call duration: FreeSWITCH `sched_hangup`; Asterisk `Dial` `L()` and `TIMEOUT(absolute)`.
- Toll-fraud protection: switch authentication plus dialplan rules.
- Call history and CDR: the switch's CDR and CEL.
- Call lifecycle events: the switch's event system.
- RTCP reporting to HOMER: the switch receives the relayed RTCP and can report it ([setup](docs/edge.md#rtcp-and-call-quality-in-homer)).
- Config version history: the operator's VCS.
- Editing the config through the admin API: edit the file, run `freesbc check`, and the watcher reloads it. Like nginx, there is no write API.

## Status & limitations

FreeSBC targets small and medium deployments on a single node; for failover, run two independent nodes ([`docs/two-node.md`](docs/two-node.md)). Measured capacity is in [Performance](#performance). Memory follows the sustained call rate rather than concurrent calls, because state outlives each call by up to 32 s (about 1.25 MB per sustained CPS; sipgo keeps each UDP transaction for its timers); size RAM and `GOMEMLIMIT` with [Memory, CPS and GOMEMLIMIT](docs/performance.md#memory-cps-and-gomemlimit). Method, caveats, profiles and the first bottlenecks are in [docs/performance.md](docs/performance.md); the rerunnable harness is in [test/perf/](test/perf/README.md).

Non-goals: transcoding, CDR, clustering, and being a registrar in its own right. The edge proxy proxies registrations to the switch rather than owning users or credentials.

- No transcoding; left to the switch.
- All state is in memory; a restart drops every call, dialog and binding.
- SDES-SRTP (`a=crypto`) is off unless `edge.srtp` or a carrier's `srtp` enables it, and then only over TLS/WSS signaling (or `edge.allow_insecure_sdes`); browser legs get DTLS-SRTP.
- Switches are UDP only (carriers may be udp, tcp or tls); switches are literal `IP:port`, with no DNS.
- Call-ID passes through the proxy unchanged, and so do the NOTIFY and MESSAGE bodies the switch writes (MWI, BLF); a switch that puts its own name in either leaks it, and the settings that decide those names are on the switch.
- No PUBLISH, and no TURN or full ICE.

See [known limitations](docs/edge.md#known-limitations) for the full list.

## Development

```sh
go vet ./...
go test ./... -race
```

The edge suite runs entirely on `127.0.0.1` and passes on macOS and Linux. See CLAUDE.md for per-package test ports and the opt-in FreeSWITCH interop test.

## Layout

```text
cmd/freesbc/          argv parsing, signal handling, exit codes
internal/
  app/                construction and lifecycle: builds every component and runs it
  config/             freesbc.yaml: parse, validate, hot reload
  sip/                SIP protocol primitives
  sip/sdp/            SDP subsystem (parse, codec negotiation, construction)
  edge/               SIP/RTP/WebRTC proxy between public parties and the switch
  media/              RTP/RTCP relay, port pools, WebRTC leg (ICE/DTLS/SRTP)
  shield/             per-IP rate limiting, scanner fingerprinting, in-memory bans
  admin/              operator HTTP API, Prometheus metrics, embedded WebUI
```

Everything is under `internal/`: the only consumer is `cmd/freesbc`, so no package here carries an API promise. Dependencies run one way: `cmd/freesbc -> app -> {edge, admin}`.

## License

Apache License 2.0. See [LICENSE](LICENSE).
