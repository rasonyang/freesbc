# FreeSBC

An open-source SIP/WebRTC edge proxy with the Caddy experience: **one binary, one YAML file, `./freesbc run`.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.27.2-00ADD8.svg)](go.mod)

- **Pure Go, one static binary, zero external dependencies**: no database, no Redis, no kernel modules, and **no external media process**.
- **Keeps your switch off the public internet**: FreeSBC is the only element with a public address. FreeSWITCH or Asterisk stays on a private LAN and only ever talks to FreeSBC.
- **Phones, browsers and carriers through one public address**: SIP/UDP, SIP/TCP and SIP/TLS phones, WS/WSS WebRTC browsers, and carriers (the switch uses FreeSBC as its outbound proxy).
- **Embedded WebUI, REST API and Prometheus metrics** behind bcrypt Basic Auth.

## Install

**Prebuilt binary**: each [release](../../releases) carries `freesbc_<version>_<os>_<arch>.tar.gz` for linux and darwin on amd64 and arm64, plus `SHA256SUMS`. Each archive holds the binary, this README, the license and `freesbc.example.yaml`:

```sh
v=v0.1.0 os=linux arch=amd64   # os: linux|darwin, arch: amd64|arm64
curl -LO https://github.com/rasonyang/freesbc/releases/download/$v/freesbc_${v}_${os}_${arch}.tar.gz
curl -LO https://github.com/rasonyang/freesbc/releases/download/$v/SHA256SUMS
shasum -a 256 -c --ignore-missing SHA256SUMS   # Linux: sha256sum -c --ignore-missing SHA256SUMS
tar -xzf freesbc_${v}_${os}_${arch}.tar.gz && cd freesbc_${v}_${os}_${arch}
./freesbc check -c freesbc.example.yaml
```

**From source**: requires Go >= 1.27.2:

```sh
go build -o freesbc ./cmd/freesbc
```

## Quick start

> **Read before exposing to the public internet:** [`docs/design.md`](docs/design.md) (networking and deployment topology, security model) and [`docs/edge.md`](docs/edge.md) (switch-side requirements).

```sh
cp freesbc.example.yaml freesbc.yaml   # then edit the addresses
./freesbc check -c freesbc.yaml        # validate; errors name the line and key
./freesbc run   -c freesbc.yaml
```

A minimal config (every key is documented in [`docs/config.md`](docs/config.md)):

```yaml
public:
  ip: 203.0.113.7            # advertised to phones, browsers, carriers
private:
  ip: 10.77.0.2              # faces the switch
edge:
  switch: [10.77.0.10:5060]  # the switch, literal IP:port
  listen:
    udp: 5060                # ports on public.bind
```

`freesbc.yaml` is gitignored since it may hold real addresses and a password hash. `-c` defaults to `freesbc.yaml`; a positional argument is a usage error.

The config file is watched. A `shield` edit is validated and applied atomically; a bad edit never takes down the process, because the previous config stays active and the error is logged. Everything else (addresses, `rtp`, `tls`, `edge`, `admin`) is read once at startup: a reload that edits it is logged as a warning listing the keys, and the running process keeps its startup values until restarted.

On SIGINT/SIGTERM FreeSBC drops its calls with their media released; no BYE is sent. A second SIGINT/SIGTERM exits at once.

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
- **Topology hiding.** Every SDP body is constructed by FreeSBC, never copied from the other leg, and all media is anchored on FreeSBC ports. A public party never gets the switch's address, and the switch never gets the public party's address in SDP, Contact or Request-URI.
- **Shield.** Per-IP rate limiting (separate limits for carrier sources) and scanner fingerprinting with an in-memory ban; every denial is a silent drop. FreeSBC touches no kernel firewall state. The private socket is trusted and exempt, so keep it unreachable from anywhere else.

Details: [`docs/edge.md`](docs/edge.md) (behaviour, switch-side requirements, limitations) and [`docs/design.md`](docs/design.md).

## Features

- **Edge proxy**: SIP/UDP, TCP, TLS, WS and WSS interworking in front of a private switch; REGISTER proxying; a multi-switch pool with per-user hashing.
- **Carrier path**: carrier directory by literal IP or DNS (SRV/A/AAAA, cached), switch-to-carrier proxying with topology hiding, inbound carrier delivery to the switch's carrier port, and deterministic carrier registration tokens.
- **Media anchoring**: RTP relay on FreeSBC ports with hardened first-packet latching and a silence watchdog; no transcoding.
- **WebRTC**: ICE-Lite, DTLS-SRTP and RTCP-mux terminated for browsers (any of `edge.listen.ws`/`wss`), relayed to plain RTP.
- **Built-in security**: per-IP rate limiting, scanner fingerprinting, in-memory bans, admission control for public INVITEs and REGISTER enumeration.
- **Embedded WebUI + REST API**: a live dashboard, a read-only config view with candidate validation and diff, Prometheus metrics, bcrypt Basic Auth.

## Documentation

- [`docs/config.md`](docs/config.md): every key, default, validation rule and reload class
- [`docs/edge.md`](docs/edge.md): topology, behaviour, switch-side requirements, non-goals, known limitations
- [`docs/design.md`](docs/design.md): the design document, what the code does as implemented
- [`freesbc.example.yaml`](freesbc.example.yaml): annotated example

## Admin & WebUI

Enable the optional `admin` block (a bcrypt `password_hash`; generate with `htpasswd -bnBC 10 "" 'your-password' | tr -d ':\n'`; the user is always `admin`), then:

- browse `http://<admin.listen>/` (HTTP Basic Auth) for the live dashboard and the Config tab: the running file read-only, a candidate editor with Validate (the same checks as `freesbc check`, listing restart-only keys the candidate changes) and a line diff against the running file. The admin API never writes the config: edit the file, run `freesbc check -c freesbc.yaml`, and the watcher reloads it, as with nginx. Keep secrets as `${ENV}` references,
- the Audit tab (`GET /api/audit`) lists the last 256 admin events: sign-ins (first successful login, failed login, rate-limited) and drain changes (`drain_on`, `drain_off`); `freesbc_admin_auth_failures_total` counts the failures. The source is the connecting address, so behind a reverse proxy it is the proxy's,
- scrape `http://<admin.listen>/metrics` with Prometheus (`basic_auth` in the scrape config),
- read live state from `/api/status`, `/api/calls`, `/api/audit` and `/api/config`, and check a candidate file with `POST /api/config/validate` (body: the YAML; response `{"valid", "errors", "restart_required"}`; it writes nothing),
- drain the node before a restart: `POST /api/drain` refuses new calls with `503` and `Retry-After: 30` while calls and registrations in place continue, `GET /api/drain` reports `active_calls`, `DELETE /api/drain` leaves drain mode (runtime state only; see [`docs/edge.md`](docs/edge.md)).

Bind the admin listener **private**. Validation rejects a non-loopback `admin.listen` unless `admin.allow_remote: true` is set, which also requires the top-level `tls` identity and then serves HTTPS. Read the security model section of [`docs/design.md`](docs/design.md) before setting it.

## Not in scope

FreeSBC does only what is necessary to make one switch on a private LAN safely reachable from the public internet. Anything the switch (FreeSWITCH or Asterisk) already does well, FreeSBC does not do.

A feature is in scope only if it passes one of these:

1. Only the edge can see or do it: the public wire before rewrite, TLS/WSS/WebRTC termination, NAT and latching, topology hiding, media anchoring, public-side admission, or FreeSBC's own state (sockets, ports, bindings, bans, reloads).
2. The switch cannot do it well from behind the edge.

Everything else stays on the switch; FreeSBC's contribution is a documented switch-side example, not a feature. Concrete examples that stay on the switch:

- Per-carrier and per-user concurrency and CPS limits: FreeSWITCH `limit`, `max-sessions`, `sessions-per-second`; Asterisk `GROUP()` / `GROUP_COUNT()`.
- Maximum call duration: FreeSWITCH `sched_hangup`; Asterisk `Dial` `L()` and `TIMEOUT(absolute)`.
- Toll-fraud protection: switch authentication plus dialplan rules.
- Call history and CDR: the switch's CDR and CEL.
- Call lifecycle events: the switch's event system.
- RTCP reporting to HOMER: the switch receives the relayed RTCP and can report it.
- Config version history: the operator's VCS.
- Editing the config through the admin API: edit the file, run `freesbc check`, and the watcher reloads it. Like nginx, there is no write API.

## Status & limitations

FreeSBC targets small and medium deployments on a single node. The repo carries no benchmarks and no load-test harness.

Non-goals: transcoding, CDR, clustering, and being a registrar in its own right. The edge proxy proxies registrations to the switch rather than owning users or credentials.

- No transcoding; left to the switch.
- All state is in memory; a restart drops every call, dialog and binding.
- SDES-SRTP (`a=crypto`) is off unless `edge.srtp` or a carrier's `srtp` enables it, and then only over TLS/WSS signaling (or `edge.allow_insecure_sdes`); browser legs get DTLS-SRTP.
- Switches are UDP only (carriers may be udp, tcp or tls); switches are literal `IP:port`, with no DNS.
- Call-ID passes through the proxy unchanged.
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
