# FreeSBC

An open-source SIP/WebRTC edge proxy with the Caddy experience: **one binary, one YAML file, `./freesbc run`.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.27.3-00ADD8.svg)](go.mod)

- **One static Go binary, nothing else to run**: no database, no Redis, no kernel modules, and **no external media process**.
- **Keeps your switch off the public internet**: FreeSBC is the only element with a public address; FreeSWITCH or Asterisk stays on a private LAN and only ever talks to FreeSBC.
- **Phones, browsers and carriers through one public address**: SIP over UDP, TCP and TLS, WebRTC over WS/WSS, and carriers.
- **Built for the open internet**: per-IP rate limits, scanner fingerprinting, REGISTER brute-force and enumeration bans, and silent drops for calls from unregistered sources.
- **Embedded WebUI, REST API and Prometheus metrics** behind a bcrypt-checked admin login.

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

## Performance

Measured on one 4 vCPU / 8 GiB cloud VM running FreeSBC v0.5.0, with the load generator and the switch on separate hosts:

- **5000 concurrent calls with media** at 80% CPU (373 MB RSS); one vCPU passes a commercial SBC's published 1000-call test.
- **3500 CPS** carrier to switch (3250 switch to carrier).
- **8 hour soak** at 3500 concurrent calls: 432,000 calls, 0 failed, no growth.
- **19,000 registrations** held.
- **Under 1 ms** of added latency.

Method, all results, sizing and which figures are lower bounds: [docs/performance.md](docs/performance.md); the harness to repeat it: [test/perf/](test/perf/README.md).

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

- **Clients.** REGISTER goes verbatim to the switch, which is the registrar (FreeSBC holds no credential), and calls to and from clients are proxied with FreeSBC on the path; several switches form a pool hashed per user.
- **Carriers.** The switch owns carrier accounts and failover and uses FreeSBC as its outbound proxy to carriers listed by IP or DNS (SRV/A/AAAA, cached), with deterministic carrier registration tokens; inbound carrier calls reach the switch's carrier port tagged `X-FreeSBC-Carrier`.
- **Media.** Every stream is anchored on FreeSBC ports, with hardened first-packet latching, a silence watchdog and no transcoding; browser legs (ICE-Lite, DTLS-SRTP) are relayed to plain RTP.
- **Topology hiding.** FreeSBC builds every SDP itself and hides the switch from every public leg, but the Call-ID and NOTIFY and MESSAGE bodies are the switch's own text: see the [switch-side requirements](docs/edge.md#switch-side-requirements).
- **Trust.** Only the private socket is trusted and exempt from the shield, so keep it unreachable from anywhere else; bans live in memory and FreeSBC touches no kernel firewall state.

Details: [`docs/edge.md`](docs/edge.md) (behaviour, switch-side requirements, limitations) and [`docs/design.md`](docs/design.md).

## Documentation

- [`docs/install.md`](docs/install.md): install script, manual download, source build, systemd service, `freesbc init`
- [`docs/config.md`](docs/config.md): every key, default, validation rule and reload class
- [`docs/edge.md`](docs/edge.md): topology, behaviour, switch-side requirements, scope rule, non-goals, known limitations
- [`docs/two-node.md`](docs/two-node.md): two independent FreeSBC nodes for failover and rolling restarts (carriers, switch, clients; FreeSWITCH and Asterisk examples)
- [`docs/homer.md`](docs/homer.md): mirror SIP signaling to a HOMER collector over HEP (setup, what is mirrored, security notes)
- [`docs/performance.md`](docs/performance.md): method, all results, sizing (memory, CPS and `GOMEMLIMIT`), lower bounds
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

FreeSBC does only what is necessary to make one switch on a private LAN safely reachable from the public internet; anything the switch does well, it does not do ([scope rule](docs/edge.md#scope-rule)).

No transcoding, not a B2BUA, not a registrar, no clustering (for failover, run two independent nodes: [`docs/two-node.md`](docs/two-node.md)), and all state is in memory.

Details: [non-goals](docs/edge.md#non-goals) and [known limitations](docs/edge.md#known-limitations).

## Development

```sh
go vet ./...
go test ./... -race
```

The edge suite runs entirely on `127.0.0.1` and passes on macOS and Linux. See CLAUDE.md for per-package test ports and the opt-in FreeSWITCH interop test, and [`docs/design.md` §17](docs/design.md#17-package-ownership-map) for the package layout and what each package owns.

## License

Apache License 2.0. See [LICENSE](LICENSE).
