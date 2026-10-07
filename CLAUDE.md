# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

- Build the only binary: `go build -o freesbc ./cmd/freesbc` (`/freesbc` is gitignored). Set the version with `-ldflags "-X main.version=<v>"` (default `dev`).
- Release: `.github/workflows/release.yml` runs on pushed `v*` tags, or by hand with a `tag` input to backfill one. It builds `CGO_ENABLED=0 -trimpath` binaries for linux/darwin x amd64/arm64, packages `freesbc_<tag>_<os>_<arch>.tar.gz` (binary, README, LICENSE, `freesbc.example.yaml`) with `SHA256SUMS`, runs `check` on the linux/amd64 build, and uploads to the release with `gh`.
- Vet: `go vet ./...`. There is no linter config or Makefile; `gofmt -l .` and `go mod tidy -diff` are clean and CI keeps them so.
- CI (`.github/workflows/ci.yml`, on push to main and PRs): gofmt, `go mod tidy -diff`, vet, build, `check` on `freesbc.example.yaml`, `go test -race ./...`, and govulncheck (pinned v1.8.0, `GOTOOLCHAIN=local`). `soak.yml` runs nightly and on demand: the suite under `-race -count=N` and each `Fuzz*` target for `-fuzztime`. A new fuzz target must be added to its matrix.
- Tests (as the README runs them): `go test ./... -race`. One package: `go test -race ./internal/config`. One test: `go test ./internal/app -run '^TestCheckExamples$' -count=1 -v`.
- No build tags. The edge suite is mostly integration tests over real loopback sockets (real sipgo transports and RTP sockets), not mocks.
- CLI: `freesbc run|check [-c file]`. `-c` defaults to `freesbc.yaml`; a positional argument is a usage error (exit 2), so always pass `-c`.
- Example config: `./freesbc check -c freesbc.example.yaml` passes (`TestCheckExamples` guards this). `check` only parses and validates: it does not test that addresses are local, open cert files or bind sockets. `run -c freesbc.example.yaml` exits 1 because `203.0.113.7` and `10.77.0.2` are not local addresses, so adapt them before `run`. The local copy `/freesbc.yaml` is gitignored.
- Opt-in live FreeSWITCH interop. It skips unless `FREESBC_FS_INTEROP=1` and shells out to `/usr/local/freeswitch/bin/fs_cli`, so run it on the FreeSWITCH host:
  `FREESBC_FS_INTEROP=1 FREESBC_FS_ADDR=<fs-ip>:5060 FREESBC_FS_LOCAL=<this-host-ip> FREESBC_FS_USER=1000 FREESBC_FS_PASS=<pw> go test ./internal/edge/ -run TestFreeSWITCH -v`

## Architecture

One process, one YAML file, one SIP plane: the **edge** (`internal/edge`), a stateful SIP proxy (not a B2BUA) between public endpoints and a SIP switch (FreeSWITCH or Asterisk) on a private LAN. There are three kinds of far end: registered clients (SIP/UDP phones, WS/WSS WebRTC browsers), carriers, and the switch. Every key is documented in `docs/config.md`.

- Addresses are written once: `public.ip` (advertised), `public.bind` (local bind, default `public.ip`; differs only behind 1:1 NAT), `private.ip` (bind = advertised). Wildcards are rejected. `run` checks both bind IPs are assigned to a local interface; `check` does not.
- Public sockets (`edge.listen.udp|ws|wss`) bind on `public.bind`. The private side is one fixed UDP socket, `private.ip:5060` (`config.PrivateSIPPort`), carrying all SIP to and from the switch. The switch is `edge.switch` (literal `IP:port`, UDP, one entry or a hash-user pool) and is trusted only on that socket.
- Call-ID, tags and CSeq pass through, and the proxy stays on the path with RFC 5658 double Record-Route. The switch is the registrar: REGISTER and its digest are forwarded verbatim and FreeSBC holds no credentials, for clients or carriers.
- Dependencies run one way: `cmd/freesbc -> app -> {edge, admin}`. `edge` imports only `config`, `media`, `shield`, `sip` and `sip/sdp`. `config`, `media`, `sip` and `sip/sdp` import nothing from this module. `admin` reads the plane only through `admin.Deps` closures built in `app`.

### Signaling and media
- Signaling uses `emiago/sipgo` v1.4.3 for transactions and retransmission, with one user agent, listener set and `shield.Shield` per process. `internal/sip` holds shared RFC 3261 primitives with no policy.
- Media (`internal/media`) knows nothing about SIP. Every stream is anchored on SBC ports, with no pass-through and no transcoding. There are two `PlanePool`s over the one `rtp` range (default `20000-29999`): public bound to `public.bind`, private to `private.ip` (`AllocateAcross`). Browser legs use `WebRTCLeg`: ICE-Lite plus DTLS-SRTP on pion ice/dtls/srtp, no `PeerConnection`, with a per-process self-signed DTLS identity. The edge never reads or offers `a=crypto`, and rejects an answer that renumbers payload types (`sdp.ErrRenumbered`).
- First-packet latching (strict or loose) and a silence watchdog (5 min, constant `rtpSilenceTimeout`). The watchdog is the only automatic reclaim for a confirmed call whose BYE was lost.
- SDP: the edge builds every body from scratch with `internal/sip/sdp` (`Build`) and never copies the other leg's body; that is what guarantees topology hiding.

### Call flow
- Edge INVITE (`onInvite`, `invite.go`):
  1. A public out-of-dialog INVITE must pass admission (`admitPublicInvite`, `admission.go`): its source is the exact transport + IP:port of a live registration (`Location.HasSource`) or a carrier source. Otherwise it is dropped with no response. A source that is both counts as the registration.
  2. A To-tag makes it a re-INVITE.
  3. Arrival on the private socket (`inbound.private()`) is a switch request, classified by Request-URI by `classifySwitchRequest` (`carrier.go`): an `fsbc=` token (in the Request-URI or topmost remaining Route) is a client (unknown token: 404), a Request-URI `host[:port]` equal to an `edge.carriers` entry is a carrier (REGISTER, INVITE, OPTIONS; other methods 405), anything else is 404. There is no AoR fallback and FreeSBC is never an open relay for the switch.
  4. An admitted public INVITE goes to a switch node chosen by an FNV-1a hash of the user (`inviteToUpstream`).
- REGISTER from clients is always forwarded, except that a public source (IPv4 address, IPv6 /64) with 10 distinct AoRs rejected 403/404 in 10 minutes has further REGISTERs dropped silently until the window ends (`enumLimiter`, `admission.go`). Drops of both kinds count in `freesbc_edge_admission_drops_total{reason}`.
- Edge handlers return after the final response. From then on `dialogTable` owns the dialog and its media; a dialog is matched on Call-ID plus both tags and is confirmed before its 2xx is relayed.

### Carrier path
- The switch uses FreeSBC as its outbound proxy for carriers; carrier accounts, line selection and failover live on the switch. `edge.carriers` (name -> `host[:port]`) is an allowlist the switch's Request-URI must equal. A DNS name without a port resolves through SRV then A/AAAA, with a port through A/AAAA only; the directory (`carrierdns.go`) caches 300 s (10 s negative), keeps the last good set and uses the first address.
- Switch to carrier (`carrier.go`, `carrierreg.go`): proxied, Request-URI never changed, 401/407 untouched. Topology hiding is on carrier legs only (`hide.go`): FreeSBC's public Via and Record-Route, no foreign Route, no switch Via/Contact, identity-header hosts equal to `private.ip` or a switch IP masked to `public.ip`. Both SDPs are built by FreeSBC and media is anchored on both legs. A carrier REGISTER's Contact is rewritten to `sip:<user>@public.ip:<port>;fsbc=<token>`, the token being sha256 over node and original Contact (deterministic, so the Contact stays stable across a restart; the binding table itself is in memory), and restored on the response; the binding lives for the granted expiry.
- Carrier to switch: admitted only from carrier sources (resolved `carriers` addresses plus `edge.carrier_sources`), delivered to `<node IP>:edge.switch_carrier_port` (default: the node's switch port), never to the client port. A Request-URI token routes to the registering node with the Request-URI restored to the original Contact; no token hashes the Request-URI user across the pool. `X-FreeSBC-Carrier: <name>` (or `unknown`) is added. Every `X-FreeSBC-*` header arriving on a public socket is stripped first.
- Switch-side rules (documented in `docs/edge.md`): never trust or identify a request by FreeSBC's IP on the client port, and restrict the carrier port to `private.ip`.

### Config model
- `config.Parse` runs in this order: strict YAML (unknown keys are errors), `${VAR}` expansion of string values, defaults, then `validate` (`validate.go`), which joins all errors. Expansion runs after unmarshal, so parse errors never echo a secret, and expanded values are never written back.
- `config.Store` publishes immutable `*Config` snapshots through an atomic pointer. Code reads `store.Current()` at the point of use, once per unit of work, and passes that snapshot down. Never mutate a snapshot. `config.Watch` (fsnotify on the parent directory, 200 ms debounce) is the only caller of `Store.Replace`, and a bad file keeps the previous snapshot. Admin `PUT /api/config` only writes the file atomically and lets the watcher reload it.
- Only `shield.*` is hot. Everything else (`public`, `private`, `rtp`, `tls`, every `edge` key, `admin`) is restart-only. A reload that edits a restart-only setting is still published, with a warning listing the keys (`config.RestartOnlyChanges`, `internal/config/restart.go`; keep its table in step with `docs/design.md` §4.4 and `docs/config.md`). `edge.Server` keeps the snapshot it was built from (`boot`) and reads restart-only settings only from it.
- The edge does no DNS for switches, so `edge.switch` entries are literal `IP:port`; carriers resolve on the public side only.
- Test seams: `edge.WithPrivateAddr(netip.AddrPort)` overrides the fixed `private.ip:5060` so tests can run public and private on 127.0.0.1; `app` has an unexported `testHookEdgeOptions`.

### Security boundaries
- The edge installs a sipgo transport read filter (`internal/sip/readfilter.go`) that runs before parsing. It caps reads at 24 KiB (`fsip.MaxReadSize`; stream transports are also bounded by sipgo's 64 KiB `ParseMaxMessageLength`), drops public reads from shield-banned sources (no switch exemption: the switch does not use a public listener) and charges the per-source rate token (`Shield.AllowRate`, once per UDP datagram or WS/WSS frame, parsable or not; `guard` only runs `Shield.CheckScanner`, so a request costs one token), and on the private socket admits only `edge.switch` IPs and stamps each request with an internal `X-FreeSBC-Arrival` header (per-process secret plus the socket) in a new byte slice. `guard` strips every `X-FreeSBC-*` header first, on every transport, and hands handlers `inbound{src, arr}`; a missing or forged marker means public. Trust is keyed on the local socket alone, never on a source address (`edge/arrival.go`). A filter must never return an error, because sipgo treats that as fatal to the read loop; reject by returning `nil, nil`.
- Shield denials are silent drops. Public sources use `shield.rate_limit`; carrier sources use `shield.carrier_rate_limit` and are never banned as scanners. A UDP scanner verdict bans only the source socket (at most a minute), since datagram sources are forgeable. Bans are in memory only; there is no unban API and no kernel firewall backend. The admin call list, call count, port usage and listeners come from the edge; there is no kick API.
- The private socket is trusted and exempt from the shield.
- Admin (`admin:` section, restart-only) uses bcrypt Basic Auth (cost >= 10, user always `admin`) and is loopback-only unless `admin.allow_remote: true`, which requires the top-level `tls`. `GET /api/config/raw` is unredacted on purpose.

### sipgo v1.4.3 workarounds (re-check when upgrading sipgo)
- Listeners bypass `ListenAndServe*`, whose unsynchronised close is flagged by `-race` on every shutdown.
- `edge.New` raises the process-wide `sip.UDPMTUSize` to 8192.
- sipgo logs a failed parse at Error with the raw message as `data` (and an error built from it). `sipgoHandler` (`internal/edge/sipgolog.go`) wraps every sipgo logger, matches the message `failed to parse`, and rewrites it (length and reason only, Debug, `freesbc_sip_parse_failures_total`, one Warn per minute). Brittle on the string: `TestSipgoParseFailureLogContract` fails if a sipgo upgrade changes it.

`docs/design.md` describes the code as implemented, with file:line citations: §4 lifecycle/reload, §6 carrier path, §7 edge, §8 media, §11 concurrency, §14 security, §15.2 all timeouts, §17 package ownership. `docs/config.md` is the configuration reference; `docs/edge.md` has the switch-side requirements, non-goals and known limitations; `docs/admin-ui.md` has the WebUI's design tokens and rules (shadcn tokens in `internal/admin/webui/assets/tokens.css`, no inline script or style, API strings via `textContent`).

## Test environment gotchas

- The edge suite runs on 127.0.0.1 with the private socket moved by `WithPrivateAddr`, and passes on macOS. `TestAuditMED006LooseLatchFirstPacketHijack` (media) binds 127.0.0.2 and skips, not fails, when it is missing. Fix with `sudo ifconfig lo0 alias 127.0.0.2 up` (not persistent), or run in Linux: `docker run --rm -v "$PWD":/src -w /src golang:1.27.1 go test -race -count=1 ./...`.
- Test ports: each package owns a disjoint band, all below 32768 (the start of Linux's ephemeral range, so the kernel never hands a test's fixed port to a client socket; macOS's starts at 49152). Keep new test ports inside the package's band:

  | Band | Package | How ports are chosen |
  |---|---|---|
  | 10000-10099 | app | kernel-assigned SIP ports with retry on a bind collision; fixed media range |
  | 10100-10199 | admin | fixed (`TestAdminServesTLS`); other admin tests listen on `:0` |
  | 20000-24999 | media | fixed per test |
  | 25000-27999 | edge SIP | `nextPort`: probed free, cursor wraps |
  | 28000-32399 | edge media | `nextMediaBase`: a 400-port window per harness, every port probed free, cursor wraps |

  Packages can therefore run in parallel inside one `go test ./...`, and `-count=N` works. Two concurrent runs of the same package (for example from two checkouts) still collide on the fixed media and admin ports.
- Many edge tests carry the comment "Timing-based over real UDP loopback: re-run once before treating a flake as failure". Before calling a failure a regression, re-run the single test with `-run '^TestName$' -count=1` and compare against a baseline checkout run sequentially, not concurrently.
- `WARN UDP ref went negative on try close` lines come from sipgo v1.4.3 (`sip/transport_udp.go`, logged without returning an error) and are not test failures.
