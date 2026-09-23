# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

- Build the only binary: `go build -o freesbc ./cmd/freesbc` (`/freesbc` is gitignored). Set the version with `-ldflags "-X main.version=<v>"` (default `dev`).
- Vet: `go vet ./...`. There is no linter config, Makefile or CI; `gofmt -l .` is currently clean.
- Tests (as the README runs them): `go test ./... -race`. One package: `go test -race ./internal/config`. One test: `go test ./internal/app -run '^TestCheckExamples$' -count=1 -v`.
- No build tags. The trunk and edge suites are mostly integration tests over real loopback sockets (real sipgo transports and RTP sockets), not mocks.
- CLI: `freesbc run|check [-c file]`. `-c` defaults to `sbc.yaml` and positional arguments are ignored, so always pass `-c`.
- Example configs: `CARRIER_A_PASS=x ./freesbc check -c sbc.example.yaml` and `./freesbc check -c edge.example.yaml` both pass (`TestCheckExamples` guards this; without `CARRIER_A_PASS` the trunk example fails with "undefined environment variable(s)").
- `check` only parses and validates; it does not open cert files or bind sockets. `run -c edge.example.yaml` exits 1 on the missing `/etc/freesbc/wss-cert.pem`, so adapt addresses and cert paths before `run`. Of the config copies, only `/sbc.yaml` is gitignored; `edge.yaml` (the README's name for the edge copy) is not.
- Opt-in live FreeSWITCH interop. It skips unless `FREESBC_FS_INTEROP=1` and shells out to `/usr/local/freeswitch/bin/fs_cli`, so run it on the FreeSWITCH host:
  `FREESBC_FS_INTEROP=1 FREESBC_FS_ADDR=<fs-ip>:5060 FREESBC_FS_LOCAL=<this-host-ip> FREESBC_FS_USER=1000 FREESBC_FS_PASS=<pw> go test ./internal/edge/ -run TestFreeSWITCH -v`
- `test/interop/` contains no Go code: SIPp scenarios and an `sbc.yaml` for manual trunk runs against FreeSWITCH. The topology and SIPp flags are in the header comments of those files.

## Architecture

One process and one YAML file run two independent SIP planes, either or both. `internal/app/app.go` refuses to start if neither is configured.

- **Trunk** (`internal/trunk`): a B2BUA for carrier/PBX interconnect over UDP/TCP/TLS. It is on when `peers:` is non-empty. Each leg gets its own Call-ID, From-tag, Via and Contact. Peers are identified only by transport source IP against `allowed_ips`. `routes` do regex matching, number transforms and ordered failover. DNS/SRV exists only on this plane.
- **Edge** (`internal/edge`): a stateful SIP proxy, not a B2BUA, for SIP/UDP phones and WS/WSS/WebRTC browsers in front of FreeSWITCH. It is on when `sip.upstream.address` or `sip.upstreams.nodes` is set. Call-ID, tags and CSeq pass through, and the proxy stays on the path with RFC 5658 double Record-Route. FreeSWITCH is the registrar: REGISTER and its digest are forwarded verbatim, and FreeSBC holds no credentials.
- **FreeSWITCH** sits on a private LAN. It is reached only over UDP, from `sip.private.bind`, at a literal `IP:port` (the edge plane does no DNS). SDP, Contact and the Request-URI never give it a public client's address and never give clients its address. It does see the client's address in Via `received=`.
- Dependencies run one way: `cmd/freesbc → app → {trunk, edge, admin}`. `trunk` and `edge` never import each other and share only `config`, `media`, `shield`, `sip` and `sip/sdp`. `config`, `media`, `sip` and `sip/sdp` import nothing from this module. `admin` reads the planes only through `admin.Deps` closures built in `app`.

### Signaling and media planes
- Signaling uses `emiago/sipgo` v1.4.3 for transactions and retransmission. Each plane has its own sipgo user agent, listeners and `shield.Shield`. `internal/sip` holds shared RFC 3261 primitives with no policy.
- Media (`internal/media`) knows nothing about SIP; the planes pass it addresses, latch modes and SRTP keys. Every stream is anchored on SBC ports. There is no media pass-through and no transcoding.
  - Trunk: one `PlanePool`. `Allocate` binds 2 RTP/RTCP pairs (4 ports) per call. SDES SRTP is terminated and re-originated per leg, following each peer's `srtp:` policy.
  - Edge: separate `rtp.public` and `rtp.private` pools (`AllocateAcross`). Browser legs use `WebRTCLeg`: ICE-Lite plus DTLS-SRTP built on pion ice/dtls/srtp, with no `PeerConnection`. The edge plane never reads or offers `a=crypto`, and rejects an answer that renumbers payload types (`sdp.ErrRenumbered`).
  - Media uses first-packet latching (strict or loose) and a silence watchdog (`listen.media.rtp_timeout`, default 5m). The watchdog is the only automatic reclaim for a confirmed call whose BYE was lost.

### Call flow
- Trunk INVITE: the pre-parse read filter drops bytes from non-peer IPs, then `withShield`, peer identification, the call quota and routing run. `onInvite` (`b2bua.go`) allocates media once and dials targets in failover order. It then blocks in a `select` for the whole call, until either leg ends, media reports `Done`, or the admin API calls `KillCall`.
- Edge INVITE (`onInvite` in `invite.go`) is classified in this order:
  1. A To-tag makes it a re-INVITE.
  2. An upstream source with a Request-URI equal to `sip.pstn.match` goes to a PSTN gateway.
  3. Arrival on the private socket goes to a registered client. The client is found by the `fsbc=` token that FreeSWITCH copies from the stored Contact into the Request-URI.
  4. Anything else goes to an upstream chosen by an FNV-1a hash of the user.
- Edge handlers return after the final response. From then on `dialogTable`, keyed by Call-ID alone, owns the dialog and its media.
- SDP: the edge builds every body from scratch with `internal/sip/sdp` (`Build`) and never copies the other leg's body. That is what guarantees topology hiding. The trunk edits the peer's body in place with `pion/sdp` directly (not the bounded `sdp` parser) and strips inbound `a=crypto`.

### Config model
- `config.Parse` runs in this order: strict YAML (unknown keys are errors), `${VAR}` expansion, defaults, then `validate`, which joins all errors. Expansion runs after unmarshal, so parse errors never echo a secret, and expanded values are never written back. Validation rules are in `validate.go` (trunk, shield, admin) and `validate_proxy.go` (edge).
- `config.Store` publishes immutable `*Config` snapshots through an atomic pointer. Code reads `store.Current()` at the point of use (the trunk takes one snapshot per call; media pools read it per allocation) and never mutates a snapshot. `config.Watch` (fsnotify on the parent directory, 200 ms debounce) is the only caller of `Store.Replace`, and a bad file keeps the previous snapshot. Admin `PUT /api/config` only writes the file atomically and lets the watcher reload it.
- Hot vs restart-only settings are tabulated in `docs/design.md:337-345`. Restart-only includes the listener set, TLS certificates and outbound per-peer TLS material, the edge topology (upstreams, PSTN, `webrtc`), the trunk dialog-cache Contact, the nftables mode, `admin.listen`/`tls_cert`/`tls_key` and whether an `admin:` section exists (`admin.auth` itself hot-reloads).
- `check` is weaker than `run` for edge addresses: validation accepts any `host:port` for upstreams and PSTN gateways (`checkHostPort`, `validate_proxy.go:366-379`), but `run` rejects a hostname (`parseEndpoint`, `edge/topology.go:126-134`). Use literal `IP:port`.
- A trunk listener (`listen.sip` or `sip.bind_ip`) with no `peers` is a validation error (`validate_proxy.go:41-43`), so edge-only configs must omit it.

### Security boundaries
- Both planes install a sipgo transport read filter (`internal/sip/readfilter.go`) that runs before parsing. The trunk filter admits only peer IPs. The edge filter caps reads at 64 KiB and, on the private bind, admits only upstream IPs. A filter must never return an error, because sipgo treats that as fatal to the read loop; reject by returning `nil, nil`.
- Shield denials are silent drops. The trunk overrides `onNoRoute` so that non-peer sources get silence instead of a 405.
- The edge private plane is trusted and exempt from the shield. Only the trunk shield manages nftables (the edge uses `shield.NewNoKernel`). The admin call list, kick, unban and shield metrics are wired to the trunk plane only.
- Admin uses bcrypt Basic Auth (cost ≥ 10) and is loopback-only unless `admin.allow_remote: true` is set. `GET /api/config/raw` is unredacted on purpose.

### sipgo v1.4.3 workarounds (re-check when upgrading sipgo)
- Listeners bypass `ListenAndServe*`, whose unsynchronised close is flagged by `-race` on every shutdown.
- `DialogServerCache.ReadInvite` is single-use, so trunk in-dialog refreshes are answered on the raw transaction.
- `edge.New` raises the process-wide `sip.UDPMTUSize` to 8192, which also changes the trunk plane.

`docs/design.md` describes the code as implemented, with file:line citations: §4 lifecycle/reload, §6 trunk, §7 edge, §8 media, §11 concurrency, §14 security, §15.2 all timeouts, §17 package ownership. `docs/edge.md` and the README section "Status & limitations" list the non-goals and known limitations.

## Test environment gotchas

- 20 tests need loopback addresses that macOS does not configure (Linux routes all of 127/8):
  - trunk: `TestPreParseFilterDropsNonPeerBytes`, `TestPreParseFilterAllowsPeerBytes` (which also binds 127.0.0.9), `TestRefreshReInviteWrongTagsGet481`, and `TestBridgeNATBindAdvertisedTopology` (which fails only after a ~32 s Timer_B);
  - edge: 16 of the 17 `TestPSTN*` tests, whose fake FreeSWITCH binds 127.0.0.2 (`TestPSTNUnconfiguredFallsBackTo404` is unaffected).

  Fix with `sudo ifconfig lo0 alias 127.0.0.2 up` and `sudo ifconfig lo0 alias 127.0.0.9 up` (not persistent), or run in Linux: `docker run --rm -v "$PWD":/src -w /src golang:1.25.7 go test -race -count=1 ./...`.
- Test ports are fixed, not ephemeral:
  - Trunk tests hard-code SIP/RTP ports in 45xxx–46xxx (for example 45070). `TestKillCallTearsDownBothLegs` also binds `127.0.0.1:5070`, the port `test/interop/sbc.yaml` listens on.
  - Media tests use fixed pools in 20000–20100, 40000–40517 and 41xxx.
  - The edge harness probes SIP ports in 24000–44999 and skips busy ones (`nextPort`), but its media windows are unprobed: 400 ports per harness on 127.0.0.1 starting at 45000, which overlaps trunk's 45xxx–46xxx.

  As a result, packages running in parallel inside one `go test ./...` can collide (edge media vs trunk ports), two concurrent runs (for example from two checkouts) collide, and `go test ./internal/edge -count=2` always fails in its second pass (`rtp.*.port_max: must be 1024-65535`).
- Most trunk call tests use a 4-port `port_range`, which fits exactly one call. A session released late can show up as `media: RTP port range exhausted`, a 503 from `pool.Allocate`, or "carrier dialog never ended". Many of these tests carry the comment "Timing-based over real UDP loopback: re-run once before treating a flake as failure". Before calling a failure a regression, re-run the single test with `-run '^TestName$' -count=1` and compare against a baseline checkout run sequentially, not concurrently.
- `WARN UDP ref went negative on try close` lines come from sipgo v1.4.3 (`sip/transport_udp.go`, logged without returning an error) and are not test failures.
