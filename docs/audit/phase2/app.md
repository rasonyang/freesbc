# Phase 2 — internal/app and cmd/freesbc

Scope: `internal/app/app.go` (233 lines), `internal/app/app_test.go`, `cmd/freesbc/main.go`.
Method: reading only, plus `go vet ./internal/app ./cmd/freesbc` (clean) and `go list` imports. `go test` was not run here.
All findings are INFERENCE unless marked otherwise.

## Findings

### P2-APP-001: trunk calls are not torn down when `app.Run` shuts down
- Severity: P1 | Layer: config/lifecycle | INFERENCE | Action: fix
- Location: `internal/app/app.go:137-139`; `internal/trunk/server.go:302-319`; `internal/trunk/b2bua.go:459-484`
- Evidence: after `<-gctx.Done()`, `app.Run` returns `g.Wait()`. The trunk member (`sipServer.Run`) returns after `regCancel(); <-regDone; listenCancel(); wg.Wait()` (server.go:307-312). `wg` counts only the listener goroutines. Nothing iterates `s.calls` on shutdown: the only `range s.calls` is in `Calls()` (calls.go:205). Each `onInvite` goroutine stays blocked in
  `select { case <-c.aLeg.Context().Done() ... case <-c.bLeg.Context().Done() ... case <-c.sess.Done() ... case <-killCtx.Done() }`,
  and `killCtx` is rooted at `context.Background()` (b2bua.go:459). The edge plane, by contrast, calls `s.dialogs.closeAll()` on shutdown (docs/design.md:385-387).
- Consequence: `app.Run` returns while trunk call goroutines, their `media.Session` sockets and their `PlanePool` ports are still live, and no BYE is sent. In the binary, process exit reclaims these. In-process (tests or embedding), they leak until the RTP watchdog fires (default 5m) or a peer sends BYE. docs/design.md §4.5 (358-396) does not say what happens to live trunk calls on shutdown, so the docs are also incomplete here.
- Invariant: task invariant "port-pool, dialog, leg … released on every exit path (… shutdown)".
- Confirming test: start a trunk-only `app.Run` and bridge one call over loopback. Cancel ctx and wait for `Run` to return. Then assert that `pool.Stats()` shows 0 ports in use, that `ActiveCalls()==0`, and that `runtime.NumGoroutine()` returns to baseline (bounded retry). Expected: FAIL.
- Overlap: the trunk reviewer may report the same issue from `server.go`.

### P2-APP-002: data race on `trunk.Server.registrar` via admin closures
- Severity: P2 | Layer: admin | INFERENCE | Action: fix
- Location: write at `internal/trunk/server.go:284` (`s.registrar = NewRegistrar(...)`), inside the `sipServer.Run` goroutine started at `internal/app/app.go:102`. Read at `internal/trunk/server.go:131` (`if s.registrar == nil`) through `deps.Peers` (`internal/app/app.go:199` `Registered: sipServer.IsRegistered(name)`). That closure is called by admin HTTP handlers (`internal/admin/api.go:53`) and by the Prometheus collector (`internal/admin/metrics.go:103`), both in the admin goroutine (app.go:123).
- Evidence: `s.shield` was made an `atomic.Pointer` for exactly this reason (server.go:140, 151, 233). `s.registrar` is a plain field with no happens-before edge between the trunk goroutine that writes it and the admin goroutine that reads it.
- Consequence: a scrape or `GET /api/peers` during startup is an unsynchronised read of a pointer being written. This is a data race under the Go memory model, and `-race` would report it.
- Confirming test: in-package trunk test. Call `NewServer`, then run `go s.Run(ctx)` concurrently with a tight loop of `s.IsRegistered("p1")` under `-race`. Expected: race report.

### P2-APP-003: whether each plane runs is decided once at startup, and this is not documented as restart-only
- Severity: P2 | Layer: config/lifecycle, docs | INFERENCE | Action: fix (docs; optionally reject on reload)
- Location: `internal/app/app.go:69` (`if len(store.Current().Peers) > 0`), `app.go:78` (`if store.Current().ProxyEnabled()`); docs table `docs/design.md:337-345`.
- Evidence: plane existence depends only on the startup snapshot. A reload is still accepted and published by `config.Watch` in these cases:
  - It adds `peers`/`listen.sip` to an edge-only process. The trunk plane never starts, and the reload succeeds silently.
  - It removes every peer from a trunk process. The trunk listeners stay bound, and the read filter now drops everything.
  - It adds or removes `sip.upstream(s)`. The edge plane is not started or stopped.
  The restart-only column lists "the listener set" and "edge topology", but not "whether the trunk / edge plane exists". Neither case produces a warning in the log.
- Confirming test: an edge-only `app.Run` in which the file is rewritten to add a peer. Assert that nothing listens on the new `listen.sip` port and that no error or warning is logged.

### P2-APP-004: `app.Run` reads several config snapshots after the watcher has started
- Severity: P2 | Layer: config/lifecycle | INFERENCE | Action: fix
- Location: `internal/app/app.go:57,69,78` (before the watcher starts, so all three return the same snapshot) versus `app.go:120` (`store.Current().Admin`) and `app.go:134-135` (after `config.Watch` is running at app.go:93).
- Evidence: the admin section, and the peer/route counts in the "freesbc started" log, can come from a newer snapshot than the one that decided which planes run. docs/design.md:257-260 documents this window. It still breaks the "one unit of work, one snapshot" rule, because `cfg` from line 49 is already in scope.
- Fix: use `cfg` (line 49) for every startup decision.

### P2-APP-005: admin reports trunk-only state in both-plane and edge-only deployments
- Severity: P2 | Layer: admin | INFERENCE | Action: fix
- Location: `internal/app/app.go:146-204`.
- Evidence:
  - `ActiveCalls` sums trunk and edge (app.go:155-164), but `Calls` lists trunk calls only (app.go:171-180). `GET /api/calls` and the active-call count therefore disagree whenever edge dialogs exist.
  - `Unban` and `Shield` are trunk-only (app.go:182-192). In a both-plane process, an edge-shield ban cannot be removed and edge drops are not counted.
  - `Ports: pool.Stats` (app.go:152) is the trunk `PlanePool` even when no trunk plane runs (app.go:55 always builds it). The edge public/private pools are never exposed.
  - `app.go:57-60` logs "media plane ready" with the trunk port range in edge-only mode.
  The "Known gap" comment at app.go:146-149 and CLAUDE.md document the call/kill/unban/shield part. The `ActiveCalls` vs `Calls` mismatch and the `Ports` mismatch are not documented.
- Confirming test: an edge-only `adminDeps` with one edge dialog. Assert `ActiveCalls()==1 && len(Calls())==0`.

### P2-APP-006: `check` accepts configs that `run` rejects
- Severity: P2 | Layer: config/lifecycle | INFERENCE | Action: fix
- Location: `internal/app/app.go:31-34` (`Check` = `config.Load` only).
- Evidence: the following run-time failures are unreachable from `check`:
  - edge hostname endpoints: `buildTopology` in `edge.New` (app.go:79; `edge/topology.go:126-134`);
  - missing or invalid DTLS cert files: `media.LoadDTLSIdentity` (`edge/edge.go:132`);
  - peer client TLS material: `buildClientTLSConfig` → `tls.LoadX509KeyPair` / `os.ReadFile` (`trunk/tlscert.go:69,84`), called from `trunk.Server.Run` (server.go:167);
  - inbound TLS certs, loaded at bind.
  CLAUDE.md documents the hostname case only.
- Fix: have `Check` also run the pure, no-bind parts (`edge` topology build, file readability).

### P2-APP-007: positional arguments are silently ignored
- Severity: P2 | Layer: config/lifecycle | INFERENCE (documented behaviour) | Action: fix
- Location: `cmd/freesbc/main.go:39` (`_ = fs.Parse(os.Args[2:])`; `fs.Args()` never inspected).
- Evidence: `freesbc run edge.yaml` starts with `./sbc.yaml`, which may be a different, valid config. It then serves the wrong plane with exit 0. `freesbc check edge.yaml` reports "sbc.yaml: config OK". This is documented at docs/design.md:233-235, but it is a real operator hazard. Fix: exit 2 when `fs.NArg() > 0`.

### P2-APP-008: a second SIGINT/SIGTERM cannot force-exit a hung shutdown
- Severity: P2 | Layer: config/lifecycle | INFERENCE | Action: fix
- Location: `cmd/freesbc/main.go:49-50`.
- Evidence: `signal.NotifyContext` keeps capturing signals until `stop()`, and `stop()` runs only when `main` returns. The docs say "no overall shutdown deadline at the app level" (docs/design.md:363-364). A shutdown that hangs therefore ignores repeated Ctrl-C and needs SIGKILL. Possible causes are un-REGISTER, admin 5 s drain, `nft delete` or an edge `wg.Wait()`. Fix: call `stop()` right after `<-ctx.Done()` so the second signal gets the default action.

### P2-APP-009: test uses `time.Sleep` for synchronisation and a racy free-port helper
- Severity: P2 | Layer: config/lifecycle | INFERENCE | Action: fix (test only)
- Location: `internal/app/app_test.go:61` (`time.Sleep(200 * time.Millisecond)` before `cancel()`); `app_test.go:85-93` (`freeUDPPort` closes the port before `Run` binds it).
- Evidence: if the listener has not bound within 200 ms, the test only exercises cancel-before-bind and still passes. It never checks that startup succeeded. `edge.Server.Ready()` exists, but trunk has no equivalent, and app exposes neither.

## Checklist items checked and clean
- Partial-start cleanup: `trunk.NewServer` (server.go:104-119) and `edge.New` (edge.go:104-141) bind nothing and start no goroutines, so an `edge.New` failure after `NewServer` leaks nothing. The only side effect that is never undone is the process-wide `raiseUDPSendLimit()` (edge.go:113), which is documented.
- A bind failure in one plane cancels `gctx` through errgroup and stops the others. Errors after cancel are suppressed; `g.Wait()` returns the first error (app.go:91-139).
- Neither plane configured → error before any goroutine starts (app.go:84-86).
- Watcher failure is non-fatal by design (app.go:93-99), as documented at docs/design.md:323-326.
- `os.Exit(1)` in main skips `defer stop()`. This is harmless: stop only unregisters signal delivery.
- `_ = fs.Parse(...)`: the FlagSet uses `flag.ExitOnError`, so the discarded error is always nil.
- Goroutines with no exit path, `time.After` in loops, `recover`, defer in loops, locks across I/O, and per-packet work: none in app/cmd.
- Architecture: `cmd/freesbc` imports only `internal/app`. `internal/app` imports admin, config, edge, media, trunk, which matches docs/design.md:83-103 and §17 (3004-3005). app touches no SIP message or SDP body.
- No credential handling and no ESL/call-centre logic in app/cmd.
- `admin.Deps.Peers` reads `store.Current()` per call, so it is hot rather than a stale snapshot. Closures capture `sipServer`/`edgeSrv` pointers, which never change.
- Hot reload does not touch startup-only settings in app: admin config is read once, the listener set is fixed, and plane topology is fixed.

## Docs vs code
- docs/design.md §4.1, §4.2 and §17: line citations `app.go:93-99`, `93-118`, `120-130` and `main.go:37,39` match the code.
- §4.5 omits trunk live-call behaviour on shutdown (P2-APP-001).
- The §4.4 restart-only table omits plane existence (P2-APP-003).
