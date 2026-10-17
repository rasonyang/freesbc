# Issue #170: lingering sipgo server transactions

Research note. It records why memory per sustained CPS was high, what was changed, what was measured and what is left. Sizing guidance is in [performance.md](../performance.md#memory-cps-and-gomemlimit).

## Root cause

sipgo v1.4.3 starts a goroutine for every request that reaches the transaction layer (`TransactionLayer.handleMessage`, `sip/transaction_layer.go:140`). For a new transaction it runs the server's handler on it (`serverTxRequest`, `:228`). `Server.handleRequest` (`server.go:258`) calls the handler and then `tx.TerminateGracefully()` (`server.go:267`). On UDP, once a final response has been sent, `TerminateGracefully` (`sip/transaction_server_tx.go:165`) blocks on `<-tx.Done()` (`:181`) until the transaction's own timer ends it:

| Transaction | State after the final | Ends at | UDP lifetime |
|---|---|---|---|
| non-INVITE (REGISTER, OPTIONS, BYE, ...) | Completed | Timer J (`actFinal`, `transaction_server_tx_fsm.go:233`) | 64*T1 = 32 s |
| INVITE, 2xx | Accepted (RFC 6026) | Timer L (`actRespondAccept`, `:213`) | 32 s |
| INVITE, 3xx-6xx | Completed, then Confirmed on the ACK | Timer H (`:203`), or Timer I = T4 after the ACK (`actConfirm`, `:272`) | 5 s after the ACK, 32 s without |

The wait does no work. The timers are `time.AfterFunc` callbacks that call `actDelete` themselves. Retransmissions are absorbed by the transaction layer: a retransmitted request finds the transaction in its store and `tx.Receive` replays the last response, on a fresh goroutine. The parked goroutine only keeps its stack alive: a goroutine stack that grew while the handler ran, held for 32 s. On a reliable transport, and for a transaction with no final, `TerminateGracefully` is `Terminate` and nothing is parked.

## What a lingering transaction retains

Measured with `TestMeasureTxLinger` (2000 public OPTIONS answered by the edge, so every transaction is the edge's own; heap after a forced GC, `MemProfileRate=1` for the breakdown):

| Item | Per transaction | Held by | Needed for |
|---|---:|---|---|
| parked goroutine | 1 | `Server.handleRequest` | nothing |
| its stack | about 4.2 KiB (4293 B measured; up to about 5 KiB under sustained load) | the goroutine | nothing |
| heap: request, response, `ServerTx`, timers, channels | about 9.4 KiB `HeapInuse` | sipgo's transaction store until Timer J/L/H/I | retransmission absorption (RFC 3261 §17.2) |

Heap breakdown of those lingering objects (inuse_space): the parsed request (`NewRequest` plus `ParseHeader` and the From/To/Via header structs, about 45%), the final response (`NewResponse` and header clones, about 25%), `NewServerTx` (about 460 B), the `time.Timer`s and the source-address strings. The edge's own objects are not among them for OPTIONS.

For an INVITE, more is reachable for the same 32 s, through edge closures held by sipgo transactions:

- the INVITE server transaction's `OnCancel` hook (`invite.go:359`, `:659`, `carrier.go:267`) captures the dialog;
- the forwarded INVITE's client transaction keeps the `watch2xx` hook (`invite_leg.go:86`) until Timer M (32 s), and it captures the `inviteLeg`, so the dialog, its media session (closed sockets' structures, SDPs) and the requests.

With a weak pointer to the dialog, an ended dialog became collectable 31 to 32 s after the BYE. Clearing the `OnCancel` capture alone did not change that, because `watch2xx` holds the same dialog for as long. In a sustained call run's heap profile, `inviteToUpstream` accounts for about 28% of the live heap (`beginDialog` and media allocation are about a quarter of that). The rest is sipgo's own request and response objects.

## Change made (prototype on this branch)

`internal/edge/txserve.go`. `Run` installs `serveTx` on the transaction layer (`ua.TransactionLayer().OnRequest`) in place of sipgo's `Server.handleRequest`. It dispatches by method from a map built in `Run` (`s.routes`, the same handlers as before, each wrapped by `guard`). Then:

- if the handler's `finalTracker` saw a final response and the transport is unreliable, it returns at once, and sipgo's timers end the transaction as before;
- otherwise it calls `TerminateGracefully` as sipgo did: `Terminate` for no final (the silent admission drop depends on this) and on reliable transports. It still blocks in the one case where sipgo itself sent a final that the handler did not, the 487 after a CANCEL. That is rare, and sipgo's behaviour there is unchanged.

`guard` reuses the `finalTracker` that `serveTx` hands it. Nothing about the transaction state machine, its timers or retransmission handling changes. `TestServeTxDoesNotParkGoroutines` checks that no goroutine is parked after 50 OPTIONS, and that a retransmission is answered from the transaction without running the handler again. It fails on the old code (`sipgo Server.handleRequest 0 -> 50`).

Size: about 70 lines in `txserve.go` and 25 changed in `edge.go`, no sipgo fork or `replace`. Risk: low. It relies on `Server.handleRequest` doing only middleware (the edge has none), dispatch and `TerminateGracefully`, and on `TransactionLayer.OnRequest` replacing the handler `NewServer` installed. Both are true in v1.4.3, v1.5.0 and v1.6.0.

## Measurements

### Burst (`TestMeasureTxLinger`, right after the burst, delta over the idle baseline per edge server transaction)

| Workload | Build | Goroutines | Stack | Heap (`HeapInuse`) |
|---|---|---:|---:|---:|
| 2000 OPTIONS | before | 1.00 | 4293 B | 10228 B |
| 2000 OPTIONS | after | 0.00 | 147 B | 9609 B |
| 1000 calls (INVITE, ACK, BYE) | before | 2.50 | 9437 B | 33288 B |
| 1000 calls | after | 1.50 | 5210 B | 34890 B |

The call rows include the in-process fake switch, a plain sipgo server that still parks two goroutines per call, and the remaining `drainAcks` goroutine, one per INVITE. After 36 s every count is back at the baseline in both builds.

### Sustained (`TestMeasureTxLingerSustained`, 50 s at a fixed rate, mean of the last 10 s)

Everything runs in one process on a shared 4-CPU VM: the edge, the test phones and, for calls, the fake switch. So absolute numbers are this harness's. Compare rows with each other, not with the perf rig. CPU is the process's busy time over the 50 s run (runtime/metrics), and GC is its share.

| Workload | Build | GOMEMLIMIT | RSS | Heap in use | Stacks | Goroutines | CPU | GC share |
|---|---|---|---:|---:|---:|---:|---:|---:|
| 1000 OPTIONS/s | before | unset | 523 MiB | 254 MiB | 148 MiB | 32102 | 7.8 s | 20% |
| 1000 OPTIONS/s | after | unset | **248 MiB** | 213 MiB | 1.3 MiB | 140 | 6.2 s | 9% |
| 1000 OPTIONS/s | before | 300MiB | 310 MiB | 162 MiB | 127 MiB | 32144 | 73.1 s | 83% |
| 1000 OPTIONS/s | after | 200MiB | 198 MiB | 171 MiB | 1.5 MiB | 140 | 6.5 s | 13% |
| 300 calls/s | before | unset | 1074 MiB | 706 MiB | 248 MiB | 48150 | 17.9 s | 25% |
| 300 calls/s | after | unset | **860 MiB** | 655 MiB | 109 MiB | 28940 | 17.1 s | 22% |
| 300 calls/s | before | 650MiB | 641 MiB | 428 MiB | 178 MiB | 48145 | 41.2 s | 63% |
| 300 calls/s | after | 650MiB | 624 MiB | 473 MiB | 99 MiB | 28940 | 21.5 s | 38% |
| 300 calls/s | before | 450MiB | 609 MiB | 406 MiB | 174 MiB | 48137 | 105.1 s | 81% |
| 300 calls/s | after | 450MiB | 518 MiB | 394 MiB | 95 MiB | 28572 | 86.0 s | 79% |
| 1000 OPTIONS/s | before | 150MiB | 298 MiB | 150 MiB | 127 MiB | 32146 | 129.5 s | 86% |

Reading:

- Edge-only transactions (OPTIONS): RSS per sustained request per second fell from 517 KiB to 235 KiB (55% less), goroutines from 32 per request/s to 0, stacks from 156 KiB to under 1 KiB per request/s.
- Calls: 64 fewer goroutines per CPS (160 to 96; the remaining 96 are the fake switch's 64 and `drainAcks`' 32), stacks 875 to 365 KiB per CPS, RSS 20% less for the whole process. The fake switch's own parked goroutines are in both builds, so the edge's share of the saving is larger than 20%.
- GOMEMLIMIT trades CPU for memory, and the fix makes that trade much cheaper. Stacks count against the limit but cannot be collected. At a limit the old build reaches the same RSS only by running the GC most of the time (63% to 86% of its CPU), while the fixed build holds a lower RSS with GC at 13% to 38%.
- A limit close to the live heap makes the GC run continuously: the 450MiB call rows spend about 80% of their CPU in GC, five times the unlimited run's CPU. The old build at 150MiB for OPTIONS (86%) shows the same thing, and the fixed build at 150MiB spent 53.6 s of GC CPU in the 50 s run. A limit is only cheap with headroom over the live heap plus stacks.

### Perf rig (`test/perf/run.sh`)

Not re-run: the container rig needs a Docker daemon, and this environment has none. The pre-#170 figures stay in performance.md: 2.3 MB RSS and about 76 goroutines per CPS, and 0.8 MB/CPS live heap at 2500 CPS carrier-in. From the dump there, 64 of those 76 goroutines per CPS were the two parked handler goroutines per call (INVITE and BYE). These are now gone; at the about 4 to 5 KiB per stack measured here, that is 0.25 to 0.3 MB of stack per CPS, plus less GC and stack-scan work. **Re-run `run.sh -n -s 1000:3500:500:60 -H 2 carrier-in` and the `call` step test to close the issue's acceptance criterion.**

## Options evaluated

| Option | What | Effort | Risk | Verdict |
|---|---|---|---|---|
| a1. Own transaction-layer handler | `serveTx` above | small (about 100 lines) | low: behaviour identical except the wait | **done** |
| a2. Upgrade sipgo to v1.6.0 | upstream `39ba2cf` "Avoid blocking on graceful server tx termination" (refs sipgo #349) removes the same `<-tx.Done()`; it is in the v1.6.0 module (proxy hash `e8676d2`, 2026-08-27) | medium: about 18 upstream commits (parser bounds, stream deadlines, TCP close on framing error, TLS/WSS fixes) and every listed workaround must be re-checked | medium | recommended separately, see below |
| a3. `runtime.Goexit()` at the end of the handler | skips the code after the handler in sipgo's `handleRequest` | trivial | high: depends on sipgo running nothing else after the handler and that no deferred code in the handler's goroutine expects a normal return | rejected |
| a4. `replace` with a patched sipgo | the same 3-line change in `TerminateGracefully` | small | low, but a fork to maintain | unnecessary (a1, and upstream has it) |
| b1. Drop the request or response from a finished transaction | nil out `tx.origin` headers or body after the final | medium | high: `origin` is the edge's own request (shared pointer, read by sipgo's FSM and the edge), and the response is required to answer retransmissions | rejected |
| b2. Release edge captures after the final | clear the dialog captured by the `OnCancel` hook when the handler returns (prototyped: sipgo's INVITE FSM ignores CANCEL after a final), and make `watch2xx` (Timer M hook) hold a small record (relayed-2xx tag, rejected tags, far side) instead of the whole `inviteLeg` once the dialog ends | medium | medium: the late-2xx and forked-2xx paths must keep working | **follow-up**: both captures must go for any gain (one alone measured no change); expected gain is the dialog, media and SDP share of the live heap per call |
| b3. Shorter Timer J/L | `sip.SetTimers` is global and also drives client transactions; a retransmission after the transaction is gone would be handled as a new request (a REGISTER or BYE forwarded twice) | trivial | high: RFC 3261 non-compliance | rejected |
| b4. Compact completed-transaction cache | keep only the key and the encoded final response for Timer J instead of the whole `ServerTx` | large (sipgo patch) | medium | not worth it before b2 and an upgrade |
| b5. `drainAcks` goroutine per INVITE | it lives until Timer L (32 s) after a 2xx only to catch an ACK that wrongly reuses the INVITE branch | small | medium: forwarding of that ACK is tested behaviour; sipgo main `1f8ebf1` (after v1.6.0) lowers "ACK missed" to Debug | follow-up: start the drain only after a non-2xx final, or once sipgo's log level change ships |
| c. GOMEMLIMIT and sizing | documented in performance.md, and a commented line in `packaging/freesbc.service` | trivial | none | **done** |

## sipgo upgrade assessment

- v1.5.0 (2026-08-07) still blocks in `TerminateGracefully` (`sip/transaction_server_tx.go:184-185`).
- v1.6.0 (module proxy hash `e8676d2`, 2026-08-27) has the fix: `TerminateGracefully` only logs "Server transaction retained for timer termination" and returns. `Server.handleRequest` is unchanged, so with v1.6.0 `serveTx` is redundant but still correct. Upstream later moved the git tag `v1.6.0` to `86ec9f7` (2026-09-20, "remove conn creation as blocking operation from server transaction map #363"). Go modules keep the original `e8676d2`, so that commit is not in the v1.6.0 module.
- v1.6.0 does not fix #306 (provisional ordering), so `provTable` stays. The "failed to parse" log string, `UDPMTUSize`, `SIPDebugTracer`/`SIPTraceWrite` and the "ACK missed" Warn are still present in v1.6.0 (checked in the module source).
- Trial on a copy of `origin/main` with only `go get github.com/emiago/sipgo@v1.6.0` (no `serveTx`): `go build` and `go vet` are clean, and `go test -race -count=1 ./internal/edge/ ./internal/app/ ./internal/sip/...` passes. Not run in that trial: `./internal/media` and `./internal/admin` (fixed ports shared with parallel work), govulncheck, the soak and fuzz jobs, and the perf rig.
- Verdict: do not upgrade on this branch, although the trial is encouraging. The change set is larger than #170 and touches the transport layer the edge wraps (`streamListener`, read filter, dialed carrier connections, stream deadlines, TCP close on framing errors). It deserves its own PR with the full CI, soak and a perf-rig run. That PR can delete `serveTx` or keep it as a harmless guard.

## Recommendation

1. Keep `serveTx`. It is small, behaviour-preserving, and removes the parked goroutine per transaction now, without waiting for the upgrade.
2. Re-run the perf rig (`call` and `carrier-in` CPS steps) to replace the 2.3 MB/CPS figure in performance.md.
3. Follow up with b2 (release the dialog from the `OnCancel` and `watch2xx` hooks after the call ends), then evaluate the sipgo v1.6.x upgrade in its own PR.
4. Operators: set GOMEMLIMIT with headroom over the live heap (performance.md).

## Outcome (sipgo v1.6.0 upgrade, issue #229)

The upgrade was done in its own change. `serveTx` and `txserve.go` are removed and the handlers are registered with sipgo's `srv.On*` and `OnNoRoute` again. Upstream is equivalent for what `serveTx` did: v1.6.0's `ServerTx.TerminateGracefully` (`sip/transaction_server_tx.go:170`) terminates at once on a reliable transport or without a final, and otherwise logs "Server transaction retained for timer termination" and returns, leaving the transaction to its timers. It is slightly broader than `serveTx`: it also covers the 487 sipgo sends itself for a CANCEL, which `serveTx` still blocked on. `TestServeTxDoesNotParkGoroutines` became `TestServerTxDoesNotParkGoroutines` and now guards the upstream behaviour (it would fail on v1.4.3 and v1.5.0). `provTable`, the "failed to parse" rewrite, `UDPMTUSize`, the HEP tracer and `drainAcks` (the "ACK missed" Warn is still at Warn in v1.6.0) are kept.
