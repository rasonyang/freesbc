# Performance

Capacity numbers for FreeSBC from the formal three-host run of issue #109 (2026-10-18, with the 8 hour soak ending 2026-10-19), with the method and harness in [`test/perf/`](../test/perf/README.md) so anyone can repeat it. The run reports are the [day report](https://github.com/rasonyang/freesbc/issues/109#issuecomment-6249040280) and the [soak report](https://github.com/rasonyang/freesbc/issues/109#issuecomment-6256238968) on #109. The earlier single-host run (Docker on a laptop) is kept at the end for history; where the two disagree, the three-host figures stand.

All figures were measured on the rig below; anything derived is marked so. A figure is either a **knee** (the first step that failed the pass criteria) or a **lower bound**: the ladder ended because the load generator, the switch or the prescribed range ran out before FreeSBC did. The tables say which. Nothing here is a promise.

## Summary

FreeSBC on one cloud VM (4 vCPU = 2 physical cores + HT, 7.4 GiB usable), real NICs, SIPp generators and switch on separate hosts.

| What | Result | Kind | Limit that ended the ladder |
|---|---|---|---|
| Concurrent G.711 calls, media anchored on both legs | **5000** (CPU 310 of 400, 500.6k pps / 668 Mbit/s each way, RSS 373 MB) | knee at the 80% CPU line (320) | 5500: CPU 337 and the generator at 94% of a core |
| Soak, 8 h at 3500 concurrent (70% of 5000) | **PASS**: 432000 calls, 0 failed, no growth | measured | none |
| Call setup, client to switch (no media, 2 s calls) | **2250 CPS** | lower bound (one generator source IP) | 2500: `503 early_cap`, 64 unanswered INVITEs per public source |
| Call setup, carrier to switch | **3500 CPS** loss-free | knee for loss-free; failures only at 5000 | kernel receive drops on both UDP SIP sockets from 3750 CPS: GC mark phases keep each socket's one read loop off the CPU (#235) |
| Call setup, switch to carrier | **3250 CPS** | knee | 3500: carrier-leg timeouts (0.204% failed) |
| Registrations held / refresh rate | **19000** held (binding cap 20000); refresh **20000 REGISTER/s or more** at 13% of the CPU | lower bound (range top) | none; the ladder ended at 20000/s |
| WebRTC (ICE-Lite + DTLS-SRTP over ws/wss) | **100 DTLS handshakes/s or more**, **600 concurrent SRTP calls or more** | lower bound (generator-limited) | one `webrtcload` process at 100% (150/s) and 126% (800 calls) of a core |
| FreeSWITCH 1.10.0 as the switch | **3000 concurrent calls or more** (CPU 211); **1500 CPS or more**; 5000 registrations | lower bound (range top, switch-limited) | 3000 is the top of the range; at 1500 CPS FreeSWITCH used 6.6 of its 8 vCPU |
| Latency added by FreeSBC (1000 concurrent) | **below 1 ms** | measured | below the resolution of SIPp's mean (3.0 ms both ways) |

* **Competitor scenario** (1000 concurrent G.711 calls held 600 s, 50 CPS, SIPp switch): PASS on all four vCPU, on two and on one. 0 of 2000 calls failed in each. Process CPU 64 / 52 / 40 (100 = one vCPU), RSS about 120 MB (the competitor's published figure is 1730 MB), RTP tx/rx 1.0000, probe loss 0.000%, jitter mean 0.47 ms (p99 1.72 ms). One vCPU of this box carries that test.
* The CPS knees are with sipgo v1.6.0 and 4 MiB UDP SIP socket buffers (#171); the receive request is 8 MiB since #235, not yet measured on these hosts. The signaling knees are not CPU limits: FreeSBC was at 33 to 48% average CPU at all three.
* Media is cheap in memory and linear in CPU: about 1600 concurrent calls per vCPU. The media path is syscall-bound (about 70% of CPU flat in `sendto`/`recvfrom`); batching per socket would cut few syscalls, so #172 was closed as not worth it at this architecture.

## Sizing guide

Figures marked (derived) are arithmetic on the measurements. The rig's CPU convention is 100 = one vCPU, and the pass line is 80% of the cores (320 of 400).

| Dimension | Planning figure | Basis |
|---|---|---|
| Concurrent calls with media | about 1600 per vCPU, 5000 on 4 vCPU at 80% (derived: about 0.062 vCPU per 100 calls) | M02; CPU grows linearly from 250 calls (20) to 5000 (310) |
| Call setup rate | about 2250 CPS (client, lower bound) / 3500 (carrier in) / 3250 (carrier out) on 4 vCPU, with the average CPU at 33 to 48% | M01 |
| Memory per sustained CPS | **about 1.25 MB** and about 44 goroutines per CPS (2 s calls, measured 1000 to 3500 CPS; flat across the range) | M07, #170 |
| Memory per concurrent media call | about 0.07 MB (derived: 373 MB RSS at 5023 calls, includes the baseline) | M02 |
| Memory per held registration | about 7.4 KB of RSS | M04 |
| Registrations | 19000 held; the cap is 20000 | M04 |
| CPU on the signaling path | about half in sipgo's transaction layer, 15 to 25% GC | M07 profiles |
| RTP ports and sessions | the default `rtp: 20000-29999` is 5000 port pairs per plane, and `shield.max_sessions` defaults to that pair count, so a default config admits about 5000 calls; widen `rtp` (and `max_sessions` with it) above that | config; the rig used `rtp: 10000-59999` and `max_sessions: 25000`, so neither was the limit |

* **RAM** (derived): `RSS ≈ 1.25 MB x CPS + 0.07 MB x concurrent calls + about 50 MB`. The CPS term dominates: at 3500 CPS carrier-in RSS was 4.6 GB, while 5000 concurrent calls held in steady state used 373 MB. The 1.25 MB was measured before the `drainAcks` 2xx bound (see below), which removes about 24 goroutines per CPS and their stacks, so treat it as an upper figure until the next three-host run. At the 5000 CPS step carrier-in RSS reached **5.8 GB** (5832 MB) on this 7.4 GiB host, so a CPS-driven box needs about **1.2 GB of RAM per 1000 CPS** plus headroom.
* **Calls per second are not calls held.** A call that lasts 2 s and one that lasts 240 s cost the same per call setup; the 32 s the state outlives the call is what sets the memory (see below).
* **A lower bound is not a ceiling.** Client call setup (one source IP), registrations, WebRTC and the FreeSWITCH figures are where the rig stopped, not FreeSBC. Plan with them as floors.
* The CPS figures are for UDP signaling and one carrier or client source per run. A carrier source is exempt from the 64-unanswered cap; a client source is not.

### Memory, CPS and GOMEMLIMIT

Memory at a sustained call rate is set by state that outlives each call by a fixed time, not by concurrent calls. sipgo keeps every UDP server transaction for up to 64*T1 = 32 s after its final response (RFC 3261 Timer J for non-INVITE, Timer L after an INVITE 2xx, Timer H otherwise); stream transports (tcp, tls, ws, wss) end theirs at once. The edge's `drainAcks` adds one small goroutine per INVITE: for 8 s after a 2xx (`ack2xxDrainWait`), otherwise until the transaction ends.

| Figure per sustained CPS | Single-host, pre-sipgo v1.6.0 | Three-host, sipgo v1.6.0, before the `drainAcks` bound |
|---|---|---|
| RSS | about 2.3 MB | about 1.25 MB (1.22 to 1.31 carrier-in, 1.30 to 1.61 client) |
| goroutines | about 76 | about 44 (31.7 are `drainAcks`, one per INVITE) |

* The drop (about 45% of RSS, 32 goroutines) is the handler goroutine sipgo v1.6.0 no longer parks (#170). What remains is the heap sipgo holds until its timers fire (1168 MB in use at 2025 CPS: `sip.NewRequest`, `sip.NewResponse`, `ParseHeader`, `sip.NewServerTx`, header clones) and the `drainAcks` stacks (about 0.3 GB of the 2.5 GB RSS at 2025 CPS). It is per-call state held for a fixed time, not a leak: goroutines return to about 33 after each run.
* #170's remaining part: `drainAcks` now stops 8 s after a 2xx (`ack2xxDrainWait`) instead of at Timer L (32 s), since a branch-reusing ACK follows the 2xx by one round trip. That cuts about 24 of the 44 goroutines per CPS (31.7 `drainAcks` held 8 s instead of 32 s). Measured locally (`TestMeasureTxLingerSustained`, call workload at 200 CPS on macOS, fake switch and clients in the same process, so compare the two runs only): 32.1 to 8.1 goroutines and 72.5 to 25.4 KiB of stack per CPS, heap unchanged (1846 to 1823 KiB per CPS). The next monthly three-host run will confirm it.
* What remains is mostly heap: sipgo keeps each UDP transaction, and the messages it holds, for 32 s (Timer L after a 2xx, RFC 6026). That retention is left alone as a decision: it is sipgo's to change. #173 (open) covers the allocation per request.

**GOMEMLIMIT.** The rig ran with `GOMEMLIMIT=6GiB` on the 7.4 GiB host (about 80%). Without a limit the Go runtime lets the heap grow to about twice the live heap (GOGC=100) before collecting; a limit makes the GC collect harder near it, trading CPU for memory. Signaling at these rates was not CPU-bound, so that trade is cheap.

- Set it to about 80 to 90% of the memory the process may use: the container or cgroup limit (`MemoryMax=`, `--memory`), or the host's RAM minus what else runs there. Leave GOGC at its default.
- Measured: an 8 GiB-class host (7.4 GiB usable) with `GOMEMLIMIT=6GiB` reached 5.8 GB RSS at 5000 CPS carrier-in without being killed, and 4.58 GB at 3500 CPS with `gcAssistAlloc` visible. Size RAM for the CPS you expect with that curve, not for concurrent calls.
- It is a soft limit. It counts goroutine stacks, which the GC cannot reclaim, and the live heap cannot be freed either. When live heap plus stacks approach the limit, the GC runs nearly continuously, and past it the process keeps growing and the OOM killer still ends it. Keep at least 30 to 50% headroom over the expected live heap. (In the single-host in-process harness a limit just above the live heap spent about 80% of the process's CPU in GC.)
- Watch `process_resident_memory_bytes`, `go_memstats_heap_inuse_bytes`, `go_goroutines` and the GC CPU share (`go_gc_*` series) on `/metrics` under load.
- systemd: `Environment=GOMEMLIMIT=3600MiB` next to `MemoryMax=4G` (commented example in `packaging/freesbc.service`). Docker: `--memory 8g -e GOMEMLIMIT=7GiB`.

## Method and topology (three-host run)

Three separate cloud VMs with real NICs on two subnets of one private network (public side and private side), all Ubuntu 24.04, kernel 6.8.

| Role | CPU and memory |
|---|---|
| FreeSBC | Intel Xeon 6982P-C, 4 vCPU = 2 cores + HT, 7.4 GiB usable |
| Load generator (SIPp UAC, `webrtcload`) | AMD EPYC 9T24, 8 vCPU, 15 GiB |
| Switch (SIPp UAS with `-rtp_echo`, or FreeSWITCH for M06) | Intel Xeon 6982P-C, 8 vCPU, 15 GiB |

* FreeSBC: v0.5.0, measured at commit `c7f2d3c` (product code is identical to the v0.5.0 tag; the tag adds only the harness changes of #236 and docs), Go 1.27.2, sipgo v1.6.0, `GOMAXPROCS` at the default (the core-count rounds for M03 restrict the cores instead), `GOMEMLIMIT=6GiB`. `net.core.rmem_max` and `rmem_default` are 8 MiB on all three hosts, so the 4 MiB request of #171 is granted in full (and so is the 8 MiB request of #235). SIPp 3.6.1 with `rtp_stream` (a thread pool; the earlier `play_pcap_audio` spawned a thread and socket per call and collapsed the generator). FreeSWITCH 1.10.0 for M06.
* The switch is a SIPp UAS that answers instantly and echoes RTP, so no switch is the bottleneck, except in M06, where FreeSWITCH is the switch.
* Signaling is UDP, except the wss variant of M05. Media is G.711 (PCMU) 20 ms, both directions, both legs anchored by FreeSBC.
* Pass criteria for every quoted figure: under 0.1% failed calls, no aborted SIPp, FreeSBC CPU under 80% of its cores (320 of 400), RTP tx/rx at least 0.999 with kernel receive-buffer errors 0, no `invite_rejects` or `admission_drops`, and `rigcheck` (generator and switch under 90% of a core, under 80% of the host) OK. The CPS ladders step every 40 s (60 s where noted) and stop at the first failing step; each knee has a 90% confirm run of 120 s.
* FreeSBC was restarted before each ladder value. Sampling and the run kit are in [`test/perf/hosts/MEASURE.md`](../test/perf/hosts/MEASURE.md).

## Results (three-host run)

### M03 competitor scenario

1000 concurrent G.711 calls, 600 s hold, 50 CPS offered (`m03.sh`, 2000 calls), SIPp switch, plateau about 1180 s.

| Cores of FreeSBC | Concurrent (avg / peak) | Failed | CPU (100 = one vCPU) | RSS max | RTP tx/rx | Verdict |
|---|---|---|---|---|---|---|
| all 4 vCPU | 1006 / 1020 | 0 of 2000 | 64 avg / 70 peak | 120 MB | 1.0000 | PASS |
| 2 | 1006 / 1020 | 0 of 2000 | 52 / 57 | 117 MB | 1.0000 | PASS |
| 1 | 1006 / 1020 | 0 of 2000 | 40 / 44 | 115 MB | 1.0000 | PASS |

* Plateau RTP 100.6k pps / 134.4 Mbit/s each way. Probes (`webrtcload`, 3 x 20 calls, 120 s): 359989 sent and echoed, loss 0.000%, sequence gaps 0, jitter mean 0.47 ms (p99 1.72 ms), RTT p50 0.4 ms. INVITE to 200 mean 3.0 ms (4.0 on 2 cores, 5.0 on 1), p95 bucket under 10 ms.
* Process CPU is lower on one core (40) than on four (64) for the same load: with `GOMAXPROCS` 1 the Go runtime has no spinning Ps, so the multi-core figures include runtime spin time.
* The competitor ran 1000 concurrent calls on an X5670 6C/12T (8 GB, Debian 10) with 1730 MB used and "CPU Load 26%" (definition not stated). Here the whole host used at most 855 MB and 15.9% of its vCPUs on average.

### M01 call setup rate (no media, 2 s calls)

All three ladders on all four vCPU, 40 s steps from 250 CPS. A and C stayed below 30% of a core in every step.

| Scenario | Knee | First failing step | CPU avg at the knee (of 400) | RSS at the knee | What failed first |
|---|---|---|---|---|---|
| client to switch | **2250 CPS** | 2500: 0.248% | 132 (33%) | 2518 MB | `503 early_cap`: 64 unanswered INVITEs per public source IP |
| carrier to switch | **3500 CPS** | 5000: 0.101% | 190 (48%) | 4296 MB | kernel drops on both UDP SIP sockets from 3750 (#235) |
| switch to carrier | **3250 CPS** | 3500: 0.204% | 192 (48%) | 3960 MB | carrier leg did not answer within 10 s |

* **Client to switch is a lower bound.** The generator has one source IP, and `maxEarlyPerSource` (64, `internal/edge/invite.go:34`) is per public source. At 2500 CPS FreeSBC was at 148 CPU average (37%), all 248 failures were `early_cap`, and retransmissions were 0. More source IPs were not tried.
* **Carrier to switch.** Failures stay tiny through 4750 CPS (0.047%) and the first failing step is 5000 (0.101%), but `udp_rcvbuf_errors` is 0 only through 3500 and grows from 3750 (1378 drops, 6514 at 4000, 76009 at 5000) while FreeSBC's CPU is 209 to 265 of 400. The loss-free knee is 3500. This is a FreeSBC receive-path limit, not the CPU limit and not the generator. Retransmissions recover the calls up to 4750.
* **Why carrier-in drops (#235).** A local re-run found the mechanism; it ran on one 4-CPU aarch64 Linux VM (FreeSBC pinned to 4 CPUs, carrier-in, no media, 2 s calls), so its numbers explain the knee but do not replace the three-host one. Both UDP SIP sockets dropped, the private one (switch to FreeSBC) slightly more. The onset was 4250 to 4750 CPS with large run-to-run variance, and a run that drops can collapse: retransmissions pile sessions up to the cap. Average CPU had headroom (2.2 of 4 cores); GC mark phases did not. Each lasted 0.5 to 1.6 s, together 14 to 24% of wall time, over a live heap of 2.3 to 3.1 GB held mostly by retained transactions (#170), with GC at 19 to 25% of CPU from the allocation rate (#173) and mark assist about 1.3 to 1.45 times the background workers. During a mark phase GC occupies most of the 4 Ps and about 1000 goroutines are runnable (sipgo's transaction layer starts one per datagram), against about 85 outside it. Each socket has one read loop, which parses inline, and it waits its turn for a CPU: in an execution trace at 4500 CPS the readers were idle in netpoll 74 to 76% of the time, running 9% and runnable 12 to 16%, with scheduling latency p99.9 19 to 30 ms and max 57 to 102 ms. The longest gap without a read was 164 ms, and 90% of reader waits over 2 ms fell inside mark phases (27% of the traced wall time); the readers' own mark assist was under 0.5%. The 4 MiB request (8 MiB as Linux allocates it) holds about 250 ms of private-socket traffic at 4750 CPS (about 1.75 KiB of kernel truesize per datagram), which those waits use up.
* **What does not fix it.** Unsetting `GOMEMLIMIT` changed nothing. `GOGC=200` cut GC to 6 to 14% of CPU and moved the onset to 5000 CPS, but peak RSS reached 7.8 GB. 6 CPUs moved it to 5500. `SO_REUSEPORT` cannot spread the load, because each socket's traffic is one source 4-tuple and lands on one socket, and more than one read loop per socket would break per-dialog wire order.
* **Stopgap and fix.** The UDP SIP receive request is 8 MiB since #235 (granted in full only with `net.core.rmem_max` of 8 MiB or more, see [edge.md](edge.md#udp-socket-buffers)). It rides out longer waits; it does not remove them, and it is not yet measured on the three hosts: the next monthly three-host run confirms whether the loss-free knee moves. The fix is less GC work: #170 (the `drainAcks` bound) and #173 (fewer allocations per call) both landed after the three-host run, so the next monthly run also measures how far they move the knee. To name the dropping socket, `/metrics` has `freesbc_udp_socket_drops_total{socket="public|private"}` and `freesbc_udp_socket_rx_queue_bytes{socket}` (Linux), the kit records them per step (`udp_pub_drops`, `udp_priv_drops` and the receive-queue peaks in `steps.csv`), and `PROFILE_AT=<rate>` saves a CPU profile, an execution trace, a goroutine dump and a heap profile at that step ([test/perf/README.md](../test/perf/README.md)).
* **Switch to carrier.** 2500 to 3000 had a handful of failures (0.001 to 0.002%, under the line); 3500 failed on carrier-leg receive timeouts, with `udp_rcvbuf_errors` 0 throughout.
* Confirm runs at 90%, 120 s: client 2025 CPS (243000 of 243000 ok, CPU 124 / 217, RSS 2535 MB), carrier-in 3150 CPS (378000 of 378000, CPU 171 / 322, RSS 3976 MB), carrier-out 2925 CPS (351000 of 351000, CPU 171 / 294, RSS 3619 MB). All with `udp_rcvbuf_errors` 0. INVITE to 200 p95 under 5 ms at the knees.
* The step table for carrier-in, to show how it scales (40 s steps, 100 = one vCPU):

| CPS | CPU avg / peak | RSS | goroutines | rcvbuf drops |
|---:|---:|---:|---:|---:|
| 1000 | 64 / 105 | 1122 MB | 43971 | 0 |
| 2000 | 120 / 191 | 2228 MB | 87534 | 0 |
| 3000 | 173 / 296 | 3397 MB | 131206 | 0 |
| 3500 | 190 / 339 | 4296 MB | 163419 | 0 |
| 4000 | 213 / 358 | 4850 MB | 184853 | 6514 |
| 5000 | 265 / 422 | 5832 MB | 275673 | 76009 |

### M02 concurrent calls with media

G.711 on both legs, anchored; 60 s ramp then two 60 s holds; `tx_over_rx` 1.0000, 0 failed calls, `invite_rejects`, `admission_drops`, `port_alloc_failures` and `udp_rcvbuf_errors` all 0 at every passing value.

| N requested | plateau calls | CPU avg / peak (of 400) | RSS | goroutines | RTP pps each way |
|---:|---:|---:|---:|---:|---:|
| 250 | 283 | 20 / 21 | 42 MB | 1902 | 28350 |
| 1000 | 1015 | 67 / 71 | 93 MB | 6705 | 101891 |
| 2000 | 2029 | 130 / 138 | 165 MB | 13368 | 203132 |
| 3000 | 2987 | 189 / 203 | 231 MB | 19636 | 298568 |
| 4000 | 3999 | 251 / 271 | 304 MB | 26306 | 400209 |
| **5000** | **5023** | **310 / 338** | **373 MB** | **32977** | **500588** |
| 5500 | 5497 | 337 / 369 | 409 MB | 36116 | 548485 |

* **Maximum 5000** (80% line is 320). 5500 is over the CPU line and its rig check is invalid: the generator's single SIPp process was at 94% of a core (86% at 5000). So quote it as "5000 or slightly more, generator-bound above".
* At 5000: 668 Mbit/s each way, ports in use 10086 (`max_sessions` 25000 not reached), INVITE to 200 mean 8.0 ms (p95 under 20 ms).
* **Latency added (M02c, 1000 concurrent):** via FreeSBC INVITE to 200 mean 3.0 ms (p95 under 10 ms); directly to the switch 3.0 ms (p95 under 5 ms). The difference is below the 1 ms resolution of SIPp's mean and one p95 bucket.
* The soak load is **N70 = 0.7 x 5000 = 3500** concurrent calls.

### M04 registrations

* **Held:** 19000 of 19000 REGISTERs ok, 0 failed, `freesbc_active_registrations` 19000 (cap 20000). RSS 17.9 to 158.2 MB, about **7.4 KB per binding**.
* **Refresh:** every step from 1000 to 20000 REGISTER/s passed with 0.000% failed. At 20000/s: CPU 51 average / 142 peak (13% / 36% of 4 vCPU), RSS 1.44 GB (flat from 15000/s), `udp_rcvbuf_errors` 0, no rejects or drops. **At least 20000 REGISTER/s**: that is the top of the prescribed range, not a limit.

### M05 WebRTC (ICE-Lite + DTLS-SRTP)

Client side over WebSocket (`-W 200` connections; 256 per source IP is the cap), switch side plain RTP echo. Both ladders stopped at the first value where the generator, not FreeSBC, was the limit: one `webrtcload` process.

| Test | Maximum (valid) | FreeSBC at that point | First rig-limited value |
|---|---|---|---|
| DTLS handshakes/s | **100 per second or more** | CPU 64 (16%); 3000 of 3000 calls ok, DTLS p95 1.5 ms, setup p95 2.6 ms | 150/s: `webrtcload` at 100% of a core, FreeSBC at 92 |
| concurrent SRTP calls | **600 or more** | CPU 71 average (18%); 1500 of 1500 calls ok, RSS 299 MB, goroutines 12922, fds 4448 | 800: `webrtcload` at 126% of a core, FreeSBC at 106 (the 800 run itself was clean) |

* Media loss and jitter at 600 calls: 4499968 sent, 4499968 echoed, sequence gaps 0, jitter mean 0.63 ms (p99 1.45 ms), RTT p50 1.4 ms.
* **ws and wss are the same**: `wss://:443` at 100/s and at 600 calls gave 99.35 handshakes/s, 3000 of 3000 and 1500 of 1500 ok, gaps 0, jitter 0.16/0.50 and 0.62/1.48 ms, CPU 62 and 73. No measurable TLS cost at these loads. These are lower bounds: the generator ended both ladders.

### M06 FreeSWITCH as the switch

FreeSWITCH 1.10.0 in Docker on the switch host (8 vCPU), `echo` on extension 2000, FreeSBC on all 4 vCPU. No WARN or ERROR in FreeSWITCH's log during the runs.

| Test | Result | Reading |
|---|---|---|
| CPS, no media (50 to 1500, 30 s steps) | all steps pass, 0.000% failed; FreeSBC CPU 103 at 1500 (26%) | **1500 CPS or more**, switch-limited: FreeSWITCH used 6.6 of 8 vCPU (C at 83%), so the run is invalid as a FreeSBC figure. No `early_cap`: FreeSWITCH answers fast enough for one client source |
| Concurrent calls with media | **3000** (plateau 2987), all values 250 to 3000 pass | top of the prescribed range: FreeSBC CPU 211 (53%), RSS 238 MB, 298450 pps each way, tx/rx 1.0000; FreeSWITCH 2.8 cores (36% of its host). Neither was at its limit |
| Registrations | 5000 held | `show registrations` on FreeSWITCH = 5000, 10000 of 10000 REGISTERs ok |

At 3000 calls FreeSBC's CPU is 211 with FreeSWITCH, against 189 with the SIPp switch at 3000 (M02).

### M07 profiles and the #170 figure

30 s CPU profiles at the confirm runs and at 5000 calls:

* **Signaling (2025 CPS client, 3150 carrier-in, 2925 carrier-out):** about 50% of CPU in sipgo's transaction layer (`handleRequest`, `serverTxRequest`), the edge handlers (`onInvite`, `inviteToUpstream`) about 25%, GC 20 to 23% (`mallocgc` 12 to 20% cumulative; `copystack` about 8%, down from 11.7% on the single host). Timers are not a CPU cost.
* **Media (5000 calls, 312% CPU):** `media.(*Session).forward` 85% cumulative, about 66 to 70% flat in `Syscall6` (`sendto` 44%, `recvfrom` 33%). On a real NIC the send share fell from the single host's 88.5% to 44%, which confirms that the veth path had inflated it. GC is not among the top entries.
* **Goroutines at 2025 CPS (88404):** 64254 `drainAcks` timers, 16080 media readers (2 per live session), 4020 `dialog.confirm` waiters, 4020 `media.watchdog`. At 5000 calls: 32957 total, of which 20160 media readers and 2686 `drainAcks`.
* **Heap at 5000 calls:** 123 MB in use, mostly media buffers; at 2025 CPS 1168 MB in use, per-transaction SIP messages (see the memory section).
* **#170 RSS and goroutines per CPS** (60 s steps, `GOMEMLIMIT` 6 GiB, carrier-in): 1.23 MB and 44.0 per CPS at 1000, 1.24 and 44.0 at 2500, 1.31 and 46.5 at 3500 (RSS 4576 MB). Client calls: 1.61, 1.38, 1.30 MB per CPS at 1000, 1500, 2000 CPS (2500 stops on `early_cap`).

### M08 soak (8 hours)

`run.sh -i 30 -c 3500 -H 240 -t 28800 -u 3500 call`: 3500 concurrent G.711 calls (70% of the M02 maximum), 15 new calls per second, 240 s hold, 17:21 on 10-18 to 01:26 on 10-19 (8 h 05 m; plateau 7 h 57 m). No host was reclaimed or rebooted.

| Result | Value |
|---|---|
| Calls | 432000 created, 432000 ok, **0 failed**; 0 retransmissions; INVITE to 200 mean 7.0 ms, p95 under 20 ms |
| CPU | 235 average / 245 peak (73% of the CPU at the M02 maximum; 58 to 61% of 4 vCPU) |
| Plateau RSS / goroutines / fds / ports (max) | 240 MB / 22122 / 14418 / 7202 |
| Growth, first quarter to last quarter | goroutines +0.0%, RSS -0.3%, open fds +0.0%, ports in use +0.0% (limit 5%) |
| End of run | 33 goroutines, 13 fds, 0 media ports, RSS 170 MB while draining |
| RTP | 10.37 G packets each way, 356k pps average (490 Mbit/s), tx/rx 1.0000 |
| Endings and drops | 432000 of 432000 `bye_caller`; `rtp_silence`, `ack_timeout`, `media_fault`, `invite_rejects`, `admission_drops`, `udp_rcvbuf_errors` all 0; no WARN or ERROR lines from FreeSBC during the soak |

The generator's busiest SIPp was at 63% of a core and the switch's at 44%; neither limited it. **PASS.**

## Micro-benchmarks

`go test -run '^$' -bench . -benchtime 1s -benchmem ./internal/...`, native darwin/arm64 on the M3 Max (16 threads), not in the container. They are for spotting regressions and hot spots, not for sizing a server.

| Benchmark | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| `media.Session.forward` (one packet, one hop, real loopback sockets) | 16293 | 0 | 0 |
| `media.Session.forward`, parallel | 6026 | 1 | 0 |
| SRTP protect RTP, AES-CM-HMAC-SHA1-80 | 387 | 0 | 0 |
| SRTP unprotect RTP, AES-CM-HMAC-SHA1-80 | 430 | 0 | 0 |
| SRTP protect RTP, AEAD-AES-GCM | 146 | 0 | 0 |
| SRTP unprotect RTP, AEAD-AES-GCM | 171 | 0 | 0 |
| SRTP protect RTCP | 181 | 0 | 0 |
| WebRTC demux classify | 0.39 | 0 | 0 |
| WebRTC demux RTP (one packet through the mux) | 18153 | 0 | 0 |
| `dialogTable` begin+end | 425 | 952 | 3 |
| `dialogTable` begin+end, parallel | 986 | 952 | 3 |
| `dialogTable` lookup | 29 | 0 | 0 |
| `dialogTable` lookup, parallel | 212 | 0 | 0 |
| shield `AllowRate`, 1 source / 10000 sources | 95 / 115 | 0 | 0 |
| shield `AllowRate`, parallel | 415 | 0 | 0 |
| shield `CheckFrom`, 1 source / 10000 sources | 265 / 292 | 16 | 1 |
| shield `CheckFrom`, parallel / parallel one source | 655 / 518 | 16 | 1 |
| port pool allocate+release, 0% / 50% / 99% occupied | 47825 / 65535 / 172470 | 768 | 17 |
| port pool, exhausted | 2578 | 132 | 5 |
| `sdp.Parse` plain / sdes / webrtc | 2619 / 3204 / 5476 | 2225 / 2802 / 4677 | 29 / 36 / 39 |
| `sdp.Build`+marshal plain / sdes / webrtc | 359 / 446 / 662 | 352 / 480 / 704 | 1 / 1 / 1 |
| `sdp.Negotiate` plain / webrtc | 357 / 485 | 112 / 176 | 1 / 1 |

Reading them: the parallel variants are slower per operation than the serial ones for `dialogTable.begin`, `lookup` and the shield, the contention the issue predicted (one global mutex each), but at 0.2 to 1 microsecond per call they are far below the per-packet and per-transaction costs below, and did not appear among the top entries of either profile. SRTP is cheap next to the syscalls around it. Port allocation costs 48 to 172 microseconds near exhaustion, which is paid once per call leg. The `forward`, `Parse`, `Build` and `Negotiate` rows are after #173 (relay on `netip.AddrPort`, Build's append writer, Negotiate without maps); their ns/op were measured on a busier host, so compare the ratio to the earlier figures (Build about 0.3x, Negotiate about 0.12x, Parse and `forward` unchanged) rather than the absolute time.

**Full call (#173).** `BenchmarkEdgeCall` (`internal/edge/callbench_test.go`) runs one whole client call per iteration through a real edge over UDP loopback, with raw-socket client and switch peers that allocate almost nothing: INVITE with SDP, 180, 200 with SDP, ACK, BYE, its 200. So allocs/op is the edge's and sipgo's cost per call. `BenchmarkEdgeCallParallel` runs calls from every CPU at once and `BenchmarkEdgeCallPhases` splits the count by message. Base is main before #173 with the same benchmark file, run interleaved with the change (`go test ./internal/edge -run '^$' -bench BenchmarkEdgeCall -benchmem -benchtime=5000x -count=6`, darwin/arm64):

| Benchmark | allocs/op before | after | B/op before | after |
|---|---:|---:|---:|---:|
| `BenchmarkEdgeCall` | 1125 | 777 (-31%) | 66279 | 58853 (-11%) |
| `BenchmarkEdgeCallParallel` | 1143 | 795 (-30%) | 66268 | 58863 (-11%) |

| Phase (`BenchmarkEdgeCallPhases`) | allocs before | after | B before | after |
|---|---:|---:|---:|---:|
| INVITE (client to edge to switch) | 315 | 246 | 18473 | 17234 |
| 180 | 132 | 90 | 7186 | 6594 |
| 200 with SDP | 297 | 160 | 20900 | 16968 |
| ACK | 130 | 96 | 6499 | 5800 |
| BYE | 145 | 114 | 7958 | 7530 |
| 200 to the BYE | 100 | 67 | 4353 | 3957 |

The rest (about 4 allocations) is teardown. ns/op is loopback round trips and does not move. Under `BenchmarkEdgeCallParallel` on Linux (Docker `golang:1.27.2`, 8 vCPU, 100000 calls, three interleaved CPU profiles each), throughput went from about 12200 to 15800 calls/s and CPU per call (edge, sipgo and the benchmark's peers) from 464 to 389 microseconds. GC's share stayed about the same at the higher rate (`gcBgMarkWorker` 18.0% to 16.6%, `mallocgc` 11.1% to 10.7%), so GC CPU per call fell by about a fifth; stack growth (`newstack`) fell from 8.2% to 4.6%, because `guard` now grows each handler goroutine's stack once, while it is shallow (`growStack`).

## Limits a load test hits first

Verified against the code at this commit; the harness configs raise or work around each.

| Limit | Where | Observed here |
|---|---|---|
| `shield.rate_limit` default `20/s per_ip`, counts every public datagram | `internal/config/schema.go:250` | one source gets about 6 CPS before silent drops; `perf-defaults.yaml` shows it (passes 8/s, fails at 14/s) |
| `shield.carrier_rate_limit` default `200/s per_ip` | `schema.go:253` | same for carrier sources |
| Admission: a public INVITE needs a live registration at its exact transport address, or a carrier source | `admission.go` | generator pre-registers from the same IP:port |
| 64 unanswered calls per public IP (`maxEarlyPerSource`); carriers exempt | `internal/edge/invite.go:34` | `early_cap` rejects at 2500 CPS from one client IP on the three-host rig (248 of 100000), 287 at 1700 CPS on the single host |
| RTP range `20000-29999` = 5000 pairs per plane, about 5000 calls; exhaustion is 503 | config | `perf-wide.yaml` widens it to 25000 |
| Registration caps: 20000 bindings, 10 per AoR | `internal/edge/location.go:85-86` | 19000 held |
| UDP receive buffer was the OS default; no `SetReadBuffer` (fixed by #171: 4 MiB receive, 1 MiB send; the receive request is 8 MiB since #235, see [edge.md](edge.md#udp-socket-buffers)) | `internal/edge/sockbuf.go` | three-host run with the 4 MiB buffers: no drops through 3500 CPS carrier-in, drops on both SIP sockets from 3750 (#235: GC mark phases delay each socket's one read loop); 8 MiB is not yet measured there; the single-host `RcvbufErrors` numbers predate #171 |
| 5 min silence watchdog | `rtpSilenceTimeout` | pcap covers the hold |

## How to rerun

The three-host run uses the kit in [`test/perf/hosts/`](../test/perf/hosts/MEASURE.md) (`MEASURE.md` defines each step M01 to M08, its ladder and its pass criteria) with `TOPOLOGY=hosts`; the setup is in "Three real hosts" of the [harness README](../test/perf/README.md). The single-host Docker scenarios still work for a quick check on a laptop:

```sh
FREESBC_CONFIG=perf-wide.yaml test/perf/run.sh up      # build + start; SBC_CPUS=0-1 LOADGEN_CPUS=2-4 SWITCH_CPUS=5-7 SBC_MEM=8g
test/perf/run.sh -n -u 5000 -s 500:2000:100:40 -H 2 call           # client CPS
test/perf/run.sh -n -s 1000:3500:500:60 -H 2 carrier-in            # carrier-in CPS (60 s steps; watch memory)
test/perf/run.sh -n -s 500:2500:250:40 -H 2 carrier-out            # carrier-out CPS
test/perf/run.sh -c 450 -H 30 -t 90 -u 450 call                    # concurrent calls; read the plateau block
test/perf/run.sh -i 5 -u 500 -r 200 -t 10 register                 # goroutine lingering after REGISTERs
test/perf/run.sh -u 19000 -r 6000 -t 9 register                    # registrations
test/perf/run.sh -n -r 400 -t 20 -H 5 webrtc                       # DTLS handshakes/s
test/perf/run.sh -c 800 -t 60 -H 30 webrtc                         # concurrent SRTP calls
test/perf/run.sh down
go test -run '^$' -bench . -benchtime 1s -benchmem ./internal/...  # micro-benchmarks
```

Restart FreeSBC between runs (`docker restart freesbc-perf-freesbc-1`) so RSS and registrations start clean. Profiles: see "Profiling under load" in [test/perf/README.md](../test/perf/README.md). Set `SBC_CPUS`, `LOADGEN_CPUS`, `SWITCH_CPUS` for a VM with a different CPU count, and check `colima list` first. Against a real FreeSWITCH use `SWITCH=freeswitch` (see [test/perf/README.md](../test/perf/README.md#load-through-a-real-freeswitch)).

## Pending

Issue #109's three required runs are done: the [three-host run and FreeSWITCH run](https://github.com/rasonyang/freesbc/issues/109#issuecomment-6249040280) (M01 to M07, 2026-10-18) and the [8 hour soak](https://github.com/rasonyang/freesbc/issues/109#issuecomment-6256238968) (M08, PASS). Open work that touches these numbers:

* #235: carrier-in kernel receive drops from 3750 CPS, on both UDP SIP sockets, because GC mark phases keep each socket's one read loop waiting for a CPU (see M01). 3500 CPS is the loss-free carrier-in ceiling on 4 vCPU. The receive request is 8 MiB as a stopgap, not yet measured on the three hosts; the next monthly run confirms it, together with the GC cuts of #170 and #173, which landed after the run.
* #170: the 2xx wait in `drainAcks` is bounded at 8 s; the next monthly three-host run re-measures goroutines and RSS per CPS. #173: a full client call allocates 777 times, down from 1125 (see Micro-benchmarks); the next three-host run re-measures the GC share at the CPS knees. #171 (closed): re-measured, no drops through 3500 CPS. #172 (closed, not planned): batching RTP syscalls does not pay at this architecture; reopen as one reader over many sockets only if calls per core become the limit.

Not measured, or only a lower bound:

1. **Call setup with more than one source IP.** The 2250 CPS client figure is bounded by `maxEarlyPerSource` (64) at one generator IP.
2. **WebRTC beyond one `webrtcload` process.** 100 handshakes/s and 600 concurrent SRTP calls are the generator's limit; spreading the load over several processes or hosts would find FreeSBC's.
3. **FreeSWITCH beyond the switch's capacity.** 1500 CPS saturated the switch host (6.6 of 8 vCPU) and 3000 concurrent calls and 20000 REGISTER/s are range tops. A larger switch is needed to find FreeSBC's knee with a real switch.
4. **More than 5000 concurrent calls**, which needs more than one SIPp process on the generator (it was at 94% of a core at 5500).
5. **TCP and TLS SIP signaling load**, **SDES-SRTP**, and **switch-to-client calls**. The M05 runs did cover wss with DTLS-SRTP; a tls carrier leg was not loaded.
6. **A soak with FreeSWITCH or WebRTC calls**, and soaks longer than 8 hours or above 70% of the maximum. The soak used UDP, the SIPp switch and 3500 plain calls.
7. **Other host sizes.** Only 4 vCPU (2 cores + HT) was measured; the one-, two- and four-vCPU rounds are M03 at 1000 calls only. Per-vCPU figures above are derived from the 4 vCPU runs.

## Earlier single-host run (kept for history)

Preliminary numbers from the first run, before the three-host rig existed: Docker on Colima on one laptop, FreeSBC pinned to two cores, with the generator, the FreeSBC container and the switch sharing one CPU and one virtual network. **The three-host results above supersede these numbers.** They are kept to show the method's first pass and how the picture changed (the media syscall share, the per-CPS memory, the CPS knees). They predate sipgo v1.6.0 and the UDP buffer fix (#171), so memory, goroutine and receive-drop figures here are out of date; per-core figures are for 2 vCPUs of that VM, not for a server.

### Method and topology

Single-host Docker on Colima: one Apple M3 Max laptop, one Colima VM, five containers on two bridge networks.

```text
 loadgen / carriergen            FreeSBC (pinned to 2 cores)               switch / carrier
 SIPp UAC, webrtcload   --->  public side | private side  --->  SIPp UAS, -rtp_echo
 cpus 2-4                        cpus 0-1, 8 GiB limit                        cpus 5-7
```

* FreeSBC is pinned to **2 cores** (`cpuset: 0-1`, `SBC_CPUS`) and limited to 8 GiB (`SBC_MEM`). The load generators (SIPp UAC, `webrtcload`) get CPUs 2-4 and the "switch" and carrier (SIPp UAS with RTP echo) get CPUs 5-7, so FreeSBC, not the generator, is the saturated part (checked with `docker stats` during the runs: generators and switch stayed far below their sets). Go sees two CPUs (`nproc` 2), so `GOMAXPROCS=2`.
* **The generator, the switch and FreeSBC share the same physical CPU, caches, memory bandwidth and the VM's virtual network (veth + Linux bridge).** On this path a `sendto` carries the delivery to the receiving container in the sender's context, so syscall cost is probably higher than on a real NIC. Per-core figures are honest for "2 vCPUs of this VM", not for a server.
* The switch is a SIPp UAS that answers instantly and echoes RTP, so no switch is the bottleneck. FreeSWITCH was not used in this run; see M06 above for the three-host run against it.
* Signaling is UDP; media is G.711 (PCMU) 20 ms, both directions, both legs, anchored by FreeSBC. WebRTC uses ICE-Lite + DTLS-SRTP over plain `ws://` (the `webrtcload` client is a pion client).
* Config: `test/perf/configs/perf-wide.yaml` (RTP range 10000-59999, `shield` limits raised to 1000000/s, `admin.pprof: true`). Log level is the default (INFO), so each call writes lines to stdout, which Docker stores; this cost is part of the numbers.
* FreeSBC was restarted before each measurement. Pass criterion for CPS: under 0.1% failed calls (SIPp). Concurrent-call criterion: process CPU under 80% of the two pinned cores (160 on the "one core = 100" scale), no failed calls, FreeSBC rtp tx/rx at least 0.999.
* Sampling: FreeSBC `/metrics` plus `/proc/<pid>` every 2 s (10 s for the soak): CPU, RSS, goroutines, open fds, `freesbc_media_ports_in_use`, live RTP pps, and the kernel's UDP `RcvbufErrors` for the container. "CPU" below is a percentage of one core (200 = both pinned cores busy).

### Hardware and versions

| Item | Value |
|---|---|
| Host | Apple M3 Max, 16 cores, 128 GiB, macOS 26.6.2 |
| Colima VM | macOS Virtualization.Framework, aarch64, **8 CPUs, 12 GiB**, Docker 28.4.0, kernel 6.8.0-64-generic (Ubuntu), `net.core.rmem_default` = `rmem_max` = 212992 |
| Other containers in the VM | unrelated, idle (postgres, seaweedfs, buildkit); under 5% CPU |
| Go | 1.27.2 (binary built in `golang:1.27.2`, linux/arm64, static) |
| FreeSBC | commit `49d97140588bbeeeb1f4357ac1c48c9b89bb0cea` (`v0.1.0-182-g49d9714`) plus the harness changes in this change set (`test/perf/` only; no product code differs) |
| SIPp | 3.6.1 (Debian `sip-tester`) |

### Results

All tables are one run each unless stated (single host, single run: no confidence interval). "SIPp p95" is SIPp's response-time bucket upper bound for INVITE to 200 through FreeSBC to an instant UAS (buckets 1, 2, 5, 10, 20, 50, ... ms); it includes the generator and the switch, so FreeSBC's own added latency is at most this and was not isolated.

#### a. Client call setup rate (signaling only)

Registered UA (one source socket, 5000 users) to FreeSBC to switch, UDP, no RTP, 2 s hold, 40 s per step, `run.sh -n -u 5000 -s 500:2000:100:40 -H 2 call`. FreeSBC still allocates and tears down its media ports per call.

| CPS | failed | CPU avg / peak | RSS peak | goroutines peak | UDP rcvbuf drops |
|---:|---:|---:|---:|---:|---:|
| 500 | 0 | 31 / 52 | 1.0 GB | 38k | 0 |
| 1000 | 0 | 53 / 99 | 2.1 GB | 76k | 0 |
| 1400 | 0 | 67 / 112 | 2.7 GB | 106k | 0 |
| **1500** | **0** | 75 / 129 | 3.1 GB | 114k | 0 |
| 1600 | 0.656% | 75 / 153 | 3.2 GB | 121k | 484 |

* **Max sustained: 1500 CPS** (under 0.1% failed), SIPp p95 under 5 ms. At that rate FreeSBC used 0.75 of its 2 cores, so the limit is not total CPU (see [bottleneck](#first-bottleneck-signaling)).
* An earlier run of the same scenario (before the drop counter existed) failed at 1700 CPS with `invite_rejects{reason="early_cap"}` = 287: one source IP is limited to 64 unanswered INVITEs (`maxEarlyPerSource`, `internal/edge/invite.go:34`), so a single-IP generator at this rate can hit that cap as well. Carrier sources are exempt, which is why the carrier runs go higher.

#### b. Concurrent G.711 calls

Client calls with RTP both directions (SIPp pcap play, switch UAS echo), 30 s hold, ramp then about 60 s plateau, `run.sh -c N -H 30 -t 90 -u N call`. Every row: restart, then one run. Packets per call: about 100 pps received and 100 pps sent by FreeSBC (50 pps each way on each of two legs).

| Concurrent calls (plateau avg) | failed calls | CPU avg / peak | rx pps (= tx pps) | tx/rx | RSS | goroutines | open fds | ports in use |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 269 | 0 | 79 / 92 | 26968 | 1.0000 | 51 MB | 2232 | 1098 | 542 |
| 358 | 0 | 100 / 111 | 36021 | 1.0000 | n/m | n/m | n/m | n/m |
| 419 | 0 | 123 / 136 | 42085 | 1.0000 | n/m | n/m | n/m | n/m |
| **449** | **0** | **122 / 138** | 45324 | 1.0000 | n/m | n/m | n/m | n/m |
| 509 | 0 | 172 / 190 (163 / 182 in a repeat) | 51704 | 1.0000 | 80 MB | 4185 | 2058 | 1022 |
| 623 (peak 888, ramp stalled) | 37% | 201 / 329 | 65375 | 0.9996 | 120 MB | 7441 | 3990 | 1902 |

(n/m: not recorded in the notes of that run; the per-run output directories hold the numbers.)

* **Max with CPU under 80% of the two cores (160): about 450 concurrent calls** (449 at 122). The next measured point, 509, is at 163 to 172 and over the line; 1000 requested calls saturate both cores and fail 37% of calls. The step between 450 and 500 was not probed more finely.
* That is about 225 calls per pinned core. Expressed per packet: about 27 microseconds of CPU per forwarded packet in this topology (122% of a core at 45.3k forwarded pps; derived).
* Memory is small for media calls: 80 MB RSS at 509 calls, about 0.13 MB per call (derived, includes the process baseline).
* **Caveat on the tx/rx ratio.** FreeSBC's `tx/rx` only compares what FreeSBC received with what it sent. A datagram that the kernel drops on a full receive buffer never reaches the counter, so tx/rx 1.0 does not exclude kernel loss. The sampler therefore also records the container's UDP `RcvbufErrors` (it reads `/proc/<pid>/net/snmp` itself; on Linux `/metrics` now exports the same kernel counts as `freesbc_udp_receive_buffer_errors_total` and `freesbc_udp_in_errors_total`, network-namespace wide): it was 0 in the carrier runs below, which have the counter; the client-call rows above were taken before the counter existed, so their kernel drops are unknown. SIPp does not measure received loss or jitter, so end-to-end media loss for UDP calls was not measured here; the WebRTC runs below did, and the three-host probes (M03) measured it for UDP calls: loss 0.000%, jitter mean 0.47 ms.

Carrier legs with media, same method (`carrier-in`: carrier source, no REGISTER; `carrier-out`: switch to carrier):

| Scenario | Concurrent calls | CPU avg / peak | rx pps | tx/rx | UDP rcvbuf drops |
|---|---:|---:|---:|---:|---:|
| carrier-in | 448 | 123 / 143 | 44664 | 1.0000 | 0 |
| carrier-in | 507 | 167 / 187 | 50745 | 1.0000 | 0 |
| carrier-out | 448 | 117 / 137 | 45322 | 1.0000 | 0 |
| carrier-out | 507 | 162 / 186 | 50855 | 1.0000 | 0 |

The carrier path costs the same as the client path (it adds topology hiding and a second SDP build, which does not show up). Same limit: about 450 calls under 80% of two cores.

#### c. Carrier call setup rate (signaling only)

2 s hold, no RTP.

| Direction | Step length | Max sustained | Next step | Notes |
|---|---|---|---|---|
| carrier-in | 60 s steps | **3000 CPS** (0 failed) | 3500: killed by the 8 GiB memory limit | at 3000: CPU 126 / 219, RSS 7.2 GB, 252k goroutines, **155315 datagrams dropped on the receive buffer** though SIPp saw 0 failures (retransmissions recovered them) |
| carrier-out | 40 s steps | **1250 CPS** clean; 1500 at 0.090% (passes the 0.1% line, 111 drops) | 1750: 3.4% failed, 6428 drops | |

carrier-in step table (60 s each):

| CPS | failed | CPU avg / peak | RSS peak | goroutines peak | rcvbuf drops |
|---:|---:|---:|---:|---:|---:|
| 1000 | 0 | 49 / 95 | 2.3 GB | 76k | 0 |
| 1500 | 0 | 74 / 147 | 3.3 GB | 114k | 406 |
| 2000 | 0 | 90 / 181 | 4.5 GB | 156k | 22552 |
| 2500 | 0 | 106 / 206 | 5.6 GB | 202k | 83948 |
| 3000 | 0 | 126 / 219 | 7.2 GB | 252k | 155315 |
| 3500 | 12.5% (OOM at 8 GiB) | 145 / 225 | 7.9 GB | 295k | 203948 |

A run at 3500 CPS for 70 s was also killed by the memory limit (`OOMKilled=true`) after 45 s. In a shorter first sweep with 30 s steps, 3500 passed at 0.003% with 6.5 GB, which shows why the step length matters: memory keeps rising until the transaction lingering below reaches steady state (about 35 to 45 s). All rig figures in this section were taken before the sipgo v1.6.0 upgrade and the receive-buffer fix (#171); the three-host run re-measured them (carrier-in 3500 CPS loss-free, see M01 above), so do not plan with the 1500 and 3000 CPS figures here. In every row the process was below 2 cores of CPU.

#### d. Registrations

19000 users (the binding cap is 20000, `defaultMaxBindings`), from one socket, `run.sh -u 19000 -r <rate> register`; the first round creates the bindings, later rounds refresh them with the same Call-ID.

| REGISTER/s | rounds | failed / 503 | CPU avg / peak | RSS peak | goroutines peak |
|---:|---:|---:|---:|---:|---:|
| 1000 (create + 2 refreshes) | 3 | 0 | 29 / 42 | 706 MB | 28.8k |
| 3000 (refresh) | 3 | 0 | 36 / 65 | 915 MB | n/m |
| 6000 (refresh) | 3 | 0 | 43 / 97 | 1.6 GB | n/m |

* 19000 bindings held (`freesbc_active_registrations` = 19000), no 503, no shield or admission drops, no kernel drops. 6000 REGISTER/s was the highest rate tried; the limit was not found.
* After the burst, goroutines returned to the 30 baseline and the live heap after a forced GC was **54 MB for 19000 bindings (about 2.8 KB per binding, derived)**. RSS stays at 1.7 GB because Go keeps the freed memory (it had been used by the transaction goroutines above); this is retained, not live, memory.

#### e. WebRTC (ICE-Lite + DTLS-SRTP over ws)

DTLS handshakes per second (`webrtcload`, ICE + DTLS only, 5 s calls, `run.sh -n -r R -t 20 -H 5 webrtc`):

| Handshakes/s (offered) | achieved | failed calls | CPU avg / peak (plateau) | setup p95 | DTLS p95 |
|---:|---:|---:|---:|---:|---:|
| 100 | 99 | 0 | 23 / 28 | 3.1 ms | 1.3 ms |
| 200 | 196 | 0 | 50 / 56 | 3.1 ms | 1.4 ms |
| **400** | **394** | **0** | 92 / 115 | 11.6 ms | 10.4 ms |
| 500 | 467 | 4.4% | 115 / 136 | 30 ms | 29 ms |
| 700 | 592 | 8.6% | 162 / 192 | 99 ms | 149 ms |

**Max clean handshake rate: about 400 per second** on two cores (the client measures its side; "DTLS p95" is the handshake as the load client sees it). Failures above that came with kernel receive-buffer drops (978 at 700/s).

Concurrent SRTP calls (G.711 20 ms, echoed through FreeSBC and the switch UAS; `run.sh -c N -t 60 -H 30 webrtc`):

| Concurrent calls | failed | CPU avg / peak | rx pps | lost (sequence gaps) | jitter p99 | RSS | goroutines | fds |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 121 | 0 | 21 / 25 | 11982 | 0 of 360000 | 0.7 ms | 65 MB | 2606 | 888 |
| 301 | 0 | 51 / 56 | 30071 | 0 of 899999 | 2.3 ms | 135 MB | 6441 | 2169 |
| 424 | 0 | 74 / 87 | 40810 | 0 of 1259997 | 1.2 ms | 179 MB | 8976 | 3016 |
| 602 | 0 | 104 / 118 | 60551 | 0 of 1799999 | 3.5 ms | 251 MB | 12811 | 4297 |
| **816** | 0 | 141 / 154 | 81660 | 43 of 2429986 (0.0018%) | 4.2 ms | 333 MB | 17295 | 5795 |
| 1027 | 0 | 169 / 193 | 100943 | 567 of 3059967 (0.019%) | 5.7 ms | 406 MB | 21736 | 7279 |

**Max concurrent SRTP calls with CPU under 80% of the two cores (160): about 800** (816 at 141, loss 0.0018%). At 1027 calls CPU is 169, still under 0.1% loss. These are the only runs with a measured end-to-end loss and jitter. Interestingly one WebRTC call costs less CPU per packet than a plain UDP call here (169% for 101k pps against 172% for 52k pps). This was not investigated; one candidate is that SIPp's pcap player sends every call's packet on the same 20 ms tick in bursts while `webrtcload` spreads them, so the receiving socket queues differ. That is a hypothesis, not a finding.

#### f. Mini soak (not the issue's 8 h soak)

> **This is a 30 minute run. It is not the 8 to 24 hour soak the issue requires, and it does not close that criterion.**

`run.sh -i 10 -c 320 -H 60 -t 1800 -u 320 call`: client calls with G.711 both directions, 6 new calls per second, 60 s hold. SIPp's concurrency cap (`-l`) let the plateau settle at **360 concurrent calls (peak 361), about 80% of the 450-call figure, not exactly 70%**. Duration 1860 s (31 minutes). Samples every 10 s.

| Metric | Start | After warm-up (t=160 s) | t=1684 s (about 28 min) | Peak over the run |
|---|---:|---:|---:|---:|
| Active calls | 0 | 360 | 360 | 361 |
| Goroutines | 30 | 2574 | 2574 | 2580 |
| Open fds | 14 | 1454 | 1454 | 1458 |
| Ports in use | 0 | 720 | 720 | 722 |
| RSS | 15.6 MiB | 50.5 MiB | 52.4 MiB | 52.9 MiB |
| Heap in use | | | | 22.2 MB (end 20.5 MB) |

RSS rose from 50.5 to 52.4 MiB over the 28 minutes (the goroutine, fd and port counts did not move at all); the run is too short to say whether that 2 MiB is warm-up or a slow drift, which is exactly what the long soak is for. Process CPU on the plateau: 85% of one core average, 91% peak (43% of the two pinned cores). 10800 calls, 0 failed, 0 retransmissions, rx 64843188 packets and tx 64843177 (tx/rx 1.0000), `RcvbufErrors` 0, no 503, no admission or shield drops. At the end ports in use returned to 0 and fds to 14.

An earlier attempt at the same run is discarded: the host or VM stalled for 447 s in the middle (a gap in the sampler, 459231 kernel receive-buffer drops in one interval, SIPp elapsed 2297 s). The rerun used `caffeinate` and had no gap.

#### g. Profiles and the first bottleneck

CPU profiles are 30 s `/debug/pprof/profile` samples taken from inside the container under load, read with the matching binary.

<a id="first-bottleneck-signaling"></a>

**Signaling (CPS), as measured before the sipgo v1.6.0 upgrade: the first limit is not CPU but memory and the receive buffer, driven by one goroutine per server transaction that lingered for ~32 s.** Evidence (all pre-v1.6.0):

1. A goroutine dump at 2500 CPS (carrier-in): 189159 goroutines, **159195 of them (84%) in one stack**: `sipgo.(*Server).handleRequest` (`server.go:267`) blocked in `sip.(*ServerTx).TerminateGracefully` (`transaction_server_tx.go:181`), which waits on `<-tx.Done()` until the transaction's timers expire (Timer J, 32 s, for non-INVITE over UDP, and Timer H/I for INVITE). A further 19932 are the media UDP readers. Goroutines scale at about 76 per CPS (75961 at 1000 CPS, 114k at 1500, 155k at 2000) and are flat in time at a given rate.
2. Memory follows: about 2.3 MB of RSS per CPS (2.3 GB at 1000, 3.3 GB at 1500, 7.2 GB at 3000). At 3500 CPS the 8 GiB limit killed the process. Live-heap profile at 2500 CPS (2.0 GB in use): sipgo `NewRequest`, `NewResponse`, `ParseHeader` and header clones, `NewServerTx`, plus `dialogTable.begin` and port allocation. These are the lingering per-transaction objects.

   **Since the sipgo v1.6.0 upgrade** the handler goroutine is no longer parked: v1.6.0's `ServerTx.TerminateGracefully` returns at once for a finalised unreliable transaction and leaves the transaction to sipgo's timers (the edge's own `serveTx`, #170, did the same on v1.4.3 and v1.5.0 and was removed). The goroutine counts, stack memory and the 64 parked goroutines per CPS above are therefore gone, and the three-host run re-measured it (about 44 goroutines and 1.25 MB of RSS per CPS, see the [memory section](#memory-cps-and-gomemlimit)). sipgo still keeps the transaction record, request and response until its timers expire (up to 32 s), and other state (sipgo client transactions toward the switch, dialog and media objects, ended-dialog hooks) may also be held for a similar time, so RSS per CPS is not expected to be zero. In the in-process harness the removal took 64 goroutines and about 0.5 MB of stack per CPS out of calls and halved RSS per request/s for transactions the edge answers itself. See [the research note](notes/170-sipgo-tx-linger.md).
3. CPU profile at 2500 CPS (31.9 s of CPU in 30 s, one core of two): `syscall` 21.6% flat (`sendto` 10.1% and `recvfrom` 8.5% cumulative), GC 22% (`gcBgMarkWorker` 9% plus `gcAssistAlloc` 12.8%), goroutine stack growth `runtime.copystack` 11.7% (every request starts a new goroutine that grows its stack), `mallocgc` 16%. FreeSBC's own handlers (`onInvite`, `relayResponseHide`, `onInDialog`) are under 25% each cumulative and mostly time inside `sendto`.
4. Failure mode: before calls fail, the kernel drops datagrams on the SIP sockets (`RcvbufErrors` 406 at 1500 CPS, 22552 at 2000, 155315 at 3000; none below 1500). The receive buffer is the Linux default (212992 bytes on this VM; `rmem_max` is the same) and FreeSBC does not call `SetReadBuffer`; each UDP socket has one reader loop. Bursts plus GC pauses fill it, SIPp retransmits (T1 500 ms), and above ~1500 to 1600 CPS retransmissions no longer rescue the calls. Issue #171 (closed) set 4 MiB receive and 1 MiB send buffers on the UDP SIP sockets, and the three-host run re-measured it: no drops through 3500 CPS carrier-in (the drops from 3750 are #235).

**Media: the first limit is the per-packet `sendto` syscall.** CPU profile at 509 concurrent calls (51k pps in, 51k out, process at 163%): **93.7% of all samples are in `syscall.Syscall6`; 88.5% are under `net.(*UDPConn).WriteTo` / `syscall.sendto`, 5.5% under `recvfrom`**, called from `media.(*Session).forward`. SRTP, mutexes, the scheduler and GC together are under 6%. There is one `recvfrom` and one `sendto` per packet. On this topology the send cost is inflated because the veth/bridge delivery to the next container is charged to the sender, so on a real NIC the share will be lower but the syscall will probably still lead; that is untested.

**Goroutines after REGISTER bursts: transaction timers, not a leak (before sipgo v1.6.0).** A burst of 2000 REGISTERs from 500 users (`run.sh -u 500 -r 200 -t 10 register`, i.e. four rounds) left **2027 goroutines, 2000 of them in the same `ServerTx.TerminateGracefully` stack**. Counted every 10 s after the last REGISTER: 2030, 1531, 530, 30, 30, 30, 30. They drain to the 30-goroutine baseline within about 40 s, which matches the 32 s Timer J. With sipgo v1.6.0 these goroutines are no longer parked, so this drain-to-baseline curve is expected to be flat; the three-host run saw goroutines return to about 33 after each run. The report of about 1360 goroutines still present after a minute did **not** reproduce in this setup (UDP, instant 200 from the switch, no digest challenge). If it recurs, collect `/debug/pprof/goroutine?debug=1` at that moment: stacks other than `TerminateGracefully` would indicate something else (a TCP/WS connection per user, for example, holds goroutines for as long as the connection lives).
