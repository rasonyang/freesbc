# Performance

Preliminary capacity numbers for FreeSBC from a **single-host** run, with the method and harness in [`test/perf/`](../test/perf/README.md) so anyone can repeat it. Read the caveats first: this is not the three-host topology that issue #109 asks for, and the numbers are not yet a basis for a production sizing. What still has to be run is in [Pending](#pending).

All figures below were measured; anything derived or estimated is marked so. Nothing here is a promise.

## Method and topology

Single-host Docker on Colima: one Apple M3 Max laptop, one Colima VM, five containers on two bridge networks.

```text
 loadgen / carriergen            FreeSBC (pinned to 2 cores)               switch / carrier
 SIPp UAC, webrtcload   --->  public 172.28.1.10 | private 172.28.2.10  --->  SIPp UAS, -rtp_echo
 cpus 2-4                        cpus 0-1, 8 GiB limit                        cpus 5-7
```

* FreeSBC is pinned to **2 cores** (`cpuset: 0-1`, `SBC_CPUS`) and limited to 8 GiB (`SBC_MEM`). The load generators (SIPp UAC, `webrtcload`) get CPUs 2-4 and the "switch" and carrier (SIPp UAS with RTP echo) get CPUs 5-7, so FreeSBC, not the generator, is the saturated part (checked with `docker stats` during the runs: generators and switch stayed far below their sets). Go sees two CPUs (`nproc` 2), so `GOMAXPROCS=2`.
* **The generator, the switch and FreeSBC share the same physical CPU, caches, memory bandwidth and the VM's virtual network (veth + Linux bridge).** On this path a `sendto` carries the delivery to the receiving container in the sender's context, so syscall cost is probably higher than on a real NIC. Per-core figures are honest for "2 vCPUs of this VM", not for a server.
* The switch is a SIPp UAS that answers instantly and echoes RTP, so no switch is the bottleneck. **There is no run against FreeSWITCH.**
* Signaling is UDP; media is G.711 (PCMU) 20 ms, both directions, both legs, anchored by FreeSBC. WebRTC uses ICE-Lite + DTLS-SRTP over plain `ws://` (the `webrtcload` client is a pion client).
* Config: `test/perf/configs/perf-wide.yaml` (RTP range 10000-59999, `shield` limits raised to 1000000/s, `admin.pprof: true`). Log level is the default (INFO), so each call writes lines to stdout, which Docker stores; this cost is part of the numbers.
* FreeSBC was restarted before each measurement. Pass criterion for CPS: under 0.1% failed calls (SIPp). Concurrent-call criterion: process CPU under 80% of the two pinned cores (160 on the "one core = 100" scale), no failed calls, FreeSBC rtp tx/rx at least 0.999.
* Sampling: FreeSBC `/metrics` plus `/proc/<pid>` every 2 s (10 s for the soak): CPU, RSS, goroutines, open fds, `freesbc_media_ports_in_use`, live RTP pps, and the kernel's UDP `RcvbufErrors` for the container. "CPU" below is a percentage of one core (200 = both pinned cores busy).

## Hardware and versions

| Item | Value |
|---|---|
| Host | Apple M3 Max, 16 cores, 128 GiB, macOS 26.6.2 |
| Colima VM | macOS Virtualization.Framework, aarch64, **8 CPUs, 12 GiB**, Docker 28.4.0, kernel 6.8.0-64-generic (Ubuntu), `net.core.rmem_default` = `rmem_max` = 212992 |
| Other containers in the VM | unrelated, idle (postgres, seaweedfs, buildkit); under 5% CPU |
| Go | 1.27.2 (binary built in `golang:1.27.2`, linux/arm64, static) |
| FreeSBC | commit `49d97140588bbeeeb1f4357ac1c48c9b89bb0cea` (`v0.1.0-182-g49d9714`) plus the harness changes in this change set (`test/perf/` only; no product code differs) |
| SIPp | 3.6.1 (Debian `sip-tester`) |

## Micro-benchmarks

`go test -run '^$' -bench . -benchtime 1s -benchmem ./internal/...`, native darwin/arm64 on the M3 Max (16 threads), not in the container. They are for spotting regressions and hot spots, not for sizing a server.

| Benchmark | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| `media.Session.forward` (one packet, one hop, real loopback sockets) | 16293 | 16 | 1 |
| `media.Session.forward`, parallel | 6026 | 17 | 1 |
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
| `sdp.Parse` plain / sdes / webrtc | 2619 / 3204 / 5476 | 2265 / 2842 / 4773 | 32 / 39 / 43 |
| `sdp.Build`+marshal plain / sdes / webrtc | 1250 / 1360 / 2043 | 1344 / 1617 / 2273 | 31 / 34 / 41 |

Reading them: the parallel variants are slower per operation than the serial ones for `dialogTable.begin`, `lookup` and the shield, the contention the issue predicted (one global mutex each), but at 0.2 to 1 microsecond per call they are far below the per-packet and per-transaction costs below, and did not appear among the top entries of either profile. SRTP is cheap next to the syscalls around it. Port allocation costs 48 to 172 microseconds near exhaustion, which is paid once per call leg.

## Results

All tables are one run each unless stated (single host, single run: no confidence interval). "SIPp p95" is SIPp's response-time bucket upper bound for INVITE to 200 through FreeSBC to an instant UAS (buckets 1, 2, 5, 10, 20, 50, ... ms); it includes the generator and the switch, so FreeSBC's own added latency is at most this and was not isolated.

### a. Client call setup rate (signaling only)

Registered UA (one source socket, 5000 users) to FreeSBC to switch, UDP, no RTP, 2 s hold, 40 s per step, `run.sh -n -u 5000 -s 500:2000:100:40 -H 2 call`. FreeSBC still allocates and tears down its media ports per call.

| CPS | failed | CPU avg / peak | RSS peak | goroutines peak | UDP rcvbuf drops |
|---:|---:|---:|---:|---:|---:|
| 500 | 0 | 31 / 52 | 1.0 GB | 38k | 0 |
| 1000 | 0 | 53 / 99 | 2.1 GB | 76k | 0 |
| 1400 | 0 | 67 / 112 | 2.7 GB | 106k | 0 |
| **1500** | **0** | 75 / 129 | 3.1 GB | 114k | 0 |
| 1600 | 0.656% | 75 / 153 | 3.2 GB | 121k | 484 |

* **Max sustained: 1500 CPS** (under 0.1% failed), SIPp p95 under 5 ms. At that rate FreeSBC used 0.75 of its 2 cores, so the limit is not total CPU (see [bottleneck](#first-bottleneck-signaling)).
* An earlier run of the same scenario (before the drop counter existed) failed at 1700 CPS with `invite_rejects{reason="early_cap"}` = 287: one source IP is limited to 64 unanswered INVITEs (`maxEarlyPerSource`, `internal/edge/invite.go:35`), so a single-IP generator at this rate can hit that cap as well. Carrier sources are exempt, which is why the carrier runs go higher.

### b. Concurrent G.711 calls

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
* **Caveat on the tx/rx ratio.** FreeSBC's `tx/rx` only compares what FreeSBC received with what it sent. A datagram that the kernel drops on a full receive buffer never reaches the counter. The sampler therefore also records the container's UDP `RcvbufErrors`: it was 0 in the carrier runs below, which have the counter; the client-call rows above were taken before the counter existed, so their kernel drops are unknown. SIPp does not measure received loss or jitter, so end-to-end media loss for UDP calls is **not measured**; the WebRTC runs below do measure it.

Carrier legs with media, same method (`carrier-in`: carrier source, no REGISTER; `carrier-out`: switch to carrier):

| Scenario | Concurrent calls | CPU avg / peak | rx pps | tx/rx | UDP rcvbuf drops |
|---|---:|---:|---:|---:|---:|
| carrier-in | 448 | 123 / 143 | 44664 | 1.0000 | 0 |
| carrier-in | 507 | 167 / 187 | 50745 | 1.0000 | 0 |
| carrier-out | 448 | 117 / 137 | 45322 | 1.0000 | 0 |
| carrier-out | 507 | 162 / 186 | 50855 | 1.0000 | 0 |

The carrier path costs the same as the client path (it adds topology hiding and a second SDP build, which does not show up). Same limit: about 450 calls under 80% of two cores.

### c. Carrier call setup rate (signaling only)

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

A run at 3500 CPS for 70 s was also killed by the memory limit (`OOMKilled=true`) after 45 s. In a shorter first sweep with 30 s steps, 3500 passed at 0.003% with 6.5 GB, which shows why the step length matters: memory keeps rising until the transaction lingering below reaches steady state (about 35 to 45 s). **Treat 1500 CPS (clean, 3.3 GB) as the carrier-in figure to plan with on these two cores, and 3000 CPS as a burst ceiling that needs more than 7 GB.** In every row the process was below 2 cores of CPU.

### d. Registrations

19000 users (the binding cap is 20000, `defaultMaxBindings`), from one socket, `run.sh -u 19000 -r <rate> register`; the first round creates the bindings, later rounds refresh them with the same Call-ID.

| REGISTER/s | rounds | failed / 503 | CPU avg / peak | RSS peak | goroutines peak |
|---:|---:|---:|---:|---:|---:|
| 1000 (create + 2 refreshes) | 3 | 0 | 29 / 42 | 706 MB | 28.8k |
| 3000 (refresh) | 3 | 0 | 36 / 65 | 915 MB | n/m |
| 6000 (refresh) | 3 | 0 | 43 / 97 | 1.6 GB | n/m |

* 19000 bindings held (`freesbc_active_registrations` = 19000), no 503, no shield or admission drops, no kernel drops. 6000 REGISTER/s was the highest rate tried; the limit was not found.
* After the burst, goroutines returned to the 30 baseline and the live heap after a forced GC was **54 MB for 19000 bindings (about 2.8 KB per binding, derived)**. RSS stays at 1.7 GB because Go keeps the freed memory (it had been used by the transaction goroutines above); this is retained, not live, memory.

### e. WebRTC (ICE-Lite + DTLS-SRTP over ws)

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

### f. Mini soak (not the issue's 8 h soak)

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

### g. Profiles and the first bottleneck

CPU profiles are 30 s `/debug/pprof/profile` samples taken from inside the container under load, read with the matching binary.

<a id="first-bottleneck-signaling"></a>

**Signaling (CPS): the first limit is not CPU but memory and the receive buffer, driven by one goroutine per server transaction that lingers for ~32 s.** Evidence:

1. A goroutine dump at 2500 CPS (carrier-in): 189159 goroutines, **159195 of them (84%) in one stack**: `sipgo.(*Server).handleRequest` (`server.go:267`) blocked in `sip.(*ServerTx).TerminateGracefully` (`transaction_server_tx.go:181`), which waits on `<-tx.Done()` until the transaction's timers expire (Timer J, 32 s, for non-INVITE over UDP, and Timer H/I for INVITE). A further 19932 are the media UDP readers. Goroutines scale at about 76 per CPS (75961 at 1000 CPS, 114k at 1500, 155k at 2000) and are flat in time at a given rate.
2. Memory follows: about 2.3 MB of RSS per CPS (2.3 GB at 1000, 3.3 GB at 1500, 7.2 GB at 3000). At 3500 CPS the 8 GiB limit killed the process. Live-heap profile at 2500 CPS (2.0 GB in use): sipgo `NewRequest`, `NewResponse`, `ParseHeader` and header clones, `NewServerTx`, plus `dialogTable.begin` and port allocation. These are the lingering per-transaction objects.
3. CPU profile at 2500 CPS (31.9 s of CPU in 30 s, one core of two): `syscall` 21.6% flat (`sendto` 10.1% and `recvfrom` 8.5% cumulative), GC 22% (`gcBgMarkWorker` 9% plus `gcAssistAlloc` 12.8%), goroutine stack growth `runtime.copystack` 11.7% (every request starts a new goroutine that grows its stack), `mallocgc` 16%. FreeSBC's own handlers (`onInvite`, `relayResponseHide`, `onInDialog`) are under 25% each cumulative and mostly time inside `sendto`.
4. Failure mode: before calls fail, the kernel drops datagrams on the SIP sockets (`RcvbufErrors` 406 at 1500 CPS, 22552 at 2000, 155315 at 3000; none below 1500). The receive buffer is the Linux default (212992 bytes on this VM; `rmem_max` is the same) and FreeSBC does not call `SetReadBuffer`; each UDP socket has one reader loop. Bursts plus GC pauses fill it, SIPp retransmits (T1 500 ms), and above ~1500 to 1600 CPS retransmissions no longer rescue the calls.

**Media: the first limit is the per-packet `sendto` syscall.** CPU profile at 509 concurrent calls (51k pps in, 51k out, process at 163%): **93.7% of all samples are in `syscall.Syscall6`; 88.5% are under `net.(*UDPConn).WriteTo` / `syscall.sendto`, 5.5% under `recvfrom`**, called from `media.(*Session).forward`. SRTP, mutexes, the scheduler and GC together are under 6%. There is one `recvfrom` and one `sendto` per packet. On this topology the send cost is inflated because the veth/bridge delivery to the next container is charged to the sender, so on a real NIC the share will be lower but the syscall will probably still lead; that is untested.

**Goroutines after REGISTER bursts: transaction timers, not a leak.** A burst of 2000 REGISTERs from 500 users (`run.sh -u 500 -r 200 -t 10 register`, i.e. four rounds) left **2027 goroutines, 2000 of them in the same `ServerTx.TerminateGracefully` stack**. Counted every 10 s after the last REGISTER: 2030, 1531, 530, 30, 30, 30, 30. They drain to the 30-goroutine baseline within about 40 s, which matches the 32 s Timer J. The report of about 1360 goroutines still present after a minute did **not** reproduce in this setup (UDP, instant 200 from the switch, no digest challenge). If it recurs, collect `/debug/pprof/goroutine?debug=1` at that moment: stacks other than `TerminateGracefully` would indicate something else (a TCP/WS connection per user, for example, holds goroutines for as long as the connection lives).

## Sizing guidance

From this single-host, two-core, Docker-on-Colima topology only. Treat as a floor to test against on real hardware, not as a prediction. Figures marked (derived) are arithmetic on the measurements.

| Dimension | Figure measured | Per core (derived) | Notes |
|---|---|---|---|
| Client call setup | 1500 CPS (fails at 1600), 0.75 core used | not CPU-bound | memory about 2.3 MB per CPS |
| Carrier call setup | in: 1500 clean, 3000 burst; out: 1250 clean | | in at 3000 needs >7 GB |
| Concurrent UDP G.711 calls | about 450 under 80% of 2 cores | about 225 | 27 us CPU per forwarded packet; ~0.13 MB per call |
| Concurrent WebRTC SRTP calls | about 800 under 80% of 2 cores | about 400 | end-to-end loss 0.0018% at 816 |
| DTLS handshakes | about 400/s | about 200/s | |
| Registrations | 19000 held (cap 20000); 6000 REGISTER/s refresh | | live heap about 2.8 KB per binding |
| RAM | signaling at high CPS: about 430 CPS per GB; media calls: about 7000 per GB (derived from RSS) | | the high-CPS figure is dominated by lingering transactions |

Practical reading, with the caveats above: a pair of cores handles on the order of 1000 calls per second of setup or a few hundred concurrent media calls; the media path is syscall-bound, so more cores help roughly linearly only if the network path scales, which was not measured here (two cores only). Provision RAM for CPS, not for concurrent calls. The rtp range (5000 calls per plane with the default `20000-29999`) is well above the 450 to 800 calls two cores sustained here. Use `perf-wide.yaml` or a wider `rtp` for larger tests.

## Limits a load test hits first

Verified against the code at this commit; the harness configs raise or work around each.

| Limit | Where | Observed here |
|---|---|---|
| `shield.rate_limit` default `20/s per_ip`, counts every public datagram | `internal/config/schema.go:250` | one source gets about 6 CPS before silent drops; `perf-defaults.yaml` shows it (passes 8/s, fails at 14/s) |
| `shield.carrier_rate_limit` default `200/s per_ip` | `schema.go:253` | same for carrier sources |
| Admission: a public INVITE needs a live registration at its exact transport address, or a carrier source | `admission.go` | generator pre-registers from the same IP:port |
| 64 unanswered calls per public IP (`maxEarlyPerSource`); carriers exempt | `internal/edge/invite.go:35` | 287 `early_cap` rejects at 1700 CPS from one client IP |
| RTP range `20000-29999` = 5000 pairs per plane, about 5000 calls; exhaustion is 503 | config | `perf-wide.yaml` widens it to 25000 |
| Registration caps: 20000 bindings, 10 per AoR | `internal/edge/location.go:85-86` | 19000 held |
| UDP receive buffer is the OS default; no `SetReadBuffer` | `internal/edge` (no call) | kernel drops before calls fail |
| 5 min silence watchdog | `rtpSilenceTimeout` | pcap covers the hold |

## How to rerun

```sh
FREESBC_CONFIG=perf-wide.yaml test/perf/run.sh up      # build + start; SBC_CPUS=0-1 LOADGEN_CPUS=2-4 SWITCH_CPUS=5-7 SBC_MEM=8g
test/perf/run.sh -n -u 5000 -s 500:2000:100:40 -H 2 call           # a. client CPS
test/perf/run.sh -n -s 1000:3500:500:60 -H 2 carrier-in            # c. carrier-in CPS (60 s steps; watch memory)
test/perf/run.sh -n -s 500:2500:250:40 -H 2 carrier-out            # c. carrier-out CPS
test/perf/run.sh -c 450 -H 30 -t 90 -u 450 call                    # b. concurrent calls; read the plateau block
test/perf/run.sh -i 5 -u 500 -r 200 -t 10 register                 # goroutine lingering after REGISTERs
test/perf/run.sh -u 19000 -r 6000 -t 9 register                    # d. registrations
test/perf/run.sh -n -r 400 -t 20 -H 5 webrtc                       # e. DTLS handshakes/s
test/perf/run.sh -c 800 -t 60 -H 30 webrtc                         # e. concurrent SRTP calls
test/perf/run.sh down
go test -run '^$' -bench . -benchtime 1s -benchmem ./internal/...  # micro-benchmarks
```

Restart FreeSBC between runs (`docker restart freesbc-perf-freesbc-1`) so RSS and registrations start clean. Profiles: see "Profiling under load" in [test/perf/README.md](../test/perf/README.md). Set `SBC_CPUS`, `LOADGEN_CPUS`, `SWITCH_CPUS` for a VM with a different CPU count, and check `colima list` first.

## Pending

Issue #109 stays open. These are required before it can close, and none has been done:

1. **Three-host run.** Load generator, FreeSBC (separate `public.bind` and `private.ip`) and a SIPp switch on three machines with a real NIC. Everything above must be repeated there; the single-host numbers will not carry over (especially the syscall cost). On each machine, with this repo checked out and SIPp installed (see "Three real hosts" in the harness README):

   ```sh
   export TOPOLOGY=hosts
   export SBC_PUBLIC=<fsbc public ip> SBC_PRIVATE=<fsbc private ip>
   export LOADGEN_IP=<generator ip> CARRIERGEN_IP=<second generator ip, in edge.carrier_sources>
   export SWITCH_IP=<switch ip> CARRIER_IP=<carrier uas ip>
   export SBC_EXEC="ssh sbc" SWITCH_EXEC="ssh switch" CARRIER_EXEC="ssh carrier"
   export REMOTE_PERF=/opt/freesbc/test/perf      # test/perf on every host that runs SIPp
   test/perf/run.sh -n -u 5000 -s 500:4000:250:40 -H 2 call
   test/perf/run.sh -c 1000 -H 30 -t 90 -u 1000 call
   ```

   Use the same config as `perf.yaml` with the `ADDRESS` lines changed, raise `ulimit -n`, and take profiles with `admin.pprof`.
2. **A run against FreeSWITCH** as the switch (`edge.switch` pointed at it, same generator scenarios, the `echo` application), because a real switch is slower than the SIPp UAS and its answer latency interacts with the 64 early-dialog cap.
3. **An 8 to 24 hour soak at about 70% of the measured maximum**, showing no growth in goroutines, RSS, fds and ports in use. For example, at 70% of 450 calls:

   ```sh
   test/perf/run.sh -i 30 -c 315 -H 60 -t 28800 -u 315 call     # 8 hours; use -t 86400 for 24 hours
   ```

   Holds above 900 s are not supported with media (the pcap is capped; the 5 minute silence watchdog ends the call). Read `metrics.csv` for flat `goroutines`, `rss_bytes`, `open_fds` and `ports_in_use`, and for `ports_in_use` back to 0 at the end.

Also not measured here: end-to-end loss and jitter for UDP calls (SIPp does not analyse received RTP), the latency FreeSBC itself adds (needs a run directly against the switch), TCP/TLS/WSS signaling load, SDES-SRTP, and switch-to-client calls.
