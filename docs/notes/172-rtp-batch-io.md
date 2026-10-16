# Issue #172: batched RTP I/O (prototype notes)

Status: **prototype, off by default.** On loopback, batching does not make the relay cheaper at call-like load, and it costs about 10% more CPU per packet when each read returns one packet, which is the normal case. Whether it is worth keeping depends on the three-host run below. If that run does not show a clear gain, close #172 with these numbers and remove the batched loop.

## The question

The media profile in [performance.md](../performance.md#g-profiles-and-the-first-bottleneck) (509 concurrent G.711 calls, two cores, Docker veth + bridge) had 93.7% of samples in `syscall.Syscall6`: 88.5% under `sendto` and 5.5% under `recvfrom`, with one of each per packet. The proposal was to try `recvmmsg`/`sendmmsg` on Linux (2) and fewer reader goroutines per socket pair (3).

## How the relay forwards

* A `Session` has two port pairs, one per side, and runs four goroutines: RTP A to B, RTP B to A, and the same for RTCP. Each goroutine blocks reading one socket (its `from` side) and writes on the other side's socket, so the far end sees the port it already sends to.
* **Each socket carries one stream: about 50 pps for G.711 at 20 ms.** Nothing else is ever queued on it.
* In Go, a read on a UDP socket with nothing queued costs `recvfrom` (EAGAIN), a park in the netpoller, a wake from `epoll_wait`, and then the `recvfrom` that returns data. A relay with spare CPU therefore makes **two `recvfrom` calls, one `sendto` and one goroutine park/unpark per packet**. Measured on the batched loop at 500 calls: 1.00 datagrams per `recvmmsg` and 1.003 EAGAIN returns per packet.

### Where batching can amortise anything

* **Receive.** `recvmmsg` returns more than one datagram only if more than one is queued on that socket. With 20 ms between packets, that happens only when the reader goroutine was not scheduled for 20 ms or more (the relay is overloaded), or when the sender bunches packets (jitter, or an upstream that itself fell behind). The batching is self-regulating: batches grow only once the relay is saturated, which is also the only time the saving matters. But it saves nothing below that point.
* **Send.** `sendmmsg` sends on one socket. A relay goroutine's write socket receives only what that one direction forwards, so a send batch is never larger than the receive batch it came from. **Batching across sessions is impossible** because every session has its own sockets. That is the RTP port model: the SDP names a port per call, and latching is per socket. A shared socket per plane would mean demultiplexing calls by source address, which the latch cannot do safely.
* **What `*mmsg` saves.** It saves only the syscall entry and exit and Go's `entersyscall`/`exitsyscall`. It does not save the kernel's per-datagram work: the UDP stack, delivery over loopback or veth (charged to the sender), and waking the receiver. Measured below, an 8-packet `sendmmsg` saves about 0.6 µs per packet over `sendto` (3.4 µs down to 2.7 µs). A relayed packet costs 7 to 20 µs of CPU in total.

### Cheaper alternatives looked at

| Option | Finding |
|---|---|
| `WriteToUDPAddrPort` instead of `WriteToUDP` | Same cost (3.26 against 3.38 µs per send, within noise). Not worth changing the latch's `*net.UDPAddr`. |
| Connected socket (`connect` after latching, `send` without an address) | About 9% cheaper per send (3.03 µs) because there is no route lookup. But a connected UDP socket drops inbound datagrams from any other source, and the same socket must still accept a better-ranked source (loose latching) and a re-INVITE's new address (`Relatch`). It could only be done after a final `rankExact` latch, with a disconnect on `Relatch`. That changes latch semantics, so it was not prototyped. |
| No allocation per packet | `ReadFromUDP` allocates a `*net.UDPAddr` (16 B) per packet; the batched loop allocates nothing. The issue's profile put GC under 6% in total. A portable fix (`ReadFromUDPAddrPort` plus a reused `net.UDPAddr`, which is safe because the latch copies what it keeps) is possible on its own, separately from batching. |
| Fewer goroutines (proposal 3) | Go needs one blocked goroutine per socket to read through the netpoller, so RTP and RTCP cannot share a goroutine with blocking reads. The real version of this is one level-triggered `epoll` loop per core over raw fds (each read through `RawConn.Read` so a concurrent `Close` cannot recycle the fd). It would remove the speculative EAGAIN read and the park/unpark per packet. CPU per packet is 95 µs at 1 call and 9 to 11 µs at 500 calls on loopback, so wakeups dominate at low load. At the issue's 509 calls the scheduler was a small share, so the gain would be mostly at mid load. It is a redesign of the relay (its own poller, fd lifetime and sharding), so it was not prototyped. |

## What was prototyped

* `internal/media/relay.go`: `forward` now builds a `relayLoop`. The per-packet logic (latch, SDES decrypt and encrypt, silence watchdog refresh, counters) moved unchanged into `relayLoop.packet`, which both loops call. `relayPlain` is the old loop, byte for byte in behaviour, and is still the default.
* `internal/media/relay_batch_linux.go`: `relayBatched` reads with `recvmmsg` (up to `relayBatchSize` = 8 datagrams) and sends survivors with `sendmmsg`. It uses `golang.org/x/sys/unix` (already a direct dependency) through each socket's `syscall.RawConn`, so the netpoller still parks the goroutine and `Close` still ends it. Design choices:
  * Headers, iovecs and sockaddrs are preallocated per loop, and the source address reuses one `net.UDPAddr`, so there are **0 allocations per packet** (the latch copies what it keeps).
  * Only RTP loops batch. RTCP (one packet every few seconds) always uses `relayPlain`, which keeps memory at about 12 KiB per RTP loop.
  * A batch that leaves one packet to send uses `WriteToUDP`. `sendmmsg` is used only for two or more.
  * When `sendmmsg` stops at a failing datagram, that datagram is dropped and not counted, and the rest are sent: the same result as one `WriteToUDP` per packet. Order is kept. A destination with an IPv6 zone, or a family the socket cannot reach, goes alone through `WriteToUDP`, in order.
  * An IPv6 source scope is kept as a numeric zone where `ReadFromUDP` names the interface. Both resolve to the same scope when sending, and the latch compares only IP and port.
  * Oversize detection (read `maxPacketSize+1`, drop anything longer) and "a read error ends the loop" are unchanged.
* `internal/media/relay_batch_other.go`: `batchRelayAvailable = false`, so every loop is `relayPlain`. `GOOS=darwin` builds it.
* **Switch:** the unexported `batchRelay` (`atomic.Bool`) is read when a session starts. It is not configuration. Tests and benchmarks flip it, and a measurement build turns it on at link time:

  ```sh
  go build -ldflags "-X github.com/freesbc/freesbc/internal/media.batchRelayBuild=on" -o freesbc-batch ./cmd/freesbc
  ```

* `WebRTCSession` is untouched. Its browser leg goes through the demux and `net.Conn`, and batching it would be a separate change.

Tests (`relay_batch_linux_test.go`):
* `TestBatchRelayRunsRelaySuite` re-runs the relay, latching, SDES (including rekey under traffic and forgeries not refreshing the watchdog), close-cause and oversize tests through the batched loop.
* `TestBatchRelayQueuedBurstInOrder` queues 27 packets before `Start`, so reads return full batches, on an AF_INET and a dual-stack socket, and checks order and counters.
* `TestBatchFlushDropsOnlyTheFailingDatagram` covers the `sendmmsg` error path.

The whole media suite also passes with the link-time switch on: `go test -race -ldflags "-X github.com/freesbc/freesbc/internal/media.batchRelayBuild=on" ./internal/media/`.

## Loopback measurements

Machine: linux/amd64 VM, 4 vCPU Intel Xeon 2.1 GHz, kernel 6.18, Go 1.27.2. Benchmarks ran with `-cpu 2` (GOMAXPROCS 2 for the relay). **Loopback is not a NIC:** as on veth, `sendto` carries delivery into the receiving socket and the receiver's wakeup in the sender's context. The load generator runs on the same four vCPUs.

### `BenchmarkRelayLoad`: relay CPU per forwarded packet under call-like load

`FREESBC_BENCH_RELAY_LOAD=1 go test -run '^$' -bench RelayLoad -count 3 -cpu 2 ./internal/media/`

N sessions, each sending G.711 at 50 pps from both ends. The ends are played by a child process, so their syscalls are not charged to the relay. CPU comes from `getrusage` over a 5 s window after 2 s of warm-up. `burst=4` sends 4 packets back to back every 80 ms (same average rate), so packets queue on the socket. Values are the median of 3 runs, with the range in brackets.

| Calls, burst | Forwarded pps | plain: CPU ns/pkt | batch: CPU ns/pkt | batch vs plain | allocs/pkt plain / batch |
|---|---:|---:|---:|---:|---:|
| 1, 1 (one run) | 91 | 94985 | 100201 | +5% | 1 / 0 |
| 100, 1 | 9200 | 19610 [19470-20160] | 20693 [19193-21336] | +6% | 1 / 0 |
| 500, 1 | 45900 | 11101 [10180-11505] | 12518 [11870-13026] | **+13%** | 1 / 0 |
| 500, 1, batch run first | 46200 | 10941 [10584-11334] | 12048 [11611-12393] | **+10%** | 1 / 0 |
| 500, 4 | 49900 | 7563 [7557-8173] | 7649 [7345-7736] | +1% (noise) | 1 / 0 |

In pps per core (`pkt/cpu-s`) at 500 calls with burst 1, plain reached about 90000 and batch about 80000. Packets per `recvmmsg`: 1.00 at burst 1 and 3.66 at burst 4. EAGAIN returns per packet: 1.003 at burst 1 and 0.26 at burst 4.

Reading it:
* At one packet per read, batching is **worse** by about 10%. The likely cause is that `recvmmsg` costs more than `recvfrom` for a single datagram: it does a second, failing internal receive, and the speculative EAGAIN read is a `recvmmsg` as well. That is a hypothesis; it was not traced in the kernel.
* At 3.7 packets per read, the saved syscalls only bring it back to parity.
* Even the plain loop gets 30% cheaper per packet once packets queue (11.1 down to 7.6 µs), because it reads several before parking. The saving comes from fewer park/unpark cycles and wakeups, not from fewer syscall entries.

### CPU profile, plain, 500 calls, burst 1

`-cpuprofile`, relay process only: `Syscall6` 70% flat; `sendto` 52% cumulative, `recvfrom` 18%, scheduler (`findRunnable`) 17%, `epoll_wait` 7%, and `relayLoop.packet` (latch, counters, watchdog) 8%. The shape is the same as the issue's veth profile, where `sendto` leads because it carries the delivery.

### `BenchmarkUDPSendPath`: sender cost per packet to a draining loopback sink

`go test -run '^$' -bench UDPSendPath -count 3 -cpu 2 ./internal/media/`. Medians:

| Path | ns/packet |
|---|---:|
| `sendto` (`WriteToUDP`, current) | 3382 |
| `WriteToUDPAddrPort` | 3255 |
| connected socket `Write` | 3031 |
| `sendmmsg`, 1 per call | 3361 |
| `sendmmsg`, 4 per call | 2939 |
| `sendmmsg`, 8 per call | 2728 |

### `BenchmarkSessionForwardBurst`: one session, endpoints in process, per packet

`go test -run '^$' -bench SessionForwardBurst -count 3 -cpu 2 ./internal/media/`. Medians:

| Burst | plain ns/pkt | batch ns/pkt |
|---:|---:|---:|
| 1 | 6787 | 6604 |
| 4 | 6067 | 5507 (-9%) |
| 16 | 5340 | 4620 (-13%) |

This is the best case: the queue is guaranteed, and the endpoints' own syscalls are part of the figure. It does not reflect paced calls.

## Caveats

* **Loopback is not a NIC.** On a real NIC, `sendto` hands the datagram to the driver queue and returns. Delivery to another host and the receiver's wakeup are not charged to the sender, so the per-send kernel cost is lower and the syscall entry is a larger share of it. Batching could therefore gain more there than here. It can also gain less, because a real deployment's per-socket queues are as shallow as on loopback. Only the three-host run decides.
* The load benchmark shares four vCPUs between the relay (GOMAXPROCS 2) and the generator. Run-to-run spread is about ±7%.
* The generator spreads calls evenly over the 20 ms. SIPp's pcap player may bunch them, but that creates bursts across sockets, not queues on one socket, so it would not change batch sizes.
* `TestAuditMED006LooseLatchFirstPacketHijack` needs 127.0.0.2 and skips without it, as before.

## Three-host procedure to decide

Use the setup in [performance.md, Pending item 1](../performance.md#pending) and [test/perf/README.md, "Three real hosts"](../../test/perf/README.md): load generator, FreeSBC and a SIPp switch on three machines with real NICs, FreeSBC pinned to two cores, and `perf.yaml` with the `ADDRESS` lines changed. Raise `ulimit -n` and set `admin.pprof: true`.

1. Build both binaries from the same commit and copy them to the FreeSBC host:

   ```sh
   go build -o freesbc-plain ./cmd/freesbc
   go build -ldflags "-X github.com/freesbc/freesbc/internal/media.batchRelayBuild=on" -o freesbc-batch ./cmd/freesbc
   ```

2. On the generator host:

   ```sh
   export TOPOLOGY=hosts
   export SBC_PUBLIC=<fsbc public ip> SBC_PRIVATE=<fsbc private ip>
   export LOADGEN_IP=<generator ip> CARRIERGEN_IP=<second generator ip, in edge.carrier_sources>
   export SWITCH_IP=<switch ip> CARRIER_IP=<carrier uas ip>
   export SBC_EXEC="ssh sbc" SWITCH_EXEC="ssh switch" CARRIER_EXEC="ssh carrier"
   export REMOTE_PERF=/opt/freesbc/test/perf
   ```

3. For each binary, restart FreeSBC before each step and run the concurrent-calls ladder:

   ```sh
   for n in 300 450 600 800 1000; do test/perf/run.sh -c $n -H 30 -t 90 -u $n call; done
   ```

   During the 600-call step (or the highest step under 160% CPU), take a 30 s CPU profile from `/debug/pprof/profile?seconds=30` (see "Profiling under load" in the harness README). Note the `sendto`/`sendmmsg` and `recvfrom`/`recvmmsg` shares.

4. Compare these:
   * Plateau CPU at equal call counts.
   * The highest call count with CPU under 160% (80% of two cores), 0 failed calls and tx/rx at least 0.999.
   * `freesbc_udp_receive_buffer_errors_total`.
   * RSS (each batched RTP loop holds about 12 KiB of buffers).

5. Decide:
   * **Enable by default** (flip `batchRelay` on, then delete `relayPlain`'s RTP use or keep it as the non-Linux path) only if the batched build carries **at least 10% more calls per core** under the 160% line, and costs no more CPU at 300 and 450 calls.
   * **Otherwise close #172** with both ladders and profiles, remove `relay_batch_*.go` and the `batchRelay` switch, and keep the `relayLoop` refactor.
   * Either way, the 1-allocation-per-packet fix and the connected-socket idea in the alternatives table can be considered separately.
