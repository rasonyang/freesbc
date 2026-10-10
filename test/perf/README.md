# FreeSBC load-test harness

Rerunnable load tests for the capacity questions in issue #109: calls per
second, concurrent G.711 calls with media, registrations, carrier legs and
WebRTC (ICE-Lite + DTLS-SRTP). Everything lives in this directory:

| Path | What |
|---|---|
| `run.sh` | Runs one scenario, samples FreeSBC while it runs, prints a summary. Step mode ramps the rate to find the highest rate under 0.1% failures. |
| `docker-compose.yml`, `docker/` | Single-host rig: two bridge networks and five containers (FreeSBC, load generator, carrier-inbound generator, carrier, switch). |
| `configs/perf.yaml` | FreeSBC config for the runs; every load-relevant knob annotated. `perf-wide.yaml`: 25000-call RTP range. `perf-defaults.yaml`: shield at its defaults, to show the ceiling you hit if you forget to raise it. |
| `sipp/*.xml` | SIPp scenarios (below). |
| `pcap/` | `g711u_10s.pcap` (10 s of PCMU, 20 ms packets, 115 KB) and `gen_pcap.py` to make longer ones. |
| `webrtcload/` | Go WebRTC load client (`package main` in this module). |
| `sample.sh`, `scrape.awk`, `summarize_*.awk` | The sampler and the summary code `run.sh` uses. |
| `out/` | One directory per run (git-ignored). |

## Method

Three roles, as in the issue:

```
 load generator          FreeSBC                         "switch"
 (public side)   --->  public.bind | private.ip  --->   SIPp UAS (private side)
 172.28.1.20            172.28.1.10 | 172.28.2.10        172.28.2.20
```

* The generator drives the public side (UDP, or WS/WSS for WebRTC).
* The switch is a SIPp UAS that answers REGISTER and INVITE immediately and
  echoes RTP (`-rtp_echo`), so the switch is never the bottleneck. For the
  one "realistic" run against FreeSWITCH, point `edge.switch` at a real
  FreeSWITCH instead and use the same generator scenarios (the UAS is only
  needed for the raw-capacity runs).
* Carrier outbound adds a SIPp UAS playing the carrier on the public side; the
  "switch" role then also generates the call (a UAC on the private side).
* While a scenario runs, `run.sh` scrapes FreeSBC's admin `/metrics` every
  `-i` seconds into `metrics.csv` and also reads CPU, RSS and fds from
  `/proc/<pid>` (the `perf_proc_*` lines of `sample.sh`), so CPU/RSS/fds are
  recorded even on a build without the `process_*` collector. `process_*`
  wins when present. Metrics that a build lacks leave an empty column.
* SIPp writes its own stats CSV (`-trace_stat`, 1 s rows); the summary reads
  the final row (calls, failures, retransmissions, response-time buckets) and
  the 1 s `CallRate(P)` samples (median/peak CPS while creating calls).

What is *not* measured by SIPp: received RTP loss and jitter. SIPp plays the
pcap and the UAS echoes it, but SIPp does not analyse what returns. Use:

* the `webrtc` scenario, which measures echoed-packet ratio, sequence-gap loss,
  RFC 3550 jitter and RTT per call;
* FreeSBC's own `freesbc_rtp_packets_rx_total` vs `..._tx_total` (summary
  line `tx_over_rx`; below 1.0 means FreeSBC dropped packets). On builds where
  these count finished sessions only, they move when calls end; the summary
  window includes the teardown, so they still add up for runs that finish.

## Prerequisites

* Docker with Compose v2 (Linux, or Colima / Docker Desktop; give the VM
  several CPUs). Images build from this repo: the `freesbc` binary
  (`golang:1.27.2`), SIPp 3.6.1 from Debian's `sip-tester` package (built with
  PCAP play and RTP echo) and `webrtcload`.
* On the host that runs `run.sh`: `bash`, `awk`, `sed`, and `python3` only when
  a scenario holds calls longer than 8 s (it generates a longer pcap).
* The rig shares the Docker VM's CPUs between generator, FreeSBC and switch.
  Use it to validate the method and look for bugs; publish numbers from three
  separate hosts.

## Quick start (compose rig)

```sh
test/perf/run.sh up                       # build and start (FREESBC_CONFIG=perf-wide.yaml test/perf/run.sh up for the wide RTP range)
test/perf/run.sh -r 10 -t 30 -H 10 call  # 10 calls/s for 30 s, 10 s each (about 100 concurrent)
test/perf/run.sh down
```

`run.sh up` builds FreeSBC from the working tree (`FREESBC_VERSION` defaults to
`git describe`, shown in the run header as the build). Run it again after code
changes or to switch `FREESBC_CONFIG`.

## Scenarios

Commands assume the repo root as the working directory.

| Scenario | Command | What happens |
|---|---|---|
| `register` | `test/perf/run.sh -r 200 -t 60 -u 5000 register` | `-u` users REGISTER from one source socket; more calls than users means more rounds, each round refreshing every binding (same Call-ID, so the same binding). Reports REGISTER/s achieved and bindings held. |
| `call` | `test/perf/run.sh -r 20 -t 60 -H 30 call` | Client UAC calls: the `-u` users are pre-registered (`register.xml`, 200/s) from the same IP:port the calls use, then INVITE, ACK, G.711 20 ms pcap, hold, BYE. Switch UAS echoes RTP: media on both legs. |
| `carrier-in` | `test/perf/run.sh -r 20 -t 60 -H 30 carrier-in` | The carrier generator (`172.28.1.25`, in `edge.carrier_sources`) INVITEs with no REGISTER. |
| `carrier-out` | `test/perf/run.sh -r 20 -t 60 -H 30 carrier-out` | The "switch" UAC (private side, `-i 172.28.2.20 -p 5070`) INVITEs `sip:N@172.28.1.30:5060`, the carrier entry in `edge.carriers`; a SIPp carrier UAS answers and echoes RTP. |
| `webrtc` | `test/perf/run.sh -r 5 -t 30 -H 20 webrtc` | `webrtcload` over `ws://172.28.1.10:8080` (`-w wss://172.28.1.10:443` for TLS): registers users, calls with ICE + DTLS-SRTP, G.711 SRTP both ways. |

Concurrency is rate x hold. `-c N` is a shortcut: with `-H 30 -c 600` the rate
becomes 20/s and SIPp's `-l` caps concurrency near 600. Set the number of
seconds with `-t` long enough that the plateau lasts well beyond the ramp (at
least 2 x hold).

**Step mode** finds the highest sustained rate:

```sh
test/perf/run.sh -n -s 50:1000:50:20 -H 2 call     # signaling only (-n: no RTP), 2 s calls
test/perf/run.sh    -s 20:400:20:30 -H 30 carrier-in   # with media
```

`-s FROM:TO:INC[:SECS]` runs each rate for SECS seconds (20 by default), stops at
the first step whose failed-call percentage exceeds `STEP_FAIL_PCT` (0.1) and
prints a table plus `max sustained rate under 0.1% failures`. `steps.csv` has the
table. Each step is its own SIPp process (own stats file); the metrics CSV spans
the whole ramp.

**Soak** (issue: 8-24 h at about 70% of the maximum): pick 70% of the step-mode
result, a hold long enough to see steady state and a long `-t`, and a slow
sampler:

```sh
FREESBC_CONFIG=perf-wide.yaml test/perf/run.sh up
test/perf/run.sh -i 30 -r 70 -t 28800 -H 60 call      # 8 hours, about 4200 concurrent calls
```

Watch `goroutines`, `rss_bytes`, `open_fds` and `ports_in_use` for growth in
`metrics.csv`, and see that `ports_in_use` returns to 0 at the end. Holds over
900 s are not supported with media: the pcap is capped at 900 s and FreeSBC's
5-minute silence watchdog then ends the call.

### Reading the outputs

Each run creates `out/<timestamp>-<scenario>/`:

| File | Content |
|---|---|
| `summary.txt` | The printed summary. |
| `metrics.csv` | `ts,cpu_s,rss_bytes,open_fds,goroutines,heap_inuse_bytes,ports_in_use,active_calls,active_regs,webrtc_sessions,edge_sessions,rtp_pkts_rx,rtp_pkts_tx,rtp_bytes_rx,rtp_bytes_tx,port_alloc_fail,invite_rejects,admission_drops,shield_drops`; counters are cumulative. CPU% is the delta of `cpu_s` over the delta of `ts` (100 = one core). |
| `sipp-*.csv`, `sipp-*.log` | SIPp's raw stats (`prereg`, `main`, `main.rdN` for register rounds, `rNNN` for step mode) and screen output. |
| `webrtc.csv`, `webrtc.log` | Per-call rows and the report of `webrtcload`. |
| `users.csv`, `g711u.pcap` | Inputs generated for the run. |

Summary lines worth knowing:

* `calls_failed` / `failed_pct`: SIPp counts any unexpected message, timeout or
  retransmission exhaustion. The pass criterion is under 0.1%.
* `cps_median` / `cps_max`: call creation rate as SIPp measured it in 1 s
  samples. `cps_over_elapsed` includes the hold and the drain, so it is lower;
  do not quote it as CPS.
* `rt_p95_bucket_ms=<20`: the INVITE-to-200 response time as SIPp sees it
  (generator to FreeSBC to switch UAS and back) falls under 20 ms for 95% of
  calls; the buckets are 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000 ms, so this
  is an upper bound. To get the latency FreeSBC adds, run the same scenario
  against the switch directly (`-T 172.28.2.20:5060` from a host that can reach
  it) and subtract.
* `cpu_avg_pct` / `cpu_peak_pct`: of the FreeSBC process, one core = 100.
* `tx_over_rx`: FreeSBC's forwarded/received RTP packet ratio.

## Limits a load test hits first

All are configured around in `configs/perf.yaml` (look for `LIMIT`). Documented
here so you can recognise the symptom:

| Limit | Default | Symptom | Rig setting |
|---|---|---|---|
| `shield.rate_limit` | `20/s per_ip`, counts every public datagram (ACK, BYE, retransmissions) | About 6 CPS from one source, the rest silently dropped; SIPp shows retransmission timeouts | `1000000/s per_ip`. `configs/perf-defaults.yaml` leaves it at default: against it step mode passes 8/s and fails at 14/s. |
| `shield.carrier_rate_limit` | `200/s per_ip` | Same, for carrier sources | `1000000/s per_ip` |
| Admission | a public INVITE needs a live registration at its exact transport IP:port, or a carrier source | INVITEs vanish with no response (`freesbc_edge_admission_drops_total{reason="invite_not_admitted"}`) | `call` pre-registers from the same IP:port; the carrier generator is in `edge.carrier_sources` |
| Unanswered calls per source | 64 per public IP (carrier sources exempt) | 503 under slow answers | irrelevant with an instant UAS; with a real switch, use more source IPs or the carrier path |
| `rtp` range | 20000-29999 = 5000 calls | 503 when ports run out (`freesbc_media_port_allocation_failure_total`) | `perf-wide.yaml`: 10000-59999 = 25000 calls |
| `shield.max_sessions` | the pair count of `rtp` | 503 + `Retry-After` (`invite_rejects_total{reason="session_cap"}`) | explicit 25000 in `perf-wide.yaml`; may not exceed the range |
| `shield.invite_rate_limit` | off | 503 (`reason="invite_rate"`) | off |
| Registration caps | 20000 bindings, 10 per AoR | REGISTER refused | `register`/`call` use distinct users up to `-u`; a binding is keyed on AoR + Call-ID, so refreshes reuse the Call-ID |
| Stream connections | 256 per source IP, 10000 total | WS/WSS connects refused | `webrtcload -conns` (default 20) multiplexes many users over few connections; beyond 256 concurrent connections add source IPs |
| File descriptors | OS limit | `too many open files` | compose sets `nofile` 1048576; on a real host raise `LimitNOFILE` (4 UDP sockets per call plus connections) |
| Silence watchdog | 5 min of no RTP ends a confirmed call | long holds without RTP die | pcap covers the hold |

## WebRTC load client

`webrtcload` plays the browser. For each user it opens a WS/WSS connection
(shared across users), REGISTERs, then places calls whose offer carries ICE
candidates from a full pion ICE agent (controlling), a DTLS fingerprint
(`setup:actpass`), rtcp-mux and PCMU. After FreeSBC's 200 it completes ICE and
DTLS (it takes the role the answer's `a=setup` leaves it), keys SRTP, sends G.711
20 ms packets for `-hold`, measures the echoed stream and sends BYE. It
reuses the patterns of `internal/edge/webrtc_inbound_test.go`. Run it directly
for flags:

```sh
docker compose -f test/perf/docker-compose.yml exec loadgen webrtcload -h
webrtcload -target wss://sbc.example.net:443 -users 500 -conns 50 -rate 20 -duration 60s -hold 30s -password secret
```

| Flag | Default | Meaning |
|---|---|---|
| `-target` | `ws://172.28.1.10:8080` | `ws://` (edge.listen.ws) or `wss://` (edge.listen.wss, certificate not verified) |
| `-users`, `-user-prefix`, `-user-start` | 100, `w`, 1 | users `w000001...`; also the cap on concurrent calls |
| `-password` | none | answers a digest challenge (MD5) for every user; the rig's SIPp switch does not challenge |
| `-domain`, `-number` | `perf.test`, `2000` | SIP domain, dialed user |
| `-rate`, `-duration` / `-calls` | 5, 30s | calls started per second, for how long (or a total) |
| `-hold` | 10s | media time per call |
| `-conns` | 20 | WebSocket connections (FreeSBC allows 256 per source IP) |
| `-reg-rate` | 200 | REGISTERs per second in the registration phase |
| `-advertise` | none | IP for the offer's `c=` line (NAT) |
| `-no-media` | off | ICE + DTLS only |
| `-out` | none | per-call CSV |

It reports: REGISTER latency, INVITE-to-200 setup latency, ICE connect time, DTLS
handshake time and handshakes per second (mean, and the busiest second),
packets sent/echoed, sequence-gap loss, jitter (RFC 3550, 8 kHz clock) and
RTT through FreeSBC and the echoing switch. Note: ICE connect is dominated by
pion's connectivity-check pacing (about 200 ms); a browser behaves
similarly. A call counts as failed on any non-200 INVITE, ICE or DTLS failure,
or when no RTP returns. Calls skipped because every user was busy are reported
separately (`skipped`); raise `-users`.

The client needs the switch behind FreeSBC to answer and echo RTP: the SIPp
`switch_uas.xml` does. Against a real switch, echo is whatever it provides
(FreeSWITCH `echo` application).

## Three real hosts

1. **FreeSBC host**: copy `configs/perf.yaml`, replace the `ADDRESS` lines
   (`public.ip`, `private.ip`, `edge.switch`, `edge.carriers`,
   `edge.carrier_sources`) with the real addresses, run `freesbc check -c`
   and `freesbc run -c` (raise `ulimit -n` first). Behind 1:1 NAT set
   `public.bind`. Keep `admin.listen` on loopback.
2. **Switch host** (private side): SIPp with `-rtp_echo` support (the
   `sip-tester` package, or build SIPp with `--with-pcap`). The IP must be the
   one in `edge.switch`.
3. **Load generator host** (public side): this repo checked out (for `run.sh`,
   scenarios and pcap), SIPp, `webrtcload` on `PATH` (`go build -o
   /usr/local/bin/webrtcload ./test/perf/webrtcload`), plus a carrier UAS host
   if you run `carrier-out`.

Then run `run.sh` from the generator host with the roles pointed at the real
machines. `*_EXEC` is a command prefix that runs a command *on that role*
(empty means locally):

```sh
export TOPOLOGY=hosts
export SBC_PUBLIC=203.0.113.7 SBC_PRIVATE=10.77.0.2     # FreeSBC
export LOADGEN_IP=203.0.113.50 CARRIERGEN_IP=203.0.113.51  # two public IPs on the generator; the second is in carrier_sources
export SWITCH_IP=10.77.0.10 CARRIER_IP=203.0.113.60
export SBC_EXEC="ssh sbc"  SWITCH_EXEC="ssh switch"  CARRIER_EXEC="ssh carrier"
export REMOTE_PERF=/opt/freesbc/test/perf   # this directory on every host that runs SIPp
test/perf/run.sh -r 50 -t 60 -H 30 call
```

* `REMOTE_PERF` must hold `sipp/` and `pcap/` on the switch and carrier hosts
  (`rsync -a test/perf/ host:$REMOTE_PERF/`). The load generator runs
  locally, so its `out/` is the local directory.
* Metrics: `sample.sh` runs on the FreeSBC host through `SBC_EXEC` and needs
  `curl`; it uses `ADMIN_URL`, `ADMIN_USER`, `ADMIN_PASS` (defaults
  `http://127.0.0.1:8081`, `admin`, `perf`, the values in `perf.yaml`).
  Environment is not forwarded by `ssh`, so for other values either edit the
  defaults or set `SAMPLE_CMD` to any command that prints `/metrics`, for
  example through a tunnel: `ssh -L 18081:127.0.0.1:8081 sbc` and
  `SAMPLE_CMD="curl -sf -u admin:pw http://127.0.0.1:18081/metrics"`
  (resource columns then come from `process_*` only).
* Ports: FreeSBC `5060/udp` on `public.bind` and `private.ip`, the switch UAS on
  `SWITCH_IP:5060`, the carrier UAS on `CARRIER_IP:5060`, RTP `6000` on the
  switch and the carrier, and `rtp` range on FreeSBC. Source ports used by the
  generator: `5070` (`GEN_PORT`).
* The hosts-mode path has not been exercised in this repo's own testing: the
  compose rig is the verified path.

## Environment variables

| Variable | Default (compose) | Meaning |
|---|---|---|
| `TOPOLOGY` | `compose` | `compose` or `hosts` |
| `SBC_PUBLIC`, `SBC_PRIVATE` | `172.28.1.10`, `172.28.2.10` | FreeSBC addresses |
| `LOADGEN_IP`, `CARRIERGEN_IP` | `172.28.1.20`, `172.28.1.25` | generator source IPs: client and carrier |
| `CARRIER_IP`, `CARRIER_PORT` | `172.28.1.30`, `5060` | the carrier UAS (`edge.carriers`) |
| `SWITCH_IP` | `172.28.2.20` | the switch (`edge.switch`) |
| `SIP_PORT`, `GEN_PORT` | `5060`, `5070` | SIP port on FreeSBC and the switch; generator source port |
| `SERVICE` | `2000` | dialed user |
| `REG_RATE` | `200` | REGISTER/s while pre-registering for `call` |
| `STEP_FAIL_PCT` | `0.1` | step-mode failure threshold (percent) |
| `OUT_ROOT` | `test/perf/out` | where runs go (compose mounts only `test/perf`) |
| `*_EXEC`, `REMOTE_PERF`, `SAMPLE_CMD` | compose exec prefixes, `/perf` | see above |
| `FREESBC_CONFIG`, `FREESBC_VERSION` | `perf.yaml`, `git describe` | for `run.sh up` |

## Known limitations

* No digest authentication in the SIPp scenarios (the SIPp switch does not
  challenge); `webrtcload -password` can answer one. To load-test a real
  registrar's challenge round-trip, point the scenarios at it with `-T` or add
  `[authentication]` to `register.xml`.
* Only the client-to-switch, carrier-to-switch and switch-to-carrier call
  directions are generated. A switch-to-client call needs the `fsbc=` token FreeSBC puts
  in the client's registered Contact; there is no scenario for it.
* The echo UAS receives all media on one port (6000) and SIPp's RTP echo is single
  threaded; at several thousand concurrent calls it, or the Docker VM, may saturate
  before FreeSBC. Check generator and UAS CPU (`docker stats`) before blaming FreeSBC.
* Response-time percentiles are SIPp bucket upper bounds, not exact values.
* Registrations made by `call`/`register` are granted 86400 s by the SIPp
  switch, so they outlive a run; `run.sh up` (or restarting FreeSBC) clears them.
