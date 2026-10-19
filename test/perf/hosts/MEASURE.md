# MEASURE.md: the measurements of the formal run (issue #109)

Reference for the agent on the loadgen host (A), which drives every measurement. Written for the
formal three-host run on the instances in the table below; STEPS.md covers setup (R00 to R09) and
the end of day (R18). Commands are meant to be run as written; deviate when something does not work
and log what and why in `/opt/freesbc/results/loadgen/notes.md`.

## 0. Rig, criteria, conventions

| Host | Role | Type | vCPU / RAM | Network |
|---|---|---|---|---|
| A loadgen | SIPp UAC, webrtcload, run.sh, the driver | compute-optimized, dedicated vCPU (`ecs.c9i.2xlarge`, Intel Xeon 6982P-C; or `ecs.c8a.2xlarge`, AMD EPYC 9T24, which the 2026-10-18 formal run used), system disk 40 GiB | 8 / 16 GiB | public vSwitch, primary + 2 (or 3) secondary IPs |
| B sbc | FreeSBC, the system under test | Intel 1:2 compute type (`ecs.c9i.xlarge`, Intel Xeon 6982P-C), at least 2 ENIs; no MemoryMax (the host itself has 8 GiB) | 4 / 8 GiB, system disk 40 GiB | eth0 public vSwitch, eth1 private vSwitch |
| C switch | SIPp UAS, FreeSWITCH (docker), Asterisk | compute-optimized, dedicated vCPU (`ecs.c9i.2xlarge`, Intel Xeon 6982P-C), system disk 40 GiB | 8 / 16 GiB | private vSwitch (public IP for ssh and downloads only) |

All spot, all in zone cn-wulanchabu-b, one security group. Addresses are in `plan.env`.

**B against the competitor's box.** The competitor's published test ran on a Xeon X5670 (6 cores, 12
threads, 2.93 GHz), 8 GB RAM, 128 GB SSD, Debian 10, kernel 4.19. Disk size is not a variable here
(FreeSBC barely touches disk). B has fewer cores than the X5670 (2 cores / 4 threads against 6 cores /
12 threads, Xeon 6982P-C against a 2010-era Westmere), but each core is much faster, so total compute is
roughly comparable to somewhat lower. Record `lscpu` (model, frequency) and `uname -r` of B in the report and state that this rig
runs Ubuntu 24.04 with a 6.x kernel (Debian 10 is EOL, the kit is tested on Ubuntu). GOMEMLIMIT is 6GiB
(`B_GOMEMLIMIT`), no MemoryMax.

**Expectation, stated before measuring.** Earlier single-host numbers (before sipgo v1.6.0) put about 450
media calls at 80% of 2 cores, so 1000 concurrent media calls (M03) may push 4 vCPU near its limit.
Report honestly whether the 1000-call plateau held, with CPU%, loss and failed calls; do not tune to rescue it.
M02 finds the actual maximum on this box.

**Pass criteria** (from #109), applied to every load figure you quote as a maximum:

- failed calls under 0.1% (SIPp `failed_pct`; a run whose SIPp aborted with calls in flight is a
  FAIL even though run.sh shows 0%: `runcheck.sh` catches it);
- FreeSBC CPU under 80% of its cores (plateau `cpu_avg_pct` below 320 on 4 vCPU, 160 on a 2-core limit; 100 = one core; `ladder.sh` computes it from `nproc`);
- added RTP loss under 0.1% (plateau `tx_over_rx` at least 0.999, `udp_rcvbuf_errors` 0, probe loss);
- no `invite_rejects`, `admission_drops`, `shield_drops`, `port_alloc_failures` in a non-step run;
- a figure is only FreeSBC's if the generator (A, 8 vCPU) and the switch (C, 8 vCPU) were not the limit:
  see "The generator is not the bottleneck" below. A run that fails that check is INVALID.

**Conventions.**

- Work from `/opt/freesbc` on A. Every shell that runs `run.sh` needs `. test/perf/hosts/env.sh sipp`
  (or `fs`) and B must run the matching config (`ssh sbc freesbc-use sipp|fs`; it restarts FreeSBC,
  which clears RSS, bans and bindings). `ssh sbc sbc-cores all` removes any CPU limit.
- Before each measurement: restart FreeSBC as above, flush FreeSWITCH registrations if `fs`
  (`ssh switch 'sudo fs_cli -x "sofia profile perf flush_inbound_reg"'`), start nothing else on A.
- Judge every run: `test/perf/hosts/runcheck.sh test/perf/out/<run>` (PASS / WARN / FAIL per SIPp block
  and metric; exit 1 on FAIL). Quote only runs without FAIL.
  Then `test/perf/hosts/rigcheck.sh test/perf/out/<run>`: INVALID (generator or switch saturated) means the run is not FreeSBC's figure.
- Record each measurement: append a block to `/opt/freesbc/results/$(date +%F)/measure-results.md`
  (title `M0x`, command, run directory names, the numbers asked below; daily-report.sh includes the
  first 60 lines in the issue comment), then `test/perf/hosts/progress.sh set M0x done "<key number>"`
  (or `failed "<why>"`).
- The sampler resource columns come from `run.sh` (`metrics.csv`, `steps.csv`). Whole-host CPU,
  load, memory and the generator/switch CPU come from `hostmon.sh`. Start it once at the beginning
  of the measurement phase, on all three hosts, and copy the csv files into
  `results/<date>/` at the end of the day:
  ```sh
  H=/opt/freesbc/test/perf/hosts
  ssh sbc    "nohup $H/hostmon.sh /var/tmp/day-sbc.csv 10 freesbc >/dev/null 2>&1 </dev/null &"
  ssh switch "nohup $H/hostmon.sh /var/tmp/day-switch.csv 10 sipp,freeswitch >/dev/null 2>&1 </dev/null &"
  nohup $H/hostmon.sh /var/tmp/day-loadgen.csv 10 sipp,webrtcload >/dev/null 2>&1 </dev/null &
  ```

## The generator is not the bottleneck (check after every measurement)

A and C have 8 vCPU each, and SIPp is mostly single-threaded per instance: one SIPp process (the UAC on
A, the echo UAS on C) saturates one core at a few thousand CPS or a few thousand media calls. So a CPS
knee above about 1 to 2k CPS may be a SIPp limit and not FreeSBC's. Therefore every measurement samples
the CPU of A and C while it runs, per process (`sipp`, `webrtcload`, `freeswitch`) and in total, next to
the run's metrics:

- `hostmon.sh` does it (started once for the day, see Conventions; `m03.sh` and `m08.sh` start their own and
  copy the csv into the run directory as `hostmon-loadgen.csv` / `hostmon-switch.csv`). Columns
  `sipp_cpu_pct`, `sipp_maxproc_cpu_pct` (busiest single SIPp process, 100 = one core), `webrtcload_*`,
  `freeswitch_*` and the total `cpu_pct` (100 = all 8 vCPUs). `pidstat -p ALL 5` or `top -b -d 5` is an
  acceptable substitute, saved in the run directory.
- After each run: `test/perf/hosts/rigcheck.sh test/perf/out/<run>` (needs the hostmon csv; `ladder.sh` calls it for you and
  stops with `FAIL-rig`). **The result is INVALID if any single `sipp` or `webrtcload` process sat at about 100%
  of a core (rigcheck uses 90%), or total CPU of A or C exceeded 80%, while FreeSBC (B) was still below its own
  limit.** An INVALID run is not FreeSBC's figure; do not record it as a maximum or a knee.
- What to do then: lower the step (the figure becomes "at least X, rig-limited"), or spread the load. `run.sh`
  starts one generator process per run, so spreading is manual: with `SWITCH=freeswitch` two `run.sh` instances can run in
  parallel from two source IPs (`A_LOADGEN2_IP`, M06); with the SIPp switch run extra SIPp instances by hand
  from the scenario files in `test/perf/sipp/` on other source IPs and ports and add their rates (as in STEPS.md R10; untested).
  Say in the report which figures are rig-limited and what you did.

## How to run long jobs

A single tool call must never block for more than about a minute or two. Anything longer than that
(most runs here take 5 to 35 minutes, the soak 8 hours) runs detached, writes a log file, and you poll.

```sh
cd /opt/freesbc && . test/perf/hosts/env.sh sipp && mkdir -p results/logs
nohup test/perf/run.sh -n -s 500:6000:500:40 -H 2 -u 12000 call > results/logs/m01-call.log 2>&1 &
echo started; sleep 1; pgrep -af 'test/perf/run.sh' | head -3
```

Poll with short calls: `tail -n 5 results/logs/m01-call.log`, `ls -dt test/perf/out/* | head -1`,
`pgrep -f test/perf/run.sh || echo finished`. When it has finished: read the end of `summary.txt`,
run `runcheck.sh`, record. `nohup` keeps the environment exported by `env.sh`; a `tmux new -d -s NAME
'bash -c ". test/perf/hosts/env.sh sipp; ...; exec bash"'` session works as well (and survives your own
session). Do not start two `run.sh` at once with `SWITCH=sipp`: each starts and stops the SIPp UAS on C.
If an instance is reclaimed (spot), note the time in notes.md, mark the step `failed "spot reclaimed"`
and redo it after the host is back (STEPS.md, section on reclaimed instances); a soak that lost its
host restarts from zero (its length must be unbroken).

`ladder.sh NAME "RUN_ARGS" v1 v2 ...` (below) wraps "step a load up until a limit is hit" and is the
way to run M02, M05 and M06; it is itself started with nohup.

## Timeline of one day (about 14 hours)

| Time | What |
|---|---|
| 08:30 | Laptop: create instances, fill `plan.env`, copy pem, rsync (RUNBOOK.md). Paste the three prompts. |
| 08:30 to 10:00 | Setup: R00 to R06 provision and self-checks, R08 and R09 smoke (about 1.5 h). Start `hostmon` on all three. |
| 10:00 to 12:00 | M03 on the whole host (about 35 min), then limited to 2 cores and to 1 core (35 min each; no 8-core run). Poll; meanwhile nothing else may use B. |
| 12:00 to 13:00 | M01 CPS steps without media (call, carrier-in, carrier-out), pprof taken at the knee (M07). |
| 13:00 to 14:15 | M02 concurrent G.711 calls up to the limit, pprof at the peak (M07), latency baseline. Decide the soak size. |
| 14:15 to 14:45 | M04 registrations, then the #170 RSS per CPS run. |
| 14:45 to 15:30 | M05 WebRTC. |
| 15:30 to 16:30 | M06 FreeSWITCH as the switch. Optional if time allows: M03 again on FreeSWITCH (35 min). |
| 16:30 to 17:00 | Day report: `daily-report.sh`, post to #109. Collect hostmon csvs. |
| 18:00 | M08 soak starts (70% of the M02 maximum, 8 h) and runs on its own. |
| 02:00 | Soak ends. |
| next morning | `m08.sh --report`, verdict, post the soak report to #109. |

If setup runs late, drop the optional FreeSWITCH M03 and shorten M06, never the soak or M03 on the whole host.

---

## M03: the competitor scenario (run first)

**Goal.** Reproduce the competitor's published test as closely as `run.sh` allows, and compare. Their
result: "50 call per second, 1000 concurrent call, Used Memory 1730M, CPU Load 26%, Call Duration 600 seconds"
(Xeon X5670, 8 GB, Debian 10).

**Interpretation.** Calls are offered at 50 CPS up to a cap of 1000 concurrent, each call lasts 600 s,
and the cap is then held by starting a new call as an old one ends (steady state about 1000/600 = 1.67 CPS).
The plateau must last at least one full hold after the ramp (run at least about 1300 s, prefer two holds).

**What run.sh does with that.** `-r 50` offers 50 calls/s; `-c N` caps SIPp's simultaneous calls at
`N + N/10 + 10` (`-l`), so `-c 900` gives a cap of exactly 1000; once the cap is reached SIPp creates
new calls only as old ones end; `-H 600` is the hold (a 602 s G.711 pcap is generated with python3,
which is under the 900 s pcap cap, and the pcap covers the whole hold, so the 5 minute RTP silence
watchdog does not fire); `-t 40` with `-r 50` means 2000 calls in all (`-m` = rate x t): the first 1000
are up after about 20 s, the other 1000 start as the first ones end, which holds the plateau at 1000
for two holds (about 1200 s); `-u 2000` users, pre-registered (REG_RATE 200/s, 10 s). G.711 media runs
both ways on both legs. The run lasts about 1820 s. The difference to the competitor: the cap is
SIPp's, so concurrency is 1000 +- a few calls, not exactly 1000; the closest equivalent.

**Command.** `m03.sh` wraps all of it (limits cores, restarts FreeSBC, starts hostmon on the three hosts, runs
`run.sh -r 50 -c 900 -H 600 -t 40 -u 2000 call`, launches three 120 s webrtcload probe batches of 20 calls
inside the plateau for loss and jitter, since SIPp does not measure received RTP, then prints the
verdict and the side-by-side table). Run each variant detached:

```sh
cd /opt/freesbc && . test/perf/hosts/env.sh sipp
nohup test/perf/hosts/m03.sh all  sipp > results/logs/m03-all-sipp.log 2>&1 &    # whole host: 4 vCPU, 8 GiB
# when it has finished (about 35 min), one after the other:
nohup test/perf/hosts/m03.sh 2    sipp > results/logs/m03-2-sipp.log 2>&1 &
nohup test/perf/hosts/m03.sh 1    sipp > results/logs/m03-1-sipp.log 2>&1 &
# optional, last of the day, a real FreeSWITCH behind FreeSBC:
. test/perf/hosts/env.sh fs && nohup test/perf/hosts/m03.sh all fs > results/logs/m03-all-fs.log 2>&1 &
```

`sbc-cores N` (N counts vCPUs; on this Hyper-Threaded instance 2 vCPUs may be one physical core, `sbc-cores show` prints the sibling layout, quote it) sets a systemd `CPUAffinity=0-(N-1)` drop-in on B and restarts FreeSBC (Go then sees N CPUs).
The NIC's interrupts and softirq are not pinned and may use the other CPUs; state this. Afterwards
`ssh sbc sudo sbc-cores all`. A does the limiting over ssh (B's agent does not have to be involved).

**Pass.** The pass criteria above at 1000 concurrent: failed under 0.1%, no aborted SIPp, no
`invite_rejects`, loss under 0.1%, plateau lasting two holds (`plateau_s` about 1200 or more). On 4 vCPU and especially on 2 and 1 cores the 1000-call plateau may not hold: then report where and how it failed (failed calls, loss, CPU, which limit) instead of a pass. For the 2 and 1
core runs the CPU criterion tells whether FreeSBC still holds the load: report the CPU in percent of the
available cores and say whether it stayed under 80%, and if a limited run fails say at which load it breaks
(do not tune to rescue it).

**Record** (the table is produced by `m03-table.sh RUN_DIR`, daily-report.sh includes it for every
`m03.tag` run directory): for each of all (4 vCPU) / 2 / 1 cores and SIPp / FreeSWITCH: concurrent calls (plateau
average and peak), FreeSBC RSS (plateau max) and whole-host used memory (hostmon, plateau), CPU as
whole-host % averaged over the plateau (100 = all vCPUs), the busiest core, load average 1/5/15 min,
FreeSBC process CPU (100 = one core), failed calls, INVITE-to-200 p95 bucket, RTP tx/rx, probe loss and jitter.
The competitor's "CPU Load 26%" does not say which definition it used; show both whole-host % and load
average and name the definition of each. Add B's `lscpu` model and frequency (`sbc-lscpu.txt` in the run
directory) and the OS/kernel difference. Check C's and A's SIPp CPU in `hostmon-switch.csv` /
`hostmon-loadgen.csv` (the SIPp echo UAS is one thread: at 1000 calls it is 50k packets/s; if it is
near a full core, say the figure is rig-limited).

**Duration.** About 31 minutes per run plus 2 minutes setup.

---

## M01: CPS steps without media

**Goal.** Find the knee: the highest call setup rate (calls/s, no RTP, 2 s calls) under the pass
criteria, for `call` (client to switch), `carrier-in` (carrier to switch) and `carrier-out` (switch to
carrier).

**Setup.** `. env.sh sipp; ssh sbc sbc-cores all; ssh sbc freesbc-use sipp`. For carrier-out the SIPp UAC runs on
C but its stats and the media-stripped scenario live in A's `out/` directory: mount it first (STEPS.md R15):
`ssh switch 'mountpoint -q /opt/freesbc/test/perf/out || sshfs -o cache=no,reconnect loadgen:/opt/freesbc/test/perf/out /opt/freesbc/test/perf/out'`
and unmount after (`ssh switch 'fusermount3 -u /opt/freesbc/test/perf/out'`).

**Commands** (the three-host form of the `test/perf/README.md` commands):

```sh
export REG_RATE=1000                                  # pre-register 12000 users in 12 s instead of 60 s
nohup test/perf/run.sh -n -u 12000 -s 250:8000:250:40 -H 2 call        > results/logs/m01-call.log 2>&1 &
# then, one after the other:
nohup test/perf/run.sh -n -s 250:8000:250:40 -H 2 carrier-in          > results/logs/m01-carrier-in.log 2>&1 &
nohup test/perf/run.sh -n -s 250:6000:250:40 -H 2 carrier-out         > results/logs/m01-carrier-out.log 2>&1 &
```

`-s FROM:TO:INC:SECS` runs each rate for 40 s and stops at the first step over 0.1% failures. Start low
and fine if the knee is below 250 (`-s 50:1000:50:40`). Restart FreeSBC between the three
(`ssh sbc freesbc-use sipp`). Then confirm the knee: run 120 s at 90% of it, which also gives the CPU,
RSS and goroutines at a sustained rate:

```sh
test/perf/run.sh -n -u 12000 -r <0.9 x knee> -t 120 -H 2 call           # nohup as above; for carrier-in/out drop -u
```

**Pass.** The knee is the last step that has `verdict=pass`, no aborted SIPp (`runcheck.sh` on the run:
in step mode run.sh itself would call an aborted step a pass), CPU (`steps.csv` `cpu_avg_pct`) under
320 (80% of 4 vCPU), `udp_rcvbuf_errors` 0, and no `invite_rejects`/`admission_drops` at that step. If the
first failing step has low FreeSBC CPU, look at A's SIPp CPU (`hostmon-loadgen.csv`; a single SIPp process tops
out at a few thousand CPS) and at `udp_rcvbuf_errors` / `rmem_max`: then the knee is rig-limited and a
lower bound.

**Record.** Per scenario: knee (CPS), `steps.csv` (paste it), CPU avg/peak at the knee, RSS peak, goroutines,
retransmissions, `rt_p95_bucket_ms`, `cps_median`/`cps_max`, what failed first, and whether the limit was FreeSBC,
A or the kernel. Take the pprof at the knee (M07). **Duration:** about 15 minutes per scenario with the
confirm run (45 to 60 minutes in all).

---

## M02: concurrent G.711 calls with media

**Goal.** The most concurrent calls (both legs anchored, media both ways) FreeSBC holds under the 80% CPU
and 0.1% added loss limits.

**Command** (derived from `docs/performance.md`, `run.sh -c 1000 -H 30 -t 90 -u 1000 call`, here stepped):

```sh
cd /opt/freesbc && . test/perf/hosts/env.sh sipp
nohup test/perf/hosts/ladder.sh m02 "-c @N@ -H 60 -t 180 -u @N@ call" 250 500 750 1000 1250 1500 2000 2500 3000 4000 \
  > results/logs/m02.log 2>&1 &
```

Each value restarts FreeSBC, runs `run.sh -c N -H 60 -t 180 -u N call` (calls ramp up in 60 s, hold at N for
at least two more minutes, so the plateau is 2 holds), judges it with `runcheck.sh`, and stops at the first
value that fails, has plateau CPU at or over 80% of the cores, or plateau `tx_over_rx` under 0.999. The last
passing value is the maximum (`results/ladder-m02-*.txt`). Refine between the last pass and the first fail
(for example 100 steps: `ladder.sh m02b "..." 900 1000 1100`). The rtp range allows 25000 calls and
`max_sessions` is 25000, so neither is the limit.

**Rig limit.** One SIPp process plays all the pcaps and one SIPp UAS echoes them. Watch A's `sipp` and
C's `sipp` CPU in hostmon during the ladder (`tail -n 3 /var/tmp/day-loadgen.csv`; `ssh sbc`/`switch` for the
others). `run.sh` cannot start a second generator process: if either is at about 95% of a core before
FreeSBC reaches 80% (320), say the maximum is rig-limited. A real FreeSWITCH as the echo (M06) removes the
UAS limit but not the generator's.

**M02c: latency FreeSBC adds** (needs a run directly against the switch): run the same load once at
1000 concurrent through FreeSBC and once straight to the switch UAS with `-T`:

```sh
test/perf/run.sh -c 1000 -H 60 -t 180 -u 1000 call                         # via FreeSBC, note rt_p95_bucket_ms
test/perf/run.sh -T $SWITCH_IP:5060 -c 1000 -H 60 -t 180 -u 1000 call     # direct baseline (the SIPp UAS answers REGISTER too)
```

The difference of `rt_mean_ms` and `rt_p95_bucket_ms` is what FreeSBC adds (bucket resolution is coarse; quote
`rt_mean_ms` as well).

**Record.** Maximum concurrent calls under the criteria; at that value: plateau CPU avg/peak, whole-host CPU,
RSS, goroutines, open fds, ports in use, RTP pps and Mbit/s, `tx_over_rx`; the first failing value and why
(CPU, loss, failures, rig); the M02c latency pair. Take pprof at the peak (M07). **Duration:** about 5 minutes
per value, 40 to 60 minutes with the refinement.

**Decide the soak size now:** `N70 = 0.7 x maximum`, rounded down to a multiple of 50. Write it into
measure-results.md.

---

## M04: registrations held, REGISTER/s at refresh

**Goal.** Bindings held (the cap is 20000) and the REGISTER rate FreeSBC absorbs when they refresh.

**Commands.**

```sh
. test/perf/hosts/env.sh sipp; ssh sbc freesbc-use sipp
# 1. hold 19000 bindings: one REGISTER per user at 1000/s (19 s); read active_registrations_peak
test/perf/run.sh -r 1000 -t 19 -u 19000 register
# 2. refresh rate: each step re-registers all 19000 users (same Call-IDs, so the same bindings) at a rising rate
test/perf/run.sh -u 19000 -s 1000:20000:1000:40 register
```

Run 1 and 2 with a restart in between. In step mode the number of REGISTERs per step is rate x 40, so
each step is two rounds or more over the 19000 users.

**Pass.** Failed under 0.1% (and no aborted SIPp), CPU under 320, `active_registrations_peak` at least
19000 in run 1. The refresh maximum is the last passing step.

**Record.** Bindings held, RSS at 19000 bindings minus RSS at start (per binding), the refresh maximum in
REGISTER/s with CPU at that rate, what failed first. **Duration:** about 15 minutes.

---

## M05: WebRTC handshakes/s and concurrent SRTP calls

**Goal.** DTLS handshakes per second, and concurrent WebRTC (ICE-Lite, DTLS-SRTP) calls with media.

**Commands** (switch SIPp: its UAS echoes; `-W 200` WebSocket connections, the cap is 256 per source IP):

```sh
. test/perf/hosts/env.sh sipp; ssh sbc freesbc-use sipp
nohup test/perf/hosts/ladder.sh m05-rate "-r @N@ -t 30 -H 3 -W 200 webrtc" 10 25 50 100 150 200 300 400 600 \
  > results/logs/m05-rate.log 2>&1 &
# when finished:
nohup test/perf/hosts/ladder.sh m05-conc "-c @N@ -H 60 -t 150 -W 200 webrtc" 100 200 400 600 800 1000 1500 2000 \
  > results/logs/m05-conc.log 2>&1 &
# TLS variant at the largest passing rate and concurrency of the above, one run each:
test/perf/run.sh -r <rate> -t 30 -H 3 -W 200 -w wss://$SBC_PUBLIC:443 webrtc
```

**Pass.** `calls_failed` under 0.1% (`webrtc` block), `reg_failed=0`, CPU under 320, echoed packets: `rtp_echoed`
at least 99.9% of `rtp_sent`, no aborted run. The generator (`webrtcload`, Go) uses A's cores: check A's CPU in hostmon.

**Record.** Maximum rate (calls/s = handshakes/s) with `dtls_per_s`, `dtls_peak_per_s`, `dtls_p95_ms`, `setup_p95_ms`
and CPU; maximum concurrent SRTP calls with `rtp_sent/echoed`, `seq_gap_lost`, `jitter_mean_ms`, `jitter_p99_ms`, `rtt_p50_ms`, CPU,
RSS; the ws and wss difference. **Duration:** about 25 to 45 minutes.

---

## M06: FreeSWITCH as the switch

**Goal.** The same CPS and concurrency figures with a real switch behind FreeSBC, to separate FreeSBC's cost from
the switch's (`test/perf/README.md`, "Load through a real FreeSWITCH").

**Setup.** `. test/perf/hosts/env.sh fs; ssh sbc freesbc-use fs`; flush FreeSWITCH registrations before each run
(ladder.sh does). FreeSWITCH is configured by provision.sh for 5000 sessions/s, 30000 sessions, RTP 20000-59999, log level
warning; record the version (`ssh switch 'sudo fs_cli -x version'`). Carrier scenarios do not work with `SWITCH=freeswitch`.

**The early-dialog cap.** FreeSBC allows at most 64 unanswered (early) dialogs per public source IP (carrier
sources exempt; `invite_rejects{reason="early_cap"}`). With a real switch the answer takes time, so one source IP can
offer at most about 64 / answer-delay calls per second (at 50 ms answer delay: 1280 CPS). `run.sh` has one
client source address (`LOADGEN_IP`). The client must register from the IP it calls from, and a carrier source cannot
register, so A's carrier-generator and carrier-UAS addresses cannot serve as a second source.

- Without `A_LOADGEN2_IP` in plan.env: run from `A_IP` only, document the cap, and read `early_cap` in
  `freesbc_edge_invite_rejects_total`. A knee at which `early_cap` rejects appear is a harness limit, not FreeSBC's.
- With `A_LOADGEN2_IP` set (a third secondary IP on A): with `SWITCH=freeswitch` no SIPp UAS is started, so two
  `run.sh` instances can run side by side, each from its own IP at half the rate, started at least 2 s apart:
  `LOADGEN_IP=$A_IP run.sh -r R ... &  sleep 3; LOADGEN_IP=$LOADGEN2_IP run.sh -r R ... &`. Judge each run with runcheck.sh and add the two.

**Commands.**

```sh
# CPS without media (from test/perf/README.md): steps of 50 up to 1500, 30 s each
nohup test/perf/run.sh -n -u 5000 -s 50:1500:50:30 -H 2 call > results/logs/m06-cps.log 2>&1 &
# concurrent calls with media (echo application on extension 2000), stepped
nohup test/perf/hosts/ladder.sh m06 "-c @N@ -H 60 -t 180 -u @N@ call" 250 500 750 1000 1500 2000 3000 \
  > results/logs/m06.log 2>&1 &
# registrations with FreeSWITCH as the registrar
test/perf/run.sh -r 500 -t 20 -u 5000 register
```

Also compare with M01's `call` knee and M02's maximum (same commands, SIPp switch). The `-s` step run does
not restart FreeSBC or flush FreeSWITCH between steps; restart both before it.

**Pass.** The pass criteria. FreeSWITCH's own CPU (`hostmon-switch.csv`, `freeswitch_cpu_pct`): if it is the first to
saturate, the figure is the switch's. Check `fs_cli -x 'show channels count'` at the plateau and `/var/log/freeswitch-perf/` for
warnings.

**Record.** CPS knee and concurrency maximum with FreeSWITCH, the same with SIPp, the FreeSWITCH version, whether `early_cap`
appeared, FreeSWITCH CPU at the limit. **Duration:** about 50 to 60 minutes.

---

## M07: pprof at the peak

**Goal.** CPU, goroutine and heap profiles of FreeSBC at the peak of M01 (signaling) and M02 (media), with the matching binary.

**Command.** While the plateau (or the confirm run at 90% of the knee) is running, from a second short call on A:

```sh
test/perf/hosts/pprof.sh m01-call-<cps>cps 30          # CPU 30 s, goroutines, heap, allocs, binary
test/perf/hosts/pprof.sh m02-<calls>calls 30
```

Files land in `results/<date>/pprof/`. Read them on A: `go tool pprof -top -nodecount=30 results/<date>/pprof/freesbc-linux results/<date>/pprof/m02-...-cpu.pb.gz`
(the Go toolchain is installed on A). **Record:** the top 15 functions by cumulative CPU for each, goroutine count by top
stack groups (`goroutine.txt`), heap in use and the top allocators, and what they suggest (syscall cost, GC share, timers). This is the data
the 80% claim needs. **Duration:** inside M01 and M02 (about 2 minutes of work each).

**The #170 RSS per CPS figure (also here).** The perf-rig note `docs/notes/170-sipgo-tx-linger.md` asks for this run to close the issue:

```sh
ssh sbc freesbc-use sipp
nohup test/perf/run.sh -n -s 1000:3500:500:60 -H 2 carrier-in > results/logs/m07-170-carrier-in.log 2>&1 &
# and the call step test:  test/perf/run.sh -n -u 12000 -s 1000:3500:500:60 -H 2 call
```

Compute RSS and goroutines per CPS from `steps.csv` (columns: `rate`, ..., `rss_peak_mb`, `goroutines_peak`):

```sh
awk -F, 'NR>1 && $4=="pass" {printf "%s cps: rss %.0f MB = %.2f MB/cps, goroutines %s = %.1f per cps\n",$1,$7,$7/$1,$8,$8/$1}' test/perf/out/<run>/steps.csv
```

Compare with the pre-v1.6.0 figures (2.3 MB RSS and about 76 goroutines per CPS, 0.8 MB/CPS live heap at 2500 CPS carrier-in).
A step at 60 s is beyond the 32 s transaction linger, so each step reaches its steady state. The limit is GOMEMLIMIT=6GiB:
if RSS approaches it, GC CPU rises (say so). **Duration:** about 10 minutes per scenario.

---

## M08: the soak

**Goal.** 8 hours at 70% of the M02 maximum with no growth in goroutines, RSS, fds and ports in use.

**Command.** Start at about 18:00, after M01 to M07 and the day report (nothing else may use B, C or A afterwards):

```sh
cd /opt/freesbc && . test/perf/hosts/env.sh sipp && ssh sbc sudo sbc-cores all
nohup test/perf/hosts/m08.sh <N70> 8 > results/m08.log 2>&1 &
```

It runs `run.sh -i 30 -c N70 -H 240 -t 28800 -u N70 call` (hold 240 s, under the 300 s a pcap hold is good
for; metrics every 30 s), hostmon on B every 60 s, and an hourly goroutine and heap snapshot to
`results/<date>/soak/`. Poll rarely (every 30 to 60 minutes): `tail -n 3 results/m08.log`,
`tail -n 2 test/perf/out/*-call/metrics.csv | cut -d, -f1-8`, `pgrep -f test/perf/run.sh`.
Spot reclaim of any host ends the soak: note the time, restart it, and report the interrupted attempt.

**Pass.** Via `soakcheck.sh` (called by `m08.sh --report`): the median of the last quarter within 5% of the first quarter (10 minute
ramp skipped) for `goroutines`, `rss_bytes`, `open_fds` and `ports_in_use`; the slope per hour; `ports_in_use` back to 0
at the end; `runcheck.sh` clean (failed under 0.1%, no aborted SIPp); no `invite_rejects`, `admission_drops`;
`freesbc_edge_calls_ended_total` dominated by `bye_caller` (no `rtp_silence`, `ack_timeout`, `media_fault`).

**Record / report (next morning).**

```sh
test/perf/hosts/m08.sh --report test/perf/out/<soak run>        # writes soak-report.md in the run directory
test/perf/hosts/soakcheck.sh test/perf/out/<soak run> 10
```

Post `soak-report.md` (scrubbed of public IPs and secrets) to #109. **Duration:** 8 hours.

---

## Anything run.sh cannot do as written

- **UDP loss and jitter for SIPp calls**: not measured. Substitute: FreeSBC `tx_over_rx` and `udp_rcvbuf_errors` for every run, and the webrtcload
  probes (M03) for end-to-end loss, jitter and RTT through both legs.
- **Exactly 1000 concurrent calls (M03)**: the cap is SIPp's `-l` (900 + 10% + 10 = 1000), so concurrency is 1000 +- a few.
- **More than one generator process** (M02, M05 at very high load): not supported; the figure is a lower bound when A's SIPp saturates.
- **Several client source IPs** (M06): only with `A_LOADGEN2_IP` and two parallel `run.sh` runs; otherwise the 64 early-dialog cap per source IP
  limits CPS against a slow-answering switch.
- **Carrier scenarios against FreeSWITCH**: refused by run.sh; they use the SIPp switch.
- **Switch-to-client calls, TCP/TLS signaling load, SDES-SRTP**: no scenario (see the list at the end of `docs/performance.md`).
- **carrier-out** needs C to see A's `out` directory (sshfs, M01).
