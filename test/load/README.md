# FreeSBC deployment and load test

A real three-server deployment and load test of FreeSBC: SIPp on a public host
drives real SIP and RTP through FreeSBC into FreeSWITCH or Asterisk on a
private LAN. Everything here is rendered from one `env` file, so the same
harness runs in a cloud, in an IDC, or in a single-host lab.

```text
        S1  SIPp (public)                S2  FreeSBC                    S3  switches (LAN only)
   ┌──────────────────────┐   UDP   ┌──────────────────────┐   UDP   ┌───────────────────────────┐
   │ carrier IP  .10      │ ──────▶ │ public.ip  :5060     │         │ FreeSWITCH internal :5060 │
   │  UAC :5072  UAS :5070│ ◀────── │ RTP 10000-59999      │         │            external :5080 │
   │ phone IP    .11      │ SIP+RTP │                      │ SIP+RTP │ Asterisk            :5160 │
   │  phones :5061        │         │ private.ip :5060     │ ──────▶ │ RTP FS 30000-39999        │
   │  agents :5062        │         │ RTP 10000-59999      │ ◀────── │ RTP Ast 40000-49999       │
   └──────────────────────┘         └──────────────────────┘         └───────────────────────────┘
          internet / WAN                      │                         private LAN, no route out
```

Status of this harness, so nothing is taken on trust:

| Item | State |
|---|---|
| SIPp scenarios, render, run/collect/latency scripts | **Run end to end** in the namespace lab (`lab/smoke.sh`) through the real FreeSBC binary and Asterisk 20.6, in both the direct and the 1:1 NAT topology. Every case passes and every gauge returns to zero. |
| Asterisk config | **Run** (same lab). |
| FreeSWITCH config | **Not run.** Written against FreeSWITCH 1.10's stock `conf/vanilla`; `install-freeswitch.sh` was applied to that tree and the result parses, but no FreeSWITCH process has loaded it. Phase 1 (§5.1) checks it first. |
| Capacity numbers | **None yet.** Every number in §8 is arithmetic for sizing, not a measurement. |

## 1. Roles

| Host | Role | Addresses | Software |
|---|---|---|---|
| S1 | Load generator: plays carriers, phones and agents | two public IPs (§2.4): carrier IP, phone IP | SIPp 3.7.x with PCAP + RTP streaming, tcpdump, tshark |
| S2 | FreeSBC, the only public SIP/RTP element | public (or VPC IP + 1:1 NAT), private | `freesbc`, `curl`, `tcpdump`, `tshark`, `python3` |
| S3 | FreeSWITCH and Asterisk side by side | private LAN only | Docker (host networking) or native packages |

Both switches run at once on S3 on different ports and RTP ranges. FreeSBC
points at one of them at a time (`edge.switch` is restart-only); `activate.sh`
switches between them. They are deliberately not one `edge.switch` pool: a
pool hashes users across nodes that must share one registration store, which
FreeSWITCH and Asterisk do not.

### 1.1 What each test exercises in FreeSBC

| Case | Call path | FreeSBC paths | Media legs on S2 per SIPp call |
|---|---|---|---|
| T1 | carrier → switch (echo) | inbound carrier (admitted by source IP, `X-FreeSBC-Carrier`, delivered to the carrier port) | 1 public + 1 private |
| T2 | carrier → switch → carrier (hairpin) | inbound carrier, then switch → carrier via outbound proxy (`edge.carriers` match, topology hiding) | 2 + 2 |
| T3 | registered phone → switch (echo) | REGISTER proxying + `fsbc=` token, admission by registered transport address, digest (407 FS / 401 Asterisk) | 1 + 1 |
| T4 | carrier → switch → registered agent | inbound carrier, then switch → client by token | 2 + 2 |
| T5 | REGISTER storm | REGISTER proxying, binding table | — |
| T6 | abuse: admission, rate limit, scanner, ringing cap, malformed | shield, admission, `maxEarlyPerSource` | — |

T1/T3 measure one call leg pair; T2/T4 load both directions through the SBC at
once and are the realistic call-center shapes (PSTN in → agent; PSTN in → PSTN
out).

## 2. Network topologies

FreeSBC's addressing is three facts (`docs/config.md`): `public.ip`
(advertised), `public.bind` (local, differs only behind 1:1 NAT) and
`private.ip` (local, on the NIC that faces the switch). The private socket
only accepts datagrams that arrive on the interface owning `private.ip`
(BPF ingress filter, `docs/edge.md`), so the switch must reach S2 on exactly
that interface.

### T-A. Cloud, S2 with two NICs (recommended for cloud)

```text
 S1 (other VPC/region, EIP) ──internet── EIP ⇄ 1:1 NAT ⇄ S2 eth0 172.31.5.10  (public subnet)
                                                       S2 eth1 10.77.0.2    (private subnet) ── S3 10.77.0.20 (no EIP)
```

- `public.ip` = the EIP, `public.bind` = eth0's VPC address, `private.ip` = eth1's address.
- S3 lives in a private subnet with no public IP and no default route out.
  Packages arrive by `docker save | ssh S3 docker load` or a NAT gateway that
  you detach before the test.
- **Put S1 in a different VPC or region, without peering.** In the same VPC,
  SIPp's SDP carries its VPC address and FreeSBC's provisional media
  destination (seeded from SDP) would reach it over the VPC fabric, bypassing
  the NAT path you meant to test. Across VPCs, traffic takes the EIPs, which
  is what real carriers and phones do.
- Security groups: see §2.5. The cloud firewall is stateful; S2 also starts
  flows toward S1 (T2's INVITE to the carrier, T4's INVITE to agents, RTP), so
  S1's group must allow them inbound.
- Provider notes (check your provider's current docs): AWS and Alibaba Cloud
  attach a second ENI in another subnet of the same AZ, with the EIP on the
  primary ENI; on GCP each NIC must be in a different VPC and NICs are fixed at
  creation. Avoid burstable instance types: their CPU credits and PPS
  allowances end a long test early and make results unrepeatable.

### T-B. Cloud, S2 with one NIC (degraded, acceptable for a first run)

`private.ip` is a secondary private address on the same eth0. It works because
the VPC fabric never delivers internet traffic addressed to a private IP, but
the BPF ingress filter no longer separates the planes (both arrive on eth0),
and S3 shares a subnet with the public side. Use only when a second NIC is not
available; say so in the report.

### T-C. On-prem / IDC, S2 dual-homed with a public address

```text
 S1 ──WAN── S2 eth0 203.0.113.7 (public)    S2 eth1 10.77.0.2 ── switch ── S3 10.77.0.20
```

`public.ip` = `public.bind` = eth0's address. The simplest topology and the
one with the fewest variables; prefer it for capacity numbers.

### T-D. On-prem behind a firewall, S2 in a DMZ with 1:1 NAT

Same FreeSBC config as T-A (`public.bind` = DMZ address). The firewall must:
map the public IP 1:1 to the DMZ address **with ports preserved** for UDP 5060
and the whole RTP range (FreeSBC advertises its bound ports; there is no port
translation field), disable SIP ALG / SIP inspection (it rewrites the bodies
FreeSBC constructs), and allow enough UDP sessions (each call is 4 flows on
S2). Asymmetric routing between the two FreeSBC NICs is not allowed.

### T-E. Isolated lab (no internet)

All three on one L2 switch or hypervisor, two VLANs: a "public" one in
198.18.0.0/15 (RFC 2544 benchmarking range, never routed) and the private LAN.
`lab/netns.sh` builds exactly this on a single Linux host (both the direct and
the 1:1 NAT variant), which is what `lab/smoke.sh` runs. Best for repeatable
capacity numbers; it misses only internet effects (loss, jitter, NAT
rebinding).

### Hybrid: S2 in the cloud, S3 on-prem over a VPN

Not part of this three-server plan, but common. Put `private.ip` **on the
tunnel interface itself** (`wg0`): the ingress filter accepts datagrams that
arrive on the interface owning `private.ip`, so `private.ip` on eth1 with the
switch behind `wg0` drops every switch packet silently (only upstream
timeouts show). VRFs break it the same way.

### 2.4 One SIPp host, two roles: two public IPs on S1

FreeSBC treats a source as a carrier (admitted by IP,
`shield.carrier_rate_limit`, never banned as a scanner, exempt from the 64-call
ringing cap) or as a phone (must register first, `shield.rate_limit`, ringing
cap applies). The shield decides by IP alone, so phones registered from a
carrier IP silently get the carrier rate limit and scanner exemption, while
admission treats their registered socket as a phone. To test both paths
honestly from one server, S1 needs two public addresses:
`SIPP_CARRIER_IP` (listed in `edge.carriers`) and `SIPP_CLIENT_IP` (not
listed). In a cloud that is a secondary private IP with a second EIP.

With one address, set both variables equal: `render.sh` then also produces
`*-clientonly` FreeSBC profiles without carriers, and T3/T5/T6 run under
those (one restart each way).

### 2.5 Flows to allow

| From → To | Protocol / ports | Why |
|---|---|---|
| S1 → S2 public | UDP 5060, UDP `SBC_RTP` | SIP and RTP into FreeSBC |
| S2 public → S1 | UDP 5061, 5062, 5070, 5072, UDP `SIPP_RTP_MIN-MAX` | responses, calls to the carrier UAS and agents, RTP |
| S2 private → S3 | UDP 5060, 5080 (FreeSWITCH), 5160 (Asterisk), UDP `FS_RTP`, `AST_RTP` | SIP and RTP to the switch |
| S3 → S2 private | UDP 5060, UDP `SBC_RTP` | switch to FreeSBC's private socket and media |
| operator → S2 | TCP 22; admin stays on 127.0.0.1:8080 (use `ssh -L 8080:127.0.0.1:8080 S2`) | management |

Nothing else reaches S3. On the S3 side the switches also restrict
themselves: FreeSWITCH's external profile has `apply-inbound-acl=fsbc`,
Asterisk a pjsip `acl` that permits only `private.ip`.

## 3. Host preparation

### 3.1 Sizing

| | S1 SIPp | S2 FreeSBC | S3 switches |
|---|---|---|---|
| CPU | ≥ S2 (it generates and receives the same RTP as S2's public side) | 8 vCPU to start; the result tells you the per-core number | 16 vCPU (Asterisk and FreeSWITCH are both heavier per call than a relay) |
| RAM | 8 GB | 4 GB | 16 GB |
| NIC | ≥ S2's public bandwidth (§8) | multiqueue (ENA/virtio-mq), RSS on | — |
| OS | Ubuntu 24.04 | Ubuntu 24.04 / Debian 12 | Ubuntu 24.04 + Docker, or native |

If S1 saturates first the run measures SIPp, not FreeSBC (§7.3).

### 3.2 Kernel (S1 and S2)

`sbc/99-freesbc-load.conf` → `/etc/sysctl.d/`, then `sysctl --system`.
FreeSBC never sets `SO_RCVBUF`/`SO_SNDBUF`, so every one of its sockets uses
`net.core.rmem_default`/`wmem_default`; raising only the `_max` values changes
nothing for it. It also moves the ephemeral port range above the RTP range.

### 3.3 Limits and time

- File descriptors: four UDP sockets per anchored call (RTP+RTCP on each
  side). The unit sets `LimitNOFILE=1048576`; Go raises the soft limit to it.
- Clocks: chrony on all three hosts; the latency tool compares two captures
  from one host (no skew), but cross-host log correlation needs synced clocks.

### 3.4 Firewalls and conntrack

Prefer the cloud security group / external firewall and no stateful host
firewall on S2. If S2 must run nftables/iptables with conntrack, size
`nf_conntrack_max` for 4 flows per call or exempt the RTP range with a
`notrack` rule; a full conntrack table drops packets with only a kernel log
line. Unload SIP helpers on every hop (`nf_conntrack_sip`, `nf_nat_sip`).

## 4. Deployment

### 4.1 Render

```sh
cd test/load
cp env.example env && $EDITOR env      # addresses, ports, user counts, passwords
./render.sh                             # writes out/sbc, out/switch, out/sipp
```

Needs `envsubst` (gettext-base), `htpasswd` (apache2-utils) and `sox`. The
admin bcrypt hash is cached in `.admin_hash` so re-rendering does not change a
restart-only key.

### 4.2 S2: FreeSBC

```sh
# build (Go version per go.mod) or take a release tarball
go build -ldflags "-X main.version=$(git describe --always)" -o freesbc ./cmd/freesbc
sudo install -m 0755 freesbc /usr/local/bin/freesbc
sudo useradd --system --no-create-home freesbc
sudo install -d -o freesbc -g freesbc -m 0750 /etc/freesbc
sudo cp out/sbc/99-freesbc-load.conf /etc/sysctl.d/ && sudo sysctl --system
sudo cp out/sbc/freesbc.service /etc/systemd/system/ && sudo systemctl daemon-reload
sudo touch /etc/freesbc/freesbc.yaml && sudo chown freesbc:freesbc /etc/freesbc/freesbc.yaml
cd out/sbc && sudo ./activate.sh freeswitch load   # check + install + (re)start
sudo systemctl enable freesbc
journalctl -u freesbc -f                           # "edge proxy listening ... carrier_sources=..."
```

`activate.sh <base> <shield>` composes `base-<switch>.yaml` and
`shield-<profile>.yaml`, runs `freesbc check`, installs atomically, and
restarts only when a restart-only key changed; a shield-only change is a hot
reload. Profiles: `load` (limits far above one source, for capacity runs) and
`default` (production defaults, for T6).

### 4.3 S3: switches

Docker (both switches on one LAN-only host, host networking so no NAT sits in
the RTP path):

```sh
cd out/switch
echo -n '<SignalWire personal access token>' > signalwire_token   # FreeSWITCH packages need one (free)
docker compose build                     # on a host with internet
docker save load-freeswitch load-asterisk | ssh S3 docker load
scp docker-compose.yml S3: && ssh S3 docker compose up -d
```

Native instead: Asterisk on Ubuntu 24.04 is `apt install asterisk` then
`./install-asterisk.sh`; FreeSWITCH on Debian 12 is
`curl -sSL https://freeswitch.org/fsget | bash -s <token> release install`
then `./install-freeswitch.sh`. The FreeSWITCH overlay replaces the
`internal`/`external` profiles, adds the `loadcarrier` gateway (outbound proxy
= FreeSBC), the users and dialplan, replaces the stock STUN lookups (S3 has no
internet), raises `max-sessions` (1000 → 20000) and `sessions-per-second`
(30 → 2000; the stock 30 caps every CPS test), and moves the core DB to
`/dev/shm`.

Switch-side rules this config follows (`docs/edge.md`): client traffic is
always digest-authenticated (no ACL or `identify` by FreeSBC's IP), carrier
traffic is recognised by FreeSBC's carrier port (FreeSWITCH) or
`X-FreeSBC-Carrier` (Asterisk), and outbound carrier calls use FreeSBC as
outbound proxy with a Request-URI equal to the `edge.carriers` entry.

### 4.4 S1: SIPp

The distribution packages are often old or built without RTP streaming. Build
3.7.x:

```sh
sudo apt install -y build-essential cmake pkg-config git libpcap-dev libncurses-dev \
  libssl-dev libgsl-dev libpugixml-dev tcpdump tshark sox
git clone --branch v3.7.9 --depth 1 https://github.com/SIPp/sipp && cd sipp
cmake . -DUSE_PCAP=1 -DUSE_SSL=1 -DUSE_GSL=1 && make -j"$(nproc)" sipp
sudo install -m 0755 sipp /usr/local/bin/
sudo cp ../out/sbc/99-freesbc-load.conf /etc/sysctl.d/ && sudo sysctl --system
```

Copy `out/sipp` to S1 and run everything from there as root (raw capture,
high fd limits). Media is SIPp's `rtp_stream` (PCMA, per-call ports, a thread
pool) rather than `pcap_play` (one thread per call).

### 4.5 Rehearse in the lab first (optional, 2 minutes)

```sh
sudo apt install -y iproute2 nftables asterisk tcpdump tshark gettext-base apache2-utils sox
sudo FREESBC=$PWD/freesbc SIPP=/usr/local/bin/sipp test/load/lab/smoke.sh nat
sudo ABUSE=1 FREESBC=$PWD/freesbc SIPP=/usr/local/bin/sipp test/load/lab/smoke.sh direct   # + T6
```

Brings up S1/S2/S3 as network namespaces (`lab/netns.sh`, `direct` or `nat`),
runs T1–T4 with registration and removal, and checks that calls, dialogs,
media sessions, ports and registrations all return to zero. Output from this
repo's run:

```text
PASS t1 CC=10 HOLD=5 SECS=10 ...   ok=20
PASS t2 ...                        ok=20
PASS reg-a                         ok=50
PASS t3 ...                        ok=20
PASS reg-b                         ok=50
PASS t4 ...                        ok=20
PASS unreg-a / unreg-b             ok=50
     t1 rtp: streams=14 packets=2107 lost=0 (0.0000%) ...
T6   t6-admission                ok=0    failed=20   admission+80 rate+0 scanner+0
T6   t6-ringcap                  ok=64   failed=36   admission+0 rate+0 scanner+0
T6   t6-rate CPS=100 T6_SECS=5   ok=149  failed=351  admission+0 rate+1111 scanner+0
T6   t6-scanner                  ok=0    failed=5    admission+0 rate+0 scanner+1
T6   t6-garbage                  ok=-    failed=-    admission+0 rate+0 scanner+0
PASS freesbc_active_calls=0 ... freesbc_active_registrations=0
```

## 5. Test cases

All on S1: `./run.sh <case> [VAR=value ...]`. Each run writes
`results/<time>-<case>/` (SIPp stats CSV every 5 s, RTT CSV, message counts,
errors, final screen, optional RTP capture + report).

| Case | Command | Pass when |
|---|---|---|
| T0 smoke | the `lab/smoke.sh` sequence by hand at `CC=10` | all calls succeed; gauges back to 0 |
| T1 carrier → echo | `./run.sh t1 CC=1000 HOLD=60 SECS=600 CAPTURE=1` | §7.1 criteria |
| T2 hairpin | `./run.sh t2 CC=500 HOLD=60 SECS=600` | §7.1; FreeSBC sees 2× the calls |
| T3 phones | `./run.sh reg-a` then `./run.sh t3 CC=1000 HOLD=60` | §7.1 |
| T4 agents | `./run.sh reg-b` then `./run.sh t4 CC=500 HOLD=60` | §7.1 |
| T5 REGISTER storm | `./run.sh t5 CPS=500 N_REG=1000` | no failures; `freesbc_registration_failure_total` flat; registrations/s recorded |
| T6a admission (shield `load`) | `./run.sh t6-admission` | 20 failed (timeouts); `admission_drops{invite_not_admitted}` +80 (every retransmission counts) |
| T6b rate limit (shield `default`) | `activate.sh <sw> default`, then `./run.sh t6-rate CPS=100 T6_SECS=5` | ≈20 answered/s plus the burst (lab: 149 of 500); `shield_drops{rate}` rises |
| T6c scanner (shield `default`) | `./run.sh t6-scanner` | 5 timeouts; `shield_drops{scanner}` +1 (see §9.3) |
| T6d ringing cap (shield `load`, so the rate limit does not interfere) | `./run.sh reg-a`, `./run.sh t6-ringcap` | exactly 64 answered, 36 × 503 (lab: 64/36) |
| T6e malformed (shield `default`) | `./run.sh t6-garbage COUNT=2000` | no response, no shield counter moves; documents §9.2 |
| T7 soak | T1 and T4 together at 70 % of the knee for 24 h (two S1 shells) | §7.1 throughout; RSS and goroutines flat |
| T8 resilience | see §5.2 | stated per item |

`ramp` runs one case over concurrency steps with a cool-down between them:

```sh
./run.sh ramp CASE=t1 STEPS="100 250 500 1000 1500 2000 3000 4000" HOLD=60 STEP_SECS=300 COOL_SECS=90 CAPTURE=1
```

CPS defaults to CC/HOLD (steady state). For setup-rate limits, hold calls
short and drive CPS instead:

```sh
for c in 20 50 100 200 400 800; do ./run.sh t1 CPS=$c CC=$((c*6)) HOLD=5 SECS=120 LABEL=cps$c; sleep 60; done
```

### 5.1 Order of work

1. **Phase 0** lab rehearsal (§4.5).
2. **Phase 1** functional, per switch: T0 by hand. For FreeSWITCH also run the
   repo's interop test on S3 (`FREESBC_FS_INTEROP=1 ... go test ./internal/edge -run TestFreeSWITCH`),
   which confirms sofia keeps the `fsbc=` token in the stored contact.
3. **Phase 2** capacity ramps T1, T2, T3, T4 × {FreeSWITCH, Asterisk}, plus the
   CPS ramp on T1. Three repetitions of the knee step.
4. **Phase 3** T5 and T6 (each row names its shield profile).
5. **Phase 4** T8 resilience.
6. **Phase 5** T7 soak.

### 5.2 Resilience (T8)

Run T1 at 50 % of the knee and, during the run:

| Event | How | Expected (from `docs/design.md`) |
|---|---|---|
| Shield hot reload | `activate.sh <sw> default` then `load` | no call failure, "config reloaded" logged |
| Switch restart | `docker restart asterisk` | new calls fail until it is back, then recover. In-flight calls lose audio; when SIPp hangs up, the restarted switch answers the BYE 481 (or it times out, 408), and either ends FreeSBC's dialog (`byeEndsDialog`, RFC 3261 §12.2.1.2), so gauges reach 0 by the end of the hold time |
| FreeSBC restart | `systemctl restart freesbc` | in-flight calls lost (state is in memory); phones must re-register before calling again; carrier calls recover at once |
| Private link loss | `ip link set <priv-if> down` for 30 s | upstream timeouts; no panic; recovery after link up |
| Port exhaustion | `SBC_RTP` set to a tiny range in `env`, re-render, run T1 above it | `freesbc_media_port_allocation_failure_total` rises; calls refused cleanly; no leak afterwards |

## 6. Collecting data

Start these before every run and stop them after the cool-down:

```sh
# S2
sudo ./collect.sh results/sbc-$(date +%s).csv 5
# S3
./collect.sh results/switch-$(date +%s).csv 5
# S2, for 30 s inside a step: FreeSBC's own latency
sudo tcpdump -i <pub-if>  -s 0 -B 65536 -w pub.pcap  udp & \
sudo tcpdump -i <priv-if> -s 0 -B 65536 -w priv.pcap udp & sleep 30; sudo pkill tcpdump
./sbc_latency.py pub.pcap priv.pcap --sip-ports 5060,5080,5160
```

- `sbc/collect.sh`: one CSV row per interval with FreeSBC's gauges and
  counters from `/metrics` (calls, dialogs, media sessions, registrations,
  ports in use/total, requests, 4xx/5xx, shield and admission drops, port
  allocation failures, panics, RTP packets, goroutines, heap), process CPU and
  RSS, UDP `RcvbufErrors`/`SndbufErrors`/`NoPorts`, and packets per second on
  each NIC.
- `sbc/sbc_latency.py`: latency **added by FreeSBC alone**, per SIP message
  kind and per RTP packet, by matching the same message on both NICs
  (Call-ID + CSeq for SIP; SSRC + sequence + timestamp for RTP, which FreeSBC
  relays unchanged). Lab sample, 100 concurrent calls, all three namespaces on
  one shared VM (a format example, not a capacity claim):

  ```text
  kind          n      p50      p90      p99    p99.9      max   (ms)
  INVITE       48    0.504    1.167    2.664    2.664    2.664
  200 (INVITE) 48    0.255    0.329    0.421    0.421    0.421
  rtp       92177    0.368    1.239    2.150    2.800    3.796
  ```
- `sipp/rtp_report.sh` (via `CAPTURE=1`): per-stream loss, max delta and
  jitter of the audio FreeSBC returns to S1.
- `switch/collect.sh`: active calls and CPU of each switch.

## 7. Method

### 7.1 Pass criteria per step (proposed; adjust to your SLO)

| Signal | Source | Pass |
|---|---|---|
| Failed calls | SIPp `screen.log` / `stat.csv` | ≤ 0.01 % |
| SIP retransmissions | SIPp `stat.csv` | ≤ 0.1 % of messages |
| Setup time INVITE → 200 | SIPp RTT CSV | p95 recorded; investigate a step-over-step rise > 2× |
| SIP latency added by FreeSBC | `sbc_latency.py` | p99 ≤ 5 ms |
| RTP relay latency added by FreeSBC | `sbc_latency.py` | p99 ≤ 2 ms, p99.9 ≤ 5 ms |
| RTP loss | `rtp_report.sh` | ≤ 0.1 % |
| Kernel drops on S2 | `collect.sh` `udp_rcvbuf_err`, NIC drops | delta = 0 |
| FreeSBC health | `collect.sh` | 0 panics, 0 port allocation failures, CPU ≤ 70 % of cores |
| Drain after cool-down | `/metrics` | calls, dialogs, media sessions, ports in use = 0; goroutines within 10 % of the pre-run baseline |

The latency thresholds are targets (ASSUMPTION), set from the stack's
low-latency goal; nothing in the repo measures them yet.

**Knee** = the highest step that passes every row. Report it per case and per
switch, with the limiting signal.

### 7.2 Hold time and CPS

Concurrency and CPS stress different things: long holds (60 s) load the media
relay (packets per second, sockets, goroutines); short holds (5 s) load
signalling and allocation (transactions, dialog table, port pool churn).
Both ramps are needed. Holds longer than 5 minutes are fine because
`rtp_stream` loops the audio; a call without media would be ended by the RTP
silence watchdog (5 min, constant).

### 7.3 Which host is the bottleneck

Every run, check all three before believing the number:

- S1 CPU > 70 %, S1 `RcvbufErrors` rising, or SIPp's "Call Rate" below the
  target → the generator limited the run; scale S1 or split the load over
  several SIPp processes (different `-p` ports, same IPs).
- S3 CPU > 70 %, the switch answering 503/480, or FreeSWITCH logging
  "sessions-per-second" / "max sessions" → the switch limited it.
- Otherwise it is FreeSBC: look at `collect.sh` (CPU, rcvbuf errors, port pool)
  and `sbc_latency.py`.

To know the switch's own ceiling, run the same SIPp scenario from S2's
private address straight at the switch (FreeSWITCH external profile; Asterisk
needs the `X-FreeSBC-Carrier` header added to a copy of `carrier_uac.xml`).

## 8. Sizing arithmetic (INFERENCE, to be replaced by measurements)

G.711 at 20 ms: 50 packets/s per direction, 200 B per IP packet,
80 kbit/s per direction at L3.

| Per SIPp call | T1 / T3 | T2 / T4 |
|---|---|---|
| FreeSBC calls (dialogs) | 1 | 2 |
| RTP/RTCP port pairs on S2 (public + private) | 2 | 4 |
| UDP sockets on S2 | 4 | 8 |
| Relay goroutines on S2 (5 per media session, `docs/design.md` §3.3) | 5 | 10 |
| Packets/s received by S2 | 100 | 200 |
| Packets/s sent by S2 | 100 | 200 |
| S2 public bandwidth each way | 80 kbit/s | 160 kbit/s |

So 1000 concurrent T1 calls ≈ 100 kpps in + 100 kpps out of S2,
≈ 80 Mbit/s each way on each NIC; in a cloud that is ~36 GB of egress per hour
from S2 and as much from S1. Hard limits in the code:
`SBC_RTP=10000-59999` gives 25000 pairs per side; the binding table holds
20000 registrations, 10 per AoR (`internal/edge/location.go`); one public IP
that is not a carrier source may have 64 calls ringing at once
(`maxEarlyPerSource`).

## 9. Findings from the lab runs

FACT unless marked; each was observed with the harness above.

1. **Socket buffers come from `rmem_default`.** FreeSBC sets no socket buffer
   size (no `SetReadBuffer` in the tree). A burst of 2000 datagrams of 1.3 KB
   into the stock 208 KiB default: 572 delivered, 1428 counted as
   `RcvbufErrors`. §3.2 covers it for the test; production deployments need
   the same sysctl, or FreeSBC could size the buffer of its SIP sockets. (The
   effect of the raised default was not measurable in the lab sandbox.)
2. **Malformed SIP bypasses the shield and is logged in full.** The read
   filter only checks bans; the per-IP rate limit runs after parsing. Each
   unparsable datagram produces an `ERROR "failed to parse"` line from sipgo
   with the raw message (`t6-garbage`: every delivered datagram, 572 of 572,
   became one ERROR line of ~1.3 KB; `shield_drops_total` did not move). That
   is a log-amplification path for an
   anonymous sender and it copies request contents (including any
   `Authorization` header) into the log.
3. **Drops of a banned UDP socket are not counted.** After a scanner verdict
   bans a socket, its later datagrams are discarded in the read filter
   (`BannedFrom` "counts nothing"), so `shield_drops_total{reason="banned"}`
   stays 0 while the scanner keeps sending (`t6-scanner`: scanner +1, banned
   +0 for 5 attempts).
4. **Removing a registration needs the same Call-ID or `Contact: *`.**
   FreeSBC mints the Contact token per (AoR, Call-ID); an `Expires: 0`
   REGISTER with a new Call-ID carries a different token, matches nothing at
   the registrar, and leaves the binding in place until it expires. Phones
   that follow RFC 3261 §10.2.4 reuse their Call-ID; SIPp does not, hence
   `client_unreg.xml` uses `Contact: *`.
5. **Two Info log lines per call, no level flag.** At 500 CPS that is ~1000
   lines/s; journald's default rate limit would drop them above ~160 CPS, so
   the unit sets `LogRateLimitIntervalSec=0`. Log volume is part of the cost
   being measured.
6. **`freesbc_rtp_packets_*` update at call end**, not continuously, so
   during long holds the per-interval RTP rate in `collect.sh` lags; use the
   NIC packet rates for live throughput.

## 10. Files

```text
env.example            every address, port, count and password (copy to env)
render.sh              env -> out/{sbc,switch,sipp}
sbc/                   activate.sh, collect.sh, sbc_latency.py, shield profiles, sysctl, systemd unit
switch/asterisk/       pjsip, dialplan, rtp, minimal module/log config
switch/freeswitch/     profiles, gateway, dialplan, ACL, vars (applied by install-freeswitch.sh)
switch/                docker-compose.yml, Dockerfiles, install scripts, collect.sh
sipp/scenarios/        carrier_uac, uas, client_reg, client_unreg, client_uac, options
sipp/run.sh            test cases and ramps; rtp_report.sh
lab/                   netns.sh (topology), smoke.sh (end-to-end), env.lab.{direct,nat}
```

Numbering (both switches): DIDs `80…` echo, `81…` hairpin to the carrier,
`82<user>` an agent; phones dial `7100` (echo) and `7101` (rings 30 s, then
echo). Users A `10000…` call, users B `20000…` answer.
