# FreeSWITCH as the switch in a load run

Replaces the SIPp `switch_uas.xml` with a real FreeSWITCH, so the call load
includes the switch's own cost and answer latency. It matters because a real
switch answers slower than the SIPp UAS, and that interacts with FreeSBC's cap
of 64 unanswered calls per public source IP. Scenarios supported: `register`,
`call` and `webrtc` (client to switch). The carrier scenarios need the SIPp
switch.

| File | Install as |
|---|---|
| `sip_profiles/perf.xml` | `<conf>/sip_profiles/perf.xml`: a profile on `10.77.0.10:5090` that accepts any REGISTER and call without digest (lab only, and only from the `freesbc_priv` ACL: step 1), context `perfload` |
| `dialplan/perfload.xml` | `<conf>/dialplan/perfload.xml`: `2000` answers and runs `echo`, `2001` answers and plays a tone, anything else is 404 |
| `../configs/perf-freeswitch.yaml` | the FreeSBC config for this mode (`edge.switch: [10.77.0.10:5090]`) |

Use a dedicated test FreeSWITCH. The profile gives up digest authentication on
purpose, because SIPp's `register.xml` and `uac_call.xml` do not answer a
challenge. That is the opposite of the production layout in
[`examples/switch/freeswitch/`](../../../examples/switch/freeswitch/README.md)
(`auth-calls=true`, no ACL for `private.ip`; see "Never identify or trust a
request by FreeSBC's IP on the client port" in
[`docs/edge.md`](../../../docs/edge.md#switch-side-requirements)). The
containment is: its own port (5090, away from the stock 5060 and 5080), a
context with no bridge and no gateway (nothing can reach a carrier), and a
firewall that admits `10.77.0.10:5090/udp` and the FreeSWITCH RTP range only
from the FreeSBC private IP. If you also keep the carrier profile
(`external`, port 5080, `auth-calls=false`), it stays restricted to
`private.ip` as in the examples.

## Setup

1. Copy the two XML files into the FreeSWITCH conf directory (paths above) and
   replace `10.77.0.10` in `perf.xml` with the host's private IP, the one in
   `edge.switch`. Restart FreeSWITCH (or `fs_cli -x 'reload mod_sofia'` and
   `reloadxml`). Check: `fs_cli -x 'sofia status profile perf'` shows
   `udp-ip 10.77.0.10:5090`.
   The profile applies the ACL `freesbc_priv` to calls and registrations, so
   define it in `autoload_configs/acl.conf.xml` inside `<network-lists>`, with
   the FreeSBC private IP (`private.ip`) as the only allowed address, before
   the reload:
   `<list name="freesbc_priv" default="deny"><node type="allow" cidr="<private.ip>/32"/></list>`.
   Without the list FreeSWITCH accepts nothing on this profile. The three-host
   kit writes it for you (`test/perf/hosts/provision.sh switch`).
2. Raise FreeSWITCH's own session limits in `autoload_configs/switch.conf.xml`
   (they would otherwise cap the run, and appear as 503s that are not FreeSBC's):
   `sessions-per-second` (stock 30) to above the target CPS, and `max-sessions`
   (stock 1000) to above rate x hold. `rtp-start-port`/`rtp-end-port` (stock
   16384-32768, 8192 calls) must cover the concurrent calls too. Keep
   `loglevel` at `warning` or `err` for a load run (`console` and file), and
   leave `sip-trace` and `sofia loglevel all` off.
3. Host prep on the FreeSWITCH host: `net.core.rmem_max` and `wmem_max` large
   enough for its SIP socket (at least 4 MiB and 1 MiB), and `ulimit -n`
   (systemd `LimitNOFILE`) in the hundreds of thousands.
4. FreeSBC host: `configs/perf-freeswitch.yaml` with the `ADDRESS` lines
   changed; `edge.switch` must list the FreeSWITCH IP and the profile's port.
   The private socket only accepts datagrams from the IPs in `edge.switch`.
5. Smoke test before loading: from the generator,
   `test/perf/run.sh -r 1 -t 5 -H 5 -u 5 call` with `SWITCH=freeswitch`, then
   `fs_cli -x 'sofia status profile perf reg'` (five registrations) and no
   failures in the summary.

## How load users register

The shipped approach is **blind registration**: `accept-blind-reg` makes the
`perf` profile answer 200 to a REGISTER for any user, so no directory entry
exists for the `u000001` ... `uNNNNNN` users that `run.sh -u N` generates, and
nothing needs creating. Each REGISTER is forwarded by FreeSBC verbatim, the
200 comes back, and FreeSBC records the live binding that admits the INVITE.
Calls land in context `perfload` with no challenge.

To load the digest round trip instead (the production setup), do both of
these, none of which is shipped here: create a directory user per generated
name (a script that writes `<conf>/directory/default/uNNNNNN.xml` with one
shared password), switch the profile to the production `internal.xml`
settings, and add an `[authentication]` branch (401, then REGISTER and INVITE
with `Authorization`) to `sipp/register.xml` and `sipp/uac_call.xml`, run with
`-au`/`-ap`. Without that, `register.xml` fails on the 401.

## Gotchas

| Symptom | Cause |
|---|---|
| About 6 CPS from one generator, SIPp retransmission timeouts | `shield.rate_limit` default `20/s per_ip`. `perf-freeswitch.yaml` raises it to 1000000/s. |
| INVITEs vanish with no response | Admission: the source IP:port has no live registration (`freesbc_edge_admission_drops_total{reason="invite_not_admitted"}`). `call` pre-registers from `LOADGEN_IP:GEN_PORT`; do not list the generator in `carrier_sources` unless you mean the carrier path. |
| 503 on a share of calls at a high rate | At most 64 unanswered INVITEs per public source IP (`invite_rejects_total{reason="early_cap"}`). With an answer latency of L seconds, one generator IP cannot start more than about 64/L calls per second. Lower `-r` or add generator IPs (each pre-registers from its own IP:port). |
| 503 `session_cap`, or `freesbc_media_port_allocation_failure_total` | `shield.max_sessions` and the `rtp` range hold (max-min+1)/2 calls (5000 for `20000-29999`). Size them above rate x hold, with room for the 32 s teardown tail. |
| 503 from FreeSWITCH (not FreeSBC) | `max-sessions` or `sessions-per-second` in `switch.conf.xml`. |
| FreeSBC drops all switch traffic | The FreeSWITCH source IP is not in `edge.switch`, or FreeSWITCH replies from another address than the one listed. |
| `/metrics` scrape empty | `admin.listen` is loopback; run the sampler on the FreeSBC host (`SBC_EXEC="ssh sbc"`) or tunnel it. |

Run the load with `SWITCH=freeswitch`: `run.sh` then starts no SIPp UAS and
`SWITCH_IP` is only informational. The commands for three hosts are in
[`../README.md`](../README.md#load-through-a-real-freeswitch).
