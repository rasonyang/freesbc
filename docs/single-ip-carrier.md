# Go-live checklist: single IP, outbound carrier

Follow this in order before the first real call on one host behind a provider's 1:1 NAT, with the switch on the same LAN using FreeSBC as its outbound proxy and a UDP carrier on the far side. Each step is short; the reasoning is in the page it links. The example values are the ones used across these docs:

| | |
|---|---|
| NAT address (`public.ip`) | `203.0.113.7` |
| Host address (`public.bind` = `private.ip`) | `10.77.0.2` |
| Switch (FreeSWITCH) | `10.77.0.3`, SIP port `5080` |
| Carrier | `198.51.100.20:5060` over UDP |
| SIP port | `16060` (a SIP ALG sits on 5060) |

The layout and why the switch is trusted by its source IP: [Single-IP host behind a 1:1 NAT](edge.md#single-ip-host-behind-a-11-nat). Steps 1 and 8 exist because of that trust.

## 1. Before the config: forwards and security group

1. In the provider's NAT, forward `udp/16060` and the whole `rtp` range to `10.77.0.2`, same port numbers ([1:1 NAT checklist](config.md#11-nat-checklist); `freesbc check` prints the list).
2. In the security group, allow `udp/16060` and the `rtp` range only from the carrier's addresses and from the switch host, and open nothing else (admin stays on loopback). The switch is trusted by source IP and the private-plane media ports sit on the forwarded range, so FreeSBC does not filter what else reaches them. Registered clients and WebRTC agents are shut out too: a deployment that adds them must open their transports ([`edge.listen`](config.md#edgelisten)).
3. Ask the carrier for two lists: where its SIP comes from and where its media comes from. They are often different hosts, and the media list is what the `rtp` rule needs.

## 2. Config

```yaml
public:
  ip: 203.0.113.7
  bind: 10.77.0.2
private:
  ip: 10.77.0.2
rtp: 10000-19999
edge:
  switch: [10.77.0.3:5080]
  listen:
    udp: 16060
  carriers:
    carrier-a: 198.51.100.20:5060
```

`edge.listen.udp` is also the switch's outbound-proxy port, and the `edge.carriers` value must equal the host and port the switch puts in the Request-URI ([`edge.carriers`](config.md#edgecarriers)). A literal `edge.carriers` address makes that IP a carrier source on that entry's transport from any source port (the start log lists `carrier_sources=198.51.100.20/32`); [`edge.carrier_sources`](config.md#edgecarrier_sources) adds more IPs or prefixes on any public transport, and only the security group restricts ports.

## 3. Check, then start

```sh
freesbc check --deploy --local-addresses -c /etc/freesbc/freesbc.yaml
systemctl enable --now freesbc
```

`check` prints `single-IP layout` and the two forwards; its "these ports MUST be reachable from clients" means from the carrier and the switch here, and `--deploy --local-addresses` proves the bind addresses are on this host ([install.md](install.md#run-as-a-systemd-service)). The start line `edge proxy listening` carries `shared_socket=true`, and a Warn `udp socket receive buffer below request` means `net.core.rmem_max` is under 8 MiB ([UDP socket buffers](install.md#udp-socket-buffers)).

## 4. Tell the carrier

Give it `203.0.113.7`, port `16060` (not 5060) and the media source and destination range; a carrier that keeps sending to 5060 gets no answer. FreeSBC answers any out-of-dialog OPTIONS from a carrier source itself, whatever its Request-URI: `200 OK`, or `503` with `Retry-After: 30` while [draining](install.md#restart-and-upgrade-on-one-node), which is what the carrier's health check sees. An OPTIONS from any other unregistered source is dropped without an answer.

## 5. ALG check before the first call

Run the two-port capture test in [A SIP ALG rewrites SIP on UDP 5060](troubleshooting.md#a-sip-alg-rewrites-sip-on-udp-5060) now, not after calls fail. It sends to `203.0.113.7:5060` and `203.0.113.7:16060`, so add a temporary `udp/5060` forward to `10.77.0.2`, allow it and 16060 from the test sender, and remove both afterwards. Nothing needs to listen on 5060; the capture on the host is enough.

FreeSBC tolerates an ALG rewriting its own Via and Record-Route (`popOwnVia`, `restoreOwnRecordRoutes`), not a rewritten SDP, which shows as one-way or no audio in step 7.

## 6. Switch: outbound proxy and ACL

On the gateway, `proxy` equals the `edge.carriers` entry and `outbound-proxy` and `register-proxy` are both `10.77.0.2:16060`. Set `register-proxy` even if the trunk does not register: the gateway ping goes to it, and without it the OPTIONS bypasses FreeSBC and the gateway goes DOWN ([examples/switch/freeswitch](../examples/switch/freeswitch/README.md), carrier gateways). Without it the status shows UP for about 32 s until the ping times out (408), so wait past that. The switch's SIP port (`10.77.0.3:5080`) accepts `10.77.0.2` only. Inbound carrier calls go to `edge.switch_carrier_port` (default: the switch port), which must be the unauthenticated carrier port, restricted the same way ([`edge.switch_carrier_port`](config.md#edgeswitch_carrier_port), [Switch-side requirements](edge.md#switch-side-requirements)).

Then ask the carrier for a trace showing Via `203.0.113.7:16060` on the OPTIONS and the Contact on the first INVITE (the ping has no Contact), not an address of the NAT. A capture on the host sits before the NAT and cannot show this.

## 7. First calls

Make a test call of more than a minute and talk both ways. One-way or no audio is audible at once; the log and metric signal comes late. A lost ACK ends the call at about 32 s with `reason=ack_timeout`, so stay past that.

- Info `proxying INVITE to carrier`, and no `invite failed` line on answer.
- At hang-up one `call ended` line with `reason=bye_caller` or `bye_callee`, and `stats=` showing `RTPPacketsRx` and `RTPPacketsTx` above zero on both `A` and `B` ([A call connects, then drops](troubleshooting.md#a-call-connects-then-drops)). An `RTPPacketsRx` of zero on one side is one-way audio.
- `freesbc_rtp_packets_rejected_total{plane}` does not keep rising. A few stray packets can be normal, a count growing with the packet rate is not. The Warn `media packets rejected by latch` names the `plane`, the `latched` and refused `source` and their ranks: media from an address or port the carrier did not signal, or a rewritten SDP.
- Media that stops, or never starts, in one direction ends the call with `reason=rtp_silence` 5 to 6 minutes later: the watchdog fires when either direction is silent ([RTP silence](troubleshooting.md#rtp-silence-reasonrtp_silence)).
- `freesbc_sip_responses_total{class}` counts the responses FreeSBC sends by class only, so a 401/407 challenge looks like a failure; use `freesbc_edge_invite_failures_total` and `freesbc_edge_calls_ended_total{reason}`.

`/metrics` needs an `admin:` section, and that section needs `listen` (keep it on loopback) or `check` fails:

```yaml
admin:
  listen: 127.0.0.1:8080
  password_hash: ${ADMIN_HASH}   # from `freesbc hash-password`
```

With no admin section, read the log (`journalctl -u freesbc`) instead.

## 8. Caps

A compromised or leaked switch is a toll-fraud path FreeSBC bounds but does not price. Ask the carrier for a concurrent-call cap and a spend cap with alerts. On the switch, set per-carrier concurrency, a call duration limit and whole-switch limits ([examples/switch/freeswitch](../examples/switch/freeswitch/README.md), "Policy FreeSBC deliberately does not do"). On FreeSBC, set the hot keys [`shield.max_sessions`](config.md#shield) to the carrier's cap or below (default: half the `rtp` pair count here, as a call takes two pairs) and `shield.invite_rate_limit` to its CPS limit, as `<n>/<s|m|h>` such as `10/s` (global, default off).

## 9. The first failed call

Start with the log, not a capture:

- The call never connected: the `invite failed` line has the carrier name, `code`, `reason_phrase`, `sip_reason` (its `Reason` header, for example `Q.850;cause=17`), `duration` and `source` (`far_end`, `edge` or `timeout`). Counter: `freesbc_edge_invite_failures_total{leg,direction,class}` ([A call never connects](troubleshooting.md#a-call-never-connects)).
- The call connected and dropped, or has no audio: the `call ended` line and its `reason` ([A call connects, then drops](troubleshooting.md#a-call-connects-then-drops)).
- The carrier's INVITE got no answer: a source that is not a carrier source is dropped silently, and the security group may drop it first. FreeSBC logs a Warn `public request dropped by admission` with `public_remote`, a once-a-minute `admission drops: ...` and counts `freesbc_edge_admission_drops_total{reason="invite_not_admitted"}`; add the address to `edge.carrier_sources` ([config.md](config.md#edgecarrier_sources)). A source that keeps sending is banned after `shield.admission_ban` (default `50/5m`, UDP only for a UDP source), so fix the list early.
- `dropped a response that cannot be routed back`, or calls that work from some paths only: usually an ALG (`reason` and `via_sent_by` name the Via it saw), step 5.
