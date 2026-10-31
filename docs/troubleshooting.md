# Troubleshooting

## A call connects, then drops

Start from the `call ended` line (Info, one per confirmed call) and read two fields, `reason` and `terminated_by`:

```
call ended sip_call_id=... reason=ack_timeout terminated_by=proxy duration=32.1s webrtc=false carrier=false stats=...
```

`reason` is also the label of `freesbc_edge_calls_ended_total{reason}`, so a dashboard shows the spread without reading logs. `duration` runs from the 2xx that confirmed the call. The labels are a fixed set, all exported from zero:

| `reason` | `terminated_by` | Meaning | Go to |
|---|---|---|---|
| `ack_timeout` | `callee` or `proxy` | The ACK to the initial 2xx never arrived | [Lost ACK](#lost-ack-reasonack_timeout) |
| `rtp_silence` | `proxy` | No genuine RTP or RTCP from one side for 5 minutes | [RTP silence](#rtp-silence-reasonrtp_silence) |
| `bye_caller`, `bye_callee` | `caller`, `callee` | A BYE from that side was accepted: a hangup, or that end's own timer | [A BYE you did not expect](#a-bye-you-did-not-expect-reasonbye_caller-or-bye_callee) |
| `bye_unanswered` | `proxy` | A BYE was relayed, the far side never answered it, FreeSBC ended the dialog and re-sent the BYE | [A BYE you did not expect](#a-bye-you-did-not-expect-reasonbye_caller-or-bye_callee) |
| `dtls_failure` | `proxy` | A WebRTC leg failed (ICE, DTLS or fingerprint) | `webrtc=true` on the line; see the `webrtc leg failed` WARN and `freesbc_webrtc_dtls_failure_total` |
| `reinvite_refused`, `answer_unusable`, `answer_timeout` | `proxy` | The answer to a re-INVITE, UPDATE or delayed offer could not be anchored, or never came | [Reliable provisionals, UPDATE and delayed offers](edge.md#reliable-provisionals-update-and-delayed-offers) |
| `media_fault` | `proxy` | The media session closed for another reason (a relay goroutine panicked) | A bug: keep the log around the line and report it |
| `shutdown` | `proxy` | The process was stopping | Expected |

A call that never connected has no `call ended` line; `freesbc_edge_invite_rejects_total{reason}` counts the INVITEs FreeSBC refused itself.

### Lost ACK (`reason=ack_timeout`)

**Fingerprint.** Setup works, audio may flow, then the call ends about 32 s after the 2xx (64*T1, `duration=32.1s` or close), with the 200 OK retransmitted on the wire meanwhile. FreeSBC logs this at WARN for the first miss on each plane and at most once a minute after that:

```
2xx ACK never arrived; the far end is not reaching the advertised Contact/Record-Route address (NAT or firewall?) plane=public advertised=sip:203.0.113.7:5060 sip_call_id=... suppressed=0 interval=1m0s
```

`freesbc_edge_ack_missed_total{plane}` counts every miss, and `GET /api/health` raises `ack_missed:public` or `ack_missed:private` at 3 misses within 10 minutes. `terminated_by=callee` means the callee's BYE came first (it gave up on the ACK); `terminated_by=proxy` means FreeSBC's own 32 s timer fired and BYEd both ends. Only the ACK of an initial INVITE's 2xx is watched.

**Why it looks asymmetric.** Responses follow Via and `rport`, so the 18x and 2xx reach the endpoint even when nothing is forwarded to FreeSBC. The ACK and every other in-dialog request (BYE, re-INVITE, UPDATE) follow the Contact and Record-Route FreeSBC advertised. If the sender cannot reach that address, setup works and the dialog dies at 32 s.

**Which side.** `plane` says whose ACK is missing, and `advertised` is the address that must be reachable from there:

- `plane=public`: the endpoint (or carrier) did not reach the public listener at `advertised`. Check in this order:
  1. Behind 1:1 NAT (`public.bind` differs from `public.ip`), the router forwards every `edge.listen` port (UDP for `udp`; TCP for `tcp`, `tls`, `ws`, `wss`) and the whole `rtp` range to `public.bind`, with the same port numbers (a signaling port the router translates is declared in `edge.advertise`; the `rtp` range never is). `freesbc check` prints the list; see the [1:1 NAT checklist](config.md#11-nat-checklist). A port that is not forwarded is the usual cause, and it hides well: registration and the INVITE can still work through a pinhole the client opened.
  2. The sender can reach `advertised` on the transport it signalled with. A firewall that drops that port, a UDP/TCP/TLS mismatch, or a SIP ALG that rewrites or drops the ACK all look the same; switch the ALG off on the router in front of either end.
  3. The advertised address is the one you meant. The `edge proxy listening` line shows `advertised=[...]` and `bind=[...]` side by side, and `GET /api/status` gives each listener's `advertised` address in `listener_info`.
- `plane=private`: the switch's ACK did not reach `private.ip:5060`. Check that the switch sends in-dialog requests to the address FreeSBC advertised, and the private socket's ingress rule (a datagram that arrives on the wrong interface is dropped silently by the kernel; see [Known limitations](edge.md#known-limitations)).

To confirm on the wire, capture on the FreeSBC host (`tcpdump -ni any udp port 5060`). A 200 OK repeated at 0.5, 1, 2, 4 s with no ACK from that source is this failure.

### RTP silence (`reason=rtp_silence`)

**Fingerprint.** `reason=rtp_silence terminated_by=proxy`, with a `duration` that runs 5 to 6 minutes past the moment the audio stopped (the watchdog polls every quarter of its timeout). FreeSBC BYEs both ends.

**What the watchdog counts.** The timeout is the constant `rtpSilenceTimeout` (5 minutes; it is not a config key, see [config.md](config.md)). Each direction has its own last-received time, and the call ends when the older of the two is past the timeout, so one side that stops sending is enough even while the other still talks. Only a packet the first-packet latch accepted refreshes it: a packet from a source that does not match the latch, and an SRTP or SRTCP packet that fails authentication, never do. An accepted RTCP packet refreshes it exactly like RTP (a receive-only side that sends RTCP receiver reports stays alive, as on hold), though RTCP packets are not counted in the RTP packet/byte metrics. A held endpoint that sends neither RTP nor RTCP for the timeout is reclaimed.

The usual causes:

- **One-way media from the start.** Media never latched because the endpoint sends RTP to an address other than the one FreeSBC advertised in the SDP (an RTP forward missing behind 1:1 NAT, a firewall, a NAT that rewrites the source). Read `stats` in the `call ended` line: a direction with no packets never arrived. The `rtp` range must be reachable on `public.bind` for the endpoint and on `private.ip` for the switch.
- **Hold with no RTP.** An endpoint that holds with `a=inactive` and sends nothing, or a switch that holds without music, leaves a silent direction. After 5 minutes the call is torn down. Keep packets flowing during hold (music on hold on the switch, or an endpoint that sends comfort noise).
- **Silence suppression with no comfort noise.** Disable it, or send CN.
- **A NAT mapping for the media pinhole that expired.** Raise the NAT's UDP timeout.
- **SDES-SRTP keys that do not match.** Packets that fail authentication are dropped and do not count, so the call goes quiet and ends here. Look for the `SDES keys not applied` WARN and see [SDES-SRTP on public legs](edge.md#sdes-srtp-on-public-legs).

### A BYE you did not expect (`reason=bye_caller` or `bye_callee`)

FreeSBC relays a BYE; it originates one only for the reasons above. A `bye_*` ending that is not a person hanging up means an endpoint or the switch sent a BYE, most often because a timer on that side ran out. `terminated_by` is the side whose BYE FreeSBC accepted first.

- **Session timers (RFC 4028).** A side that negotiated a session interval must refresh it with a re-INVITE or UPDATE, and BYEs when the refresh fails. FreeSBC forwards both in either direction, so a call that ends at the negotiated interval (look at `duration`: 1800 s, or 90 to 120 s when someone configured it short) with a `bye_*` means the refresh did not complete. A refresh is an in-dialog request, so it fails for the reasons a lost ACK does: the advertised address is unreachable, or the client's NAT mapping expired. Look for a re-INVITE or UPDATE just before the BYE in a capture.
- **Switch limits.** The switch can hang up on its own: a maximum call duration, or a media timeout on the channel (see the checks below). These are independent of FreeSBC's 5-minute watchdog.
- **`bye_unanswered`.** FreeSBC relayed a BYE, the far side never replied (typically a client that vanished), and FreeSBC ended the dialog itself.

#### Checks on the switch

FreeSWITCH (`sofia global siptrace on` shows the traffic on the profile that faces FreeSBC):

- Session timers: the sofia profile's `enable-timer` and `minimum-session-expires`, and per channel `sip_enable_timer` and `sip_session_timeout`. As a test, set `enable-timer` to false; if the drop goes away, a refresh is not completing.
- Media timeouts: the profile's `rtp-timeout-sec` and `rtp-hold-timeout-sec`.
- NAT overrides: the profile must not replace the Contact and Record-Route FreeSBC gave it (for example `ext-sip-ip`); in-dialog requests must go back to FreeSBC at `private.ip:5060`.

Asterisk (`pjsip set logger on`, or `sip set debug on` for chan_sip):

- Session timers: on the PJSIP endpoint, `timers` (`yes`, `no`, `always`, `forced`), `timers_sess_expires` and `timers_min_se`; in chan_sip, `session-timers`, `session-expires`, `session-minse` and `session-refresher`. As a test set `timers=no`.
- Media timeouts: `rtp_timeout` and `rtp_timeout_hold` on the PJSIP endpoint (chan_sip: `rtptimeout`, `rtpholdtimeout`); a channel with no media for that long gets a BYE.
- `external_media_address` and `external_signaling_address` on the transport must not be set to an address that is not FreeSBC's: media and signaling are anchored on FreeSBC either way.

## SIP datagrams lost under bursts

Symptom: calls or REGISTERs fail at high rates with no FreeSBC log line, and `nstat -az UdpRcvbufErrors` (or `RcvbufErrors` in `/proc/net/snmp`) keeps rising. Check the startup log for `udp socket receive buffer below request`: the kernel capped the 8 MiB request FreeSBC makes on its UDP SIP sockets. Raise `net.core.rmem_max` to at least 8 MiB (and `net.core.wmem_max` to at least 1 MiB) and restart FreeSBC; see [UDP socket buffers](edge.md#udp-socket-buffers). `freesbc_udp_socket_drops_total{socket="public|private"}` on `/metrics` (Linux) names which SIP socket drops, and `freesbc_udp_socket_rx_queue_bytes{socket}` shows its queue at the scrape. Drops with the full buffer granted, at carrier-in rates above about 3500 CPS on 4 vCPU, are GC mark phases keeping the socket's reader waiting for a CPU ([performance.md](performance.md), #235); in a local test more CPUs, or a higher `GOGC` at a large cost in memory, moved the onset up.

### Order of checks

1. `reason` and `terminated_by` on the `call ended` line, then the matching section.
2. `GET /api/health` for `ack_missed:*`, and `freesbc_edge_ack_missed_total{plane}`.
3. For `ack_timeout` and `rtp_silence`, verify the forwards (`freesbc check` output) and the advertised address before touching any timer.
4. For a `bye_*` at a round number of seconds, look for a session timer or media timeout on the switch.
