# Mirroring SIP signaling to HOMER

FreeSBC can ship a copy of every SIP message the edge receives or sends to a [HOMER](https://sipcapture.org) collector over HEPv3. FreeSBC is a proxy and the Call-ID passes through it, so the client, switch and carrier legs of one call land in a single HOMER call flow. The mirror is off unless a `hep:` section exists; every key is restart-only (see [`config.md`](config.md#hep)).

## Configuration

```yaml
hep:
  address: 10.77.0.50:9060     # literal IP:port of the collector
  transport: udp               # udp | tcp | tls
  tls:                         # only with transport: tls
    ca: /etc/freesbc/homer-ca.pem
    cert: /etc/freesbc/hep-client.pem   # optional, for HOMER mutual_tls
    key: /etc/freesbc/hep-client.key
  capture_id: 2001
  node_name: freesbc-edge1
  redact_auth: true            # default true
```

There is no password: HOMER 11 ignores the HEP auth key.

## HOMER 11 side

| What | Value |
|---|---|
| HEP over UDP and TCP | port 9060 |
| HEP over TLS | port 9061 |
| TLS settings | the `HOMER_INGEST_TLS_*` environment of the ingest service (certificate and key it serves; `mutual_tls` makes it require a client certificate, the `hep.tls.cert` and `key` pair here) |

For `transport: tls` FreeSBC verifies the collector's certificate against the host of `address`, a literal IP, so the certificate needs that IP as a subject alternative name. `hep.tls.ca` replaces the system roots. Verification cannot be turned off. A `hep.tls` block with `transport` other than `tls` is a validation error.

HOMER never replies, so FreeSBC never reads from the collector. Over `tcp` and `tls` the sender reconnects with backoff; over `udp` a down collector simply loses packets. The sender is bounded (a 4096-packet queue and one writer goroutine): a slow or dead collector can cost mirrored copies, never calls.

## What is mirrored

Every SIP message the edge receives or sends, on every socket:

- Public listeners: `udp`, `tcp`, `tls`, `ws` and `wss`.
- The private socket `private.ip:5060`, so the switch legs are in the same flow.
- Connections FreeSBC dials to tcp and tls carriers.

Outbound copies include sipgo's retransmissions, locally generated replies and the BYE or CANCEL the edge generates itself.

Not mirrored:

- Anything the pre-parse read filter drops: oversized reads, reads from shield-banned sources, rate-limited reads, and private-socket reads from a non-switch address. A flood the shield absorbs therefore does not reach the collector. The datagram that earns a ban is mirrored, the ones after it are not.
- A message with no Call-ID (HOMER cannot place it).
- On tcp and tls, a message split over two reads of the connection (each complete message in a read is mirrored; WS and WSS frames and UDP datagrams are always whole messages).
- RTP and RTCP. Media is not part of this feature: FreeSBC sends SIP only (HEP type 1) and never HEP type 5. To get RTCP quality reports into HOMER, report them from the switch, which receives the relayed RTCP in plain form; see [RTCP and call quality in HOMER](edge.md#rtcp-and-call-quality-in-homer).

### HEP fields

| Chunk | Value |
|---|---|
| `0x02` IP protocol | 17 for UDP, 6 for tcp, tls, ws and wss |
| `0x03`/`0x04`, `0x05`/`0x06`, `0x07`, `0x08` | The two ends of the socket that actually carried the message. The local end is reported as `public.ip` when the socket is bound to `public.bind`, with a listener's `edge.advertise` port in place of its bound one (they differ only behind NAT), so the ladder matches the addresses in the SIP headers |
| `0x0b` payload type | 1 (SIP) |
| `0x0c` capture agent ID | `hep.capture_id` |
| `0x11` correlation ID | the SIP Call-ID (long or compact form) |
| `0x13` node name | `hep.node_name` |

`redact_auth` (default `true`) replaces the value of `Authorization` and `Proxy-Authorization` with `REDACTED` in the mirrored copy only. The message FreeSBC forwards is unchanged. The per-process `X-FreeSBC-Arrival` marker is stamped after the copy is taken, so it never leaves the process.

### Metrics

Exported on `/metrics` only while `hep:` is set:

- `freesbc_hep_packets_sent_total`: messages written to the collector.
- `freesbc_hep_packets_dropped_total`: copies not sent because the queue was full or closed.
- `freesbc_hep_errors_total{kind="write"|"encode"}`: packets lost to a dial or write failure, and packets the encoder refused (oversize).

## Security notes

- **HOMER 11 does not authenticate HEP senders.** Anyone who can reach the ingest port can inject calls into your captures. Put the collector on the private network, or use `transport: tls` with mutual TLS (`hep.tls.cert` and `key`, `mutual_tls` on the HOMER side).
- **The mirror carries what topology hiding removes.** Public legs hide the switch from clients and carriers, but the copy of each leg is the message as it crossed that socket: switch addresses, the switch's Via and Contact, `fsbc=` tokens, and the private-side Record-Route all appear in HOMER. Treat the collector and its users as part of the trusted core.
- **Without `redact_auth`, REGISTER digests and nonces are shipped.** A digest response captured from HOMER can be attacked offline. Leave `redact_auth` on unless you need the credentials for debugging.
- The mirror reveals call metadata (numbers, timing, source addresses). Apply the same retention and access rules you apply to the switch's own call records.

## Implementation notes

The mirror copies inbound messages in the read filter and outbound ones through sipgo v1.4.3's only write hook, the process-wide `sip.SIPDebugTracer`, which requires `sip.SIPDebug = true`. That flag also turns on a few extra Debug-level log lines in sipgo's WebSocket transport; they appear only at the Debug log level. Details and the reasoning are in [`design.md`](design.md) §7.1b.
