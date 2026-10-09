# Switch-side examples

Minimal, copy-pasteable configurations for the switch behind FreeSBC. They are illustrations: the list in [`docs/edge.md`](../../docs/edge.md#switch-side-requirements) ("Switch-side requirements") is normative, and if a file here disagrees with it, `docs/edge.md` wins. FreeSBC does not ship or manage switch configuration (the [scope rule](../../README.md#not-in-scope)); these are examples, not a feature.

| Switch | Files | Verified |
|---|---|---|
| [FreeSWITCH](freeswitch/README.md) | `freesbc-vars.xml`, two sofia profiles, two gateways, two dialplan files | 1.10.12, stock `vanilla` config, in Docker by [`freeswitch/test/run.sh`](freeswitch/test/run.sh) |
| [Asterisk](asterisk/README.md) | `pjsip.conf`, `extensions.conf`, `acl.conf` | 22.10.1, stock modules, in Docker by [`asterisk/test/run.sh`](asterisk/test/run.sh) |

Each README lists what was exercised and what was not.

## Reference topology

The addresses of [`freesbc.example.yaml`](../../freesbc.example.yaml), used by both examples.

| | Address | Role |
|---|---|---|
| FreeSBC public side | `203.0.113.7` | `public.ip` |
| FreeSBC private side | `10.77.0.2:5060/udp` | `private.ip`, the only socket the switch talks to |
| Switch, client port | `10.77.0.10:5060` | `edge.switch`: phones and browsers (authenticated) |
| Switch, carrier port | `10.77.0.10:5080` | `edge.switch_carrier_port`: carriers and carrier gateways |

```yaml
edge:
  switch: [10.77.0.10:5060]
  switch_carrier_port: 5080
  carriers:
    carrier-a: 203.0.113.60:5060   # must equal the switch's carrier host[:port] exactly
    carrier-b: 203.0.113.60:5061
```

The carrier names and addresses differ per example (see each README); the rule is the same: the `edge.carriers` entry equals the host[:port] the switch puts in the Request-URI.

## Notes common to both switches

- **UDP only toward FreeSBC.** The private leg is the fixed UDP socket `private.ip:5060`. FreeSBC converts TCP, TLS, WS and WSS from the outside.
- **Keep the `fsbc=` Contact parameter.** FreeSBC rewrites a client's Contact to carry it and routes calls to the client by it. Do not enable anything on the switch that rewrites or strips a registered Contact.
- **The registrar must return an expiry** in its 200 OK. FreeSBC keeps the binding for that value.
- **No NAT handling on the switch.** FreeSBC anchors all media and rewrites Contact and SDP to `private.ip`, so the switch sees a flat LAN: no NAT ACLs, `rport` forcing, STUN or external addresses.
- **Plain RTP/AVP on the switch leg**, also for WebRTC clients and SDES-SRTP carriers. Leave DTLS and SRTP off on the switch.
- **Codecs.** FreeSBC does not transcode: both ends need a common codec, and an answer that renumbers a payload type is refused. The examples allow PCMU, PCMA, Opus and `telephone-event`.
- **Address-based brute-force protection on the switch (fail2ban, IP bans) sees every client request as coming from `private.ip`** and would ban FreeSBC itself. Leave source banning to FreeSBC's shield; use digest authentication and strong passwords on the switch.
- **A switch pool needs a shared registration database** and identical directory and dialplan on every node (`docs/edge.md`, "Multiple switches"). A carrier registration stays on the node that made it. Not exercised in either example.
- **Policy FreeSBC deliberately does not do** stays on the switch: per-carrier and per-user concurrent-call limits, maximum call duration, toll-fraud protection (authentication, destination allowlists) and CDR. Each README shows the switch-side syntax.
