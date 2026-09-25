# Trunk B2BUA plane

The trunk plane is a back-to-back user agent for carrier/PBX interconnect
over UDP/TCP/TLS, with routing, failover, outbound REGISTER and SRTP
(SDES). It is configured with `peers:` and `routes:`. It is enabled
independently of the [edge plane](edge.md) — either or both may run in one
process.

See the [README](../README.md) for the project overview and the [design
doc](design.md) for the implemented behaviour in detail.

## Configuration

Three top-level concepts — `listen`, `peers`, `routes` — plus optional `shield` and `admin` sections with sensible defaults:

```yaml
listen:
  sip: [udp://0.0.0.0:5060]

peers:
  carrier-a:
    address: sip.carrier-a.com:5060
    auth: { username: acct01, password: "${CARRIER_A_PASS}" }
    register: true
    allowed_ips: [203.0.113.0/24]
  internal-pbx:
    address: 10.0.0.10:5060
    allowed_ips: [10.0.0.0/8]

routes:
  - name: outbound
    from: internal-pbx
    match: { to: "^9(\\d+)$" }
    transform: { to: "$1" }
    to: [carrier-a]          # list order = failover order
  - name: inbound
    from: carrier-a
    to: [internal-pbx]
```

`${ENV_VAR}` references are expanded at load time only — secrets are never written back to disk and never appear in error output. See [`sbc.example.yaml`](../sbc.example.yaml) for the full annotated example.

For NAT/VPN deployments (private bind address, public advertised address), the optional `sip:`/`rtp:` sections replace `listen.sip` and split the bind and advertised planes independently:

```yaml
sip:
  bind_ip: 10.77.0.2        # where the SIP listener actually binds
  bind_port: 16060
  advertised_ip: <PUBLIC>   # what Contact/From/REGISTER claim (defaults to bind values)
  advertised_port: 16060
rtp:
  bind_ip: 10.77.0.2        # RTP/RTCP sockets bind here (empty = every interface)
  advertised_ip: <PUBLIC>   # what SDP c=/o= claim
  port_min: 20000           # explicit RTP port range (both or neither); replaces
  port_max: 20100           #   listen.media.port_range, which it cannot be combined with
```

The two sections are mutually independent: SIP can advertise one public address and RTP another. `advertised_ip`/`advertised_port` default to their bind counterparts; when `sip.bind_ip` is set, `rtp.advertised_ip` is required unless `listen.media.public_ip` is a literal address (otherwise SDP would advertise `127.0.0.1`).

## What it does

- **SIP trunk interconnect** — UDP, TCP and TLS transports (real certificate
  or a self-signed fallback, optional mTLS), IP-authenticated peers, and
  registration-based trunks via outbound REGISTER with digest auth
- **B2BUA with topology hiding** — two independent call legs with their own
  Call-ID, From-tag and Via, and SDP built from scratch per leg (the SBC's own `o=`, address and port; only codec lines and direction carried over)
- **Routing engine** — regex matching, number transformation, ordered
  failover with passive per-endpoint cooldown, and DNS SRV resolution
  (RFC 3263 priority/weight ordering, cached)
- **RTP relay + SRTP (SDES)** — media anchoring, `a=crypto` negotiation with
  a per-peer `disabled`/`optional`/`required` policy on the **trunk plane**
  (the edge plane never offers or reads `a=crypto`: a SIP phone there gets
  plain RTP, and only browser legs get DTLS-SRTP), SRTP↔RTP interworking in
  both directions, NAT traversal via hardened first-packet latching;
  **no transcoding** (left to the softswitch behind)
- **Carrier interop baseline** — OPTIONS answering and session-timer
  negotiation (RFC 4028), including the 422/Min-SE exchange on both legs; no
  timer tears a call down on session expiry

## Roadmap (trunk plane)

Items not yet implemented.

- **100rel/PRACK** — an INVITE carrying `Require: 100rel` is answered `420 Bad Extension` today, and the trunk plane neither advertises 100rel nor handles PRACK
- **Mid-call re-INVITE on the trunk plane** — hold/resume and codec renegotiation are answered `488`; only session-timer refresh re-INVITEs are handled (the edge proxy does re-anchor re-INVITEs)
- **Inbound digest challenge** — the SBC answers challenges but never issues one; trunk peers are authenticated by source IP, plus TLS/mTLS where configured
- **Active peer qualification** — outbound OPTIONS keepalives; peer liveness is passive cooldown today
- **`listen.media.public_ip: auto`** — STUN-detected public address; a literal address is required for now
- **Configurable TCP/TLS listener limits and TLS certificate hot rotation** — the connection cap and idle timeout are compiled in, and certificate changes need a restart
