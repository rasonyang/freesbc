# FreeSBC Deployment Security Baseline (G-1 / G-2)

- Generated: 2026-08-31 | Task cards: `docs/tasks.md` G-1 (F-07 mitigation), G-2 (F-14 mitigation)
- Scope: P0 deployment gate document. **Every clause below must be satisfied before deploying on the public internet (or any untrusted network).**
- Status: documentation gate. G-2 is promoted to a code gate once T-26 lands (non-loopback admin denied by default + bcrypt cost ≥10 enforced); the code-level fix for G-1 (inbound digest challenge / mTLS) is on hold pending a product decision (see "Later consideration" in `docs/tasks.md`).
- Background: `docs/SECURITY-AUDIT-20260826.md` F-07 (SIP identity = source IP, no challenge) and F-14 (the high-severity chain opened by an exposed plaintext admin Basic auth).

---

## G-1 Public Internet Exposure Policy (Signaling Plane)

### Trust Model (Required Reading)

FreeSBC identifies the peer behind an inbound SIP request **solely by the transport-layer source IP** (`peers.<name>.allowed_ips`; both the T-01 pre-filter and shield use it). That source IP is never challenged:

- **TCP/TLS**: blind spoofing is impractical (three-way handshake plus sequence numbers), so source-IP confidence approaches path trust.
- **UDP**: a single datagram can carry any forged source IP. **A forged source IP that lands inside a peer's `allowed_ips` inherits that peer's trust in full**, including:
  - placing real outbound calls (toll fraud, through the outbound targets in `routes`);
  - complete shield exemption (configured peers bypass rate limits and bans).

Neither T-01's ingress pre-filter nor T-02's "single-packet UDP verdicts produce in-memory bans only" **changes this boundary**: the former drops non-peer bytes before parsing, but a forged source inside `allowed_ips` is by definition a "legitimate peer"; the latter only prevents forged packets from pushing a third-party IP into the kernel blackhole, and trust on the service side is unchanged.

### Permitted Exposure Modes (Any One of Three)

1. **Expose only tcp/tls listeners to the internet** (recommended). `listen.sip` must contain no `udp://` entry bound to a publicly reachable address; UDP is permitted only on internal or otherwise controlled segments (for example a direct link to a PBX).
   - Note: inbound tls currently uses a self-signed certificate (real certificates become configurable in T-17); tightening peer-side verification is likewise part of T-17's configuration surface.
2. **Upstream ACL allowlist + uRPF**: if the deployment mandates public UDP, two gates further upstream (firewall or router) are required — (1) permit inbound UDP only from each peer's actual source prefixes (ACL allowlist); (2) enable strict-mode uRPF (RFC 3704) so spoofed sources (packets whose source address does not route back out the ingress interface) are dropped before they reach the SBC.
3. **Inbound digest challenge**: a code-level fix (asymmetric trust establishment), currently on hold — it needs a product decision (schema and challenge flow definition); see "Later consideration", F-07 code-level, in `docs/tasks.md`.

### Anti-Patterns (Prohibited)

- Exposing `udp://0.0.0.0:5060` on the internet while `allowed_ips` covers a broad prefix: any attacker able to forge a source IP from that prefix can place fraudulent calls through the outbound routes.
- Substituting narrow `allowed_ips` for upstream protection: narrowing them **is mandatory** (it is also checked by F-16/T-11), but it only shrinks the set of spoofing targets; it does not remove the ability to spoof.

### Deployment Checklist (G-1)

- [ ] Publicly reachable `listen.sip` entries are `tcp://` / `tls://` only
- [ ] If public UDP is unavoidable: upstream ACL allowlist and strict uRPF are both configured and verified
- [ ] Every peer's `allowed_ips` is narrowed to its actual source prefixes (not 0.0.0.0/0)
- [ ] Operations and security owners have confirmed in writing that they understand the "source-IP spoofing over UDP = full peer trust" boundary

---

## G-2 Admin Deployment Baseline (Management Plane)

### Baseline: Bind Loopback Only

`admin.listen` **must bind loopback only** (`127.0.0.1:8080` or `[::1]:8080`, the default shape in the sample config `sbc.example.yaml`). Rationale (F-14, High):

- admin has no TLS; Basic Auth credentials and responses travel in plaintext and can be sniffed;
- once authenticated, `/api/config/raw` exposes every SIP credential in plaintext (peer passwords) — one capture yields a complete toll-fraud chain;
- until T-09 lands, the auth path has no failure rate limit, and even a request without an Authorization header runs a full bcrypt (CPU amplification in the same process as SIP).

Manage locally over an SSH tunnel or from a browser on the host:

```sh
ssh -L 8080:127.0.0.1:8080 <sbc-host>
# open http://127.0.0.1:8080/ in a browser
```

### Non-Loopback Deployment (Interim Gate Until T-26)

When network access is genuinely required (an operations LAN segment, for example), **all of the following must hold** until T-26 turns "deny non-loopback by default" into a code-enforced rule:

- [ ] Bind only to an address reachable from the operations/management segment, **never publicly reachable**
- [ ] Front it with a TLS reverse proxy (nginx, caddy, etc.): terminate TLS at the proxy and let the proxy connect back to loopback only; if you bind a non-loopback address directly, restrict source IPs to the management segment with a firewall
- [ ] Acknowledge the risk: sniffed plaintext Basic auth → every SIP credential in plaintext via `/api/config/raw` (a complete toll-fraud chain); no failure rate limit before T-09 (any reachable source can keep bcrypt burning CPU)
- [ ] Use a strong admin password (the bcrypt hash is no substitute for password strength; T-26 will enforce cost ≥10)

Once T-26 lands: a non-loopback bind fails startup unless `admin.allow_remote` explicitly permits it — the code gate then replaces this checklist (though the proxy and firewall clauses remain recommended as defense in depth).

---

## Mapping to Code Fixes (Progress Anchors)

| Document clause | Corresponding code fix | Status (2026-08-31) |
|---|---|---|
| G-1 tcp/tls only on the internet | T-05 TCP/TLS connection cap + timeouts | ✅ Landed |
| G-1 upstream ACL + uRPF | (deployment item, no code) | This document |
| G-1 inbound digest challenge | F-07 code-level | On hold, pending product decision |
| G-1 resource protection inside the spoofing boundary | T-01 pre-filter / T-06 concurrency quota / T-02 in-memory-only UDP ban | ✅ Landed |
| G-2 loopback only | T-26 (explicit `admin.allow_remote` + bcrypt cost ≥10) | ⏳ P1 queue |
| G-2 failure rate limit / skip bcrypt for headerless requests | T-09 | ⏳ P1 queue |
| G-2 TLS reverse proxy | (deployment item) | This document |
