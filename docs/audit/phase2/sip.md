# Phase 2 — internal/sip (excluding internal/sip/sdp)

Scope: `internal/sip/*.go` (489 production lines: addr.go, header.go,
message.go, random.go, readfilter.go, register.go, request.go, tls.go). Callers
in trunk/edge were read only to judge whether a primitive is misused. sipgo
references are to `github.com/emiago/sipgo@v1.4.3/sip`. Everything below was
found by reading, so every finding is INFERENCE. `go vet ./internal/sip/` is clean.

## Findings

### P2-SIP-001 — Edge binding lifetime is taken from the first Contact in the 200 OK, which may belong to another device
- Severity: P1. Layer: leg/binding. INFERENCE.
- Location: `internal/sip/register.go:14-32`. Callers: `internal/edge/register.go:262` and `internal/trunk/register.go:114`.
- Evidence:
  ```go
  for _, h := range res.GetHeaders("Contact") {
      c, ok := h.(*sip.ContactHeader)
      ...
      if v, ok := c.Params.Get("expires"); ok {
          if n, err := strconv.Atoi(v); err == nil {
              return time.Duration(n) * time.Second
  ```
  The code does not compare the Contact URI with the Contact that was registered.
- Reference: RFC 3261 §10.2.4. The 200 OK carries *all* current bindings of the AoR, and a UA must find its own Contact in the list. Also §10.3 step 8.
- Impact: at the edge, several devices of one user register through FreeSBC, each with its own `fsbc=` token (`edge/register.go:302-312`). If FreeSWITCH lists every binding in the 200 OK (multiple registrations enabled), `recordBinding` stores whichever binding comes first. The result is one of:
  - an early expiry: the device becomes unreachable while FreeSWITCH still routes to it;
  - a stale binding that outlives the registrar's own record;
  - `granted <= 0` removing the wrong device's binding.

  The same granted value is then sent back to the client in `restoreContact` (`edge/register.go:323-328`), so the client refreshes on another device's schedule. Two smaller defects:
  - A negative `expires` value is accepted.
  - `time.Duration(n)*time.Second` overflows for n > ~9.2e9, producing a negative duration. That path also removes the binding at the edge. The trunk is protected by `regRefreshFloor`.
- Suggested test (Phase 3): run the edge harness with a fake upstream that answers REGISTER with 200 OK and `Contact: <sip:other@x;fsbc=OTHER>;expires=5, <sip:u@x;fsbc=OURS>;expires=3600`. Assert that the stored binding's `ExpiresAt` is about 3600 s and that the client sees `expires=3600`. Add a unit test of `GrantedExpires` with `expires=-1` and `expires=99999999999`.
- Action: fix. Match on the Contact URI (the `fsbc` token or the full URI), and clamp to `[0, requested]` or a sane maximum.

### P2-SIP-002 — The 64 KiB read-filter size cap can never fire; the sipgo read buffers are 32 KiB
- Severity: P2. Layer: transport. INFERENCE.
- Location: `internal/sip/readfilter.go:8-10,23`. Configured at `internal/edge/edge.go:459-469` (`maxMessageSize = 64 << 10`).
- Evidence: every sipgo read loop fills a buffer of `TransportBufferReadSize uint16 = 32768` (`sipgo sip/transport.go:18`), and the filter sees `buf[:num]`:
  - UDP: `transport_udp.go:125`
  - TCP: `transport_tcp.go:152`
  - WS: `transport_ws.go:174`

  The WS path copies each frame into that buffer with `n += copy(b[n:], data)` (`transport_ws.go:424`). Frames are separately capped at 65535 by `reader.MaxFrameSize` (`transport_ws.go:365`). So `len(data) > 64<<10` is unreachable on every transport. The comment "bounds a message BEFORE the parser sees it" is also wrong for stream transports (TCP/TLS/WS): the filter sees read chunks, not messages, and the stream parser (`parser_stream.go`) stitches chunks together. The real bound is sipgo's own `ParseMaxMessageLength = 65535` (`parser.go:33`) plus the 32 KiB UDP read, which silently truncates larger datagrams.
- Reference: project invariant "edge filter caps reads at 64 KiB" (CLAUDE.md, `docs/design.md:1012-1013,2643,2704`).
- Impact: no memory-safety issue, because sipgo bounds memory. The guard is dead code, and the docs describe a protection that FreeSBC does not provide.
- Suggested test: an edge harness test sends a 40 000-byte UDP datagram and a 70 000-byte TCP message. Assert that the filter's reject branch is never taken; add a counter hook or run a coverage check on `readfilter.go:24`.
- Action: fix. Either lower the cap below 32 KiB or document that sipgo enforces the limit. Update the docs.

### P2-SIP-003 — Docs describe the 64 KiB cap as enforced (docs/code drift)
- Severity: P2. Layer: docs. INFERENCE (depends on P2-SIP-002).
- Location: `docs/design.md:1012-1013` ("anything larger than 64 KiB is dropped before the parser"), `docs/design.md:2642-2644`, `docs/design.md:2704`, `internal/edge/edge.go:459-461` ("bounds what one datagram or one WebSocket frame can cost"). Code: `internal/sip/readfilter.go:23`, sipgo `transport.go:18`.
- Action: fix (docs).

### P2-SIP-004 — `SameAddr` ignores transport and treats a wildcard as equal to any host, so the edge private-listener check can match public stream listeners
- Severity: P2. Layer: transport. INFERENCE.
- Location: `internal/sip/addr.go:62-79`. Caller: `internal/edge/edge.go:475`.
- Evidence:
  ```go
  if ah == bh { return true }
  ...
  return wildcard(ah) || wildcard(bh)
  ```
  The caller compares `info.LocalAddr.String()` with `SIP.Private.Bind.String()`. Validation allows an unspecified private bind (`config/validate_proxy.go:231`). `TransportReadProps.Transport` is available but not consulted.
- Suppose `sip.private.bind` is `0.0.0.0:P` and a public TCP/TLS/WS listener uses port P. Accepted stream connections report their concrete local address, `SameAddr` returns true, and the read is subjected to the private-plane upstream-only rule. Every public stream client on that port is silently dropped. This fails closed, so it is an availability problem, not a bypass. Reads from the upstream IP over TCP are recorded in `privSources`. `arrivedOnPrivate` (`edge/plane.go:89-91`) rejects non-UDP, so this does not escalate to trust.
- Reference: invariant "the private plane is reached only over UDP from `sip.private.bind`" (CLAUDE.md).
- Suggested test: a config with `sip.private.bind: 0.0.0.0:P` and a public `tcp` listener on P. Send a REGISTER over TCP from a non-upstream IP and assert that it is answered. Also check whether `check` rejects the config.
- Action: fix. Compare transport (UDP only) in the filter, and reject a shared port in validation.

### P2-SIP-005 — `TeardownRequest` ignores the route set
- Severity: P2. Layer: dialog. INFERENCE.
- Location: `internal/sip/request.go:69-81`. Caller: `internal/edge/invite.go:1052-1073` (`ackThenBye`).
- Evidence: the request is built with a Request-URI from `ContactOrSource(res)`, a single Via, and From/To/Call-ID/CSeq/Max-Forwards. No `Route` headers are built from the response's `Record-Route`.
- Reference: RFC 3261 §12.1.2. The UAC route set is the Record-Route list in reverse, and §13.2.2.4 and §15.1.1 send ACK and BYE along that route set.
- Impact: sometimes the far side of an edge leg record-routes, for example a PSTN gateway behind its own proxy. The generated ACK for the 2xx goes straight to the transport source with the Contact as Request-URI, bypassing the proxy. That proxy then keeps retransmitting the 2xx until its Timer H/L expires. The BYE can also be rejected. The docstring scopes the function to "a dialog the element tracks itself", but the only caller answers a 2xx from a peer that FreeSBC does not control.
- Suggested test: a unit test calls `TeardownRequest(sip.ACK, res, via, 1)` with `res` carrying `Record-Route: <sip:p1;lr>, <sip:p2;lr>`. Assert that `Route` is `p2, p1`. This will fail.
- Action: fix.

### P2-SIP-006 — `SetSDPBody` installs Content-Type as a generic header, so the typed accessor returns nil
- Severity: P2. Layer: SDP. INFERENCE.
- Location: `internal/sip/header.go:44-48`.
- Evidence: `msg.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))`. `sip.NewHeader` always returns `*genericHeader` (`sipgo headers.go:447-452`). sipgo's cached `contentType` ref is set only for `*ContentTypeHeader` (`headers.go:115`), so after `RemoveHeaders` unrefs the typed header, `msg.ContentType()` returns nil. Serialization is correct. No FreeSBC code calls `ContentType()` today, but any sipgo path or future code that does will treat the body as untyped.
- Suggested test: a unit test calls `SetSDPBody(req, body)` and asserts `req.ContentType() != nil`. This will fail.
- Action: fix. Use `ct := sip.ContentTypeHeader("application/sdp"); msg.AppendHeader(&ct)`.

### P2-SIP-007 — `DefaultPort` maps `wss` to 5061, which contradicts its own RFC 7118 rationale for `ws`
- Severity: P2. Layer: transport. INFERENCE.
- Location: `internal/sip/addr.go:81-94`.
- Evidence: the comment says RFC 7118 puts plain SIP over WebSocket on the HTTP port (`ws` maps to 80). By the same reasoning, WSS belongs on 443 (RFC 6455 §3), but `case "tls", "wss": return 5061`. The only WS/WSS caller is `edge/topology.go:452` (`isSelfVia`). FreeSBC's own Vias carry explicit ports, so the effect is currently latent.
- Action: fix. Choose one convention and document it.

### P2-SIP-008 — `ParseBindIP` falls back to all interfaces when the bind address does not parse
- Severity: P2. Layer: config/lifecycle. INFERENCE.
- Location: `internal/sip/register.go:39-48`. Callers: `edge/mediapool.go:24`, `trunk/mediapool.go:22`.
- Evidence: `if err != nil { return netip.Addr{} }` is documented as "every interface". Today validation catches bad values (`config/validate.go:77`, `validate_proxy.go:345,353`), so this is defence-in-depth only. On any path that skips validation, a typo makes media listen on the public interface. The function also lives in `register.go`, which has nothing to do with REGISTER.
- Action: fix. Return `(netip.Addr, error)` or panic on an invalid value, and move the function to addr.go.

### P2-SIP-009 — `ContactOrSource` is exported but used only inside the package
- Severity: P2. Layer: dialog. INFERENCE.
- Location: `internal/sip/request.go:87`. `grep` finds no caller outside `internal/sip`.
- Action: fix (unexport). Trivial; reported only because `docs/design.md:3007` presents the package API as its shared surface.

## Checklist items checked and found clean
- Goroutines, `time.Sleep`, `time.After`, locks, shared maps, channels: none in the package. This matches `docs/design.md:2248`.
- `_ = err`: none. `recover()`: none. `defer` in loops: none. Per-RTP-packet work: not applicable.
- The `Editable` interface has two implementations (`*sip.Request`, `*sip.Response`, header.go:15-18) and is justified.
- `any`/`interface{}`: none.
- Transaction keying (RFC 3261 §17.1.3/§17.2.3): not done here; sipgo owns it. `BuildCancel` copies the single top Via hop including its branch (`request.go:28-29`; sipgo `ViaHeader.Clone` is one hop), plus Route, the Request-URI, From/To/Call-ID and the CSeq number with method CANCEL, as §9.1 requires.
- Dialog keying (§12): this package does not key dialogs. `FromTag`/`ToTag`/`CallID` are nil-safe accessors.
- ACK for 2xx vs non-2xx (§17.1.1.3, §13.2.2.4): `TeardownRequest` builds only 2xx ACKs with a new branch and the INVITE's CSeq number (edge/invite.go:1053-1054), which is correct apart from P2-SIP-005.
- 100 Trying not forwarded (§16.7 step 2): `Forwardable` is correct.
- Compact header forms (i f t v m l c): sipgo maps them to typed headers whose `Name()` is the full form (`parse_header.go:42-57`), so `RemoveHeaders(msg, "Contact")` also strips a Contact sent as `m:`. No leak through `SetContact`.
- Content-Length: `SetBody` updates Content-Length (sipgo message.go:146-165).
- Read filter never returns an error (`readfilter.go:22-30`), and sipgo discards a zero-length result (`transport_udp.go:171`, `transport_tcp.go:195`).
- Transport-source addresses: `SourceAddrPort`/`ParseHostPortAddr`/`AddrOf` call `Unmap`. sipgo's `Request.Source()` falls back to the Via when no source is set (`request.go:160-165`). All callers pass received messages, whose source sipgo sets from the transport, so the "never from a Via" claim holds in practice.
- Imports: nothing from this module (`go list -f '{{.Imports}}'`), matching `doc.go` and `docs/design.md:104-106`.
- Credentials: none stored or inspected. `NewBranch`/`NewToken` use crypto/rand with a magic cookie (§8.1.1.7).
- `SelfSignedTLS`: TLS ≥ 1.2 and an in-memory key. Only a harmless style nit (KeyEncipherment on an ECDSA key), not reported.
