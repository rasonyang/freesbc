# Phase 2 — internal/sip/sdp

Scope: `internal/sip/sdp` (`sdp.go`, `build.go`, `codec.go`), plus the edge call
sites in `internal/edge/media.go` and `internal/edge/dialog.go` only where the
package's contract depends on them. The review was done by reading the code. `go vet ./internal/sip/sdp`
is clean. Two behaviours of the third-party library were reproduced in a
scratch module outside the repo (pion/sdp v3.0.19, the version in go.mod).
Those results are marked "pion-reproduced". A finding counts as FACT only if the whole claim was reproduced.

## Findings

### P2-SDP-001 — Answer m-line order and media type do not match the offer
- Severity: P1 · Layer: SDP · INFERENCE · Action: fix
- Location: `internal/sip/sdp/build.go:74-80`, `build.go:163-167`, `build.go:197-206`; `internal/sip/sdp/sdp.go:199-210`, `sdp.go:172-178`
- Evidence: `Parse` relays the first audio section with a non-zero port, wherever it sits (`if md == nil && m.MediaName.Media == "audio" && m.MediaName.Port.Value != 0`), but `Session` records only `MediaCount`. It does not record the index of the relayed section or the media type and proto of the other sections. `marshal` always appends the live section first (`sd.MediaDescriptions = append(sd.MediaDescriptions, md)`) and then `declined` copies of `m=audio 0 RTP/AVP 0`.
- Impact: consider an offer with `m=video …` then `m=audio …`, or `m=audio 0 …` then `m=audio 4000 …` (the case that `sdp.go:204-206` and design.md:1808-1810 explicitly support). The answer puts the live audio at index 0, not at the offer's index. It also declares every declined slot as `audio` RTP/AVP even when the offer had video or application there. RFC 3264 §6 says: "For each m= line in the offer, there MUST be a corresponding m= line in the answer… in the same order" and "the media type… MUST match". A browser offering audio+video (JSEP) rejects such an answer in setRemoteDescription. An RFC-strict UA maps the audio port to the wrong stream.
- Reference: RFC 3264 §6; design.md:1861-1864, design.md:2918-2920 ("every non-audio section is declined at port 0" — true for the count, false for order and type).
- Confirm: unit test `TestMarshalDecliningPreservesOrder` (audit: P2-SDP-001). Parse `m=audio 0 RTP/AVP 0` + `m=audio 4000 RTP/AVP 0`, then call `Build{…}.MarshalDeclining(sess)`. Re-parse with pion and assert that index 1 has port != 0 and index 0 has port 0. A second case, `m=video 5000 RTP/AVP 96` + `m=audio …`, asserts `MediaName.Media` per index. Both are expected to fail today.
- Recommendation: `Session` should carry the relayed index and a per-section `(media, protos, fmt[0])` tuple, and `MarshalDeclining` should emit sections in offer order. This is an identity-model gap in the `Session` type. Fixing it means adding fields, not rewriting the package.

### P2-SDP-002 — o= version is shared across both legs and increments by more than one per leg
- Severity: P1 · Layer: SDP · INFERENCE · Action: fix (the defect is in edge; the contract belongs to this package)
- Location: `internal/edge/dialog.go:81-95` (`sdpOrigin.next`: `o.version++`), `dialog.go:258-262`; callers `internal/edge/media.go:161,303,362,396,454,516,549`; contract `internal/sip/sdp/build.go:36-39` ("A re-offer on the same leg must reuse the ID and bump the version").
- Evidence: each dialog has one `sdpOrigin`, and every body built toward either leg calls `next()`. Take a client-originated call: offer→FS gets v1 and answer→client gets v2. A later re-INVITE toward FS gets v3, so FS sees 1→3. Each failed PSTN failover attempt (`applyPSTNAnswer`) and each rejected re-offer also consumes a version. The two legs also share the same `<sess-id>`.
- Reference: RFC 3264 §8: "the version in the origin field MUST increment by one from the previous SDP". RFC 4566 §5.2.
- Confirm: an edge integration test, `TestReInviteOriginVersionIncrementsByOne` (audit: P2-SDP-002). Set up a call, then send one re-INVITE from the client. Parse the `o=` of the bodies FS received and assert that the versions are consecutive (1 then 2). Expected to fail with 1 then 3.
- Recommendation: keep one `sdpOrigin` per leg (public, private), and bump only when a body is actually sent on that leg.

### P2-SDP-003 — The FMTP value from the other leg is copied verbatim into the emitted SDP, including a lone CR
- Severity: P1 · Layer: SDP · INFERENCE (pion behaviour pion-reproduced) · Action: fix
- Location: `internal/sip/sdp/sdp.go:310-313` (`fmtp[pt] = rest`), `codec.go:60-62` (`merged.FMTP = a.FMTP`), `build.go:146-148` (`attr("fmtp", fmt.Sprintf("%d %s", c.PayloadType, c.FMTP))`); flows through `edge/media.go:162-169` (public offer fmtp → FS) and `edge/media.go:284,304-315` (FS answer fmtp → client).
- Evidence: FMTP is the one free-text field that crosses legs. Nothing validates its character set or content. Reproduced in pion: unmarshalling `a=fmtp:0 x=1\rinjected=1 198.51.100.7` gives no error and the value `"0 x=1\rinjected=1 198.51.100."`. The lone CR is kept, and pion also silently drops the last byte. Marshalling an attribute value that contains `\r` emits the CR verbatim (`"a=fmtp:0 x=1\rc=IN IP4 198.51.100.7\r\n"`).
- Impact: an attacker can place any text, including an IP address or port, in an fmtp line on one leg, and it appears in the SDP FreeSBC constructs for the other leg. A receiver that treats a bare CR as a line end then sees an injected `c=` line. This contradicts the invariant "nothing is copied from the other leg's body" (design.md:1841-1844, design.md:3008, CLAUDE.md:42, `build.go:18-23`). design.md:1855 separately admits "a=fmtp verbatim", so the docs contradict themselves.
- Reference: RFC 4566 §5 (a line ends only at CRLF or LF, so a bare CR inside a value is not a valid record); project invariant: topology hiding / the edge constructs bodies from scratch.
- Confirm: this is the Phase 3 SDP leak property test. Seed the FS answer with `a=fmtp:0 <sentinel-ip>` and with `a=fmtp:111 minptime=10\rc=IN IP4 <sentinel>`, then assert that the sentinel is absent from the client-facing body. Expected to fail. Fuzz target `FuzzParseBuildRoundTrip`: Parse, then Build, then assert the output has no `\r` that is not followed by `\n`, and no byte outside the printable range, in any attribute.
- Recommendation: validate fmtp against the RFC 4566 byte-string grammar (reject CR, LF and NUL). Consider a per-codec allowlist of fmtp parameters (opus, telephone-event). Fix the documentation either way.

### P2-SDP-004 — Parse accepts unspecified, loopback, multicast and link-local connection addresses, and edge uses them as RTP destinations
- Severity: P1 · Layer: SDP/media · INFERENCE · Action: fix
- Location: `internal/sip/sdp/sdp.go:249-253` (only `netip.ParseAddr` is checked); consumers `internal/edge/media.go:188-190` (`sess.SetRemote(media.SideA, netip.AddrPortFrom(offer.Audio.Address, …))`), `media.go:298,392,451` for the a=rtcp address.
- Evidence: `c=IN IP4 0.0.0.0` (the RFC 3264 §8.4 legacy hold form), `127.0.0.1`, `10.x` (the FreeSWITCH LAN), or `224.x` without a TTL are all accepted as the relay destination. Until the loose latch sees a first packet, the relay "still carries outbound audio" to the address from the SDP (`media.go:175-181`). On Linux, sending to 0.0.0.0 reaches the local host. An authenticated client (FS must answer before `Start`) can therefore point FreeSWITCH-originated RTP at FreeSBC's own loopback services or at LAN hosts.
- Reference: RFC 3264 §8.4 (0.0.0.0 means hold, not a destination); project invariant: the public client must not reach the private LAN through the SBC.
- Confirm: unit test on `Parse` for 0.0.0.0, 127.0.0.1 and ::1, asserting that the result is not usable as a destination (expected to fail). An edge integration test: a client offer with `c=IN IP4 127.0.0.1` and m-port = a local UDP listener, then assert that the listener receives no RTP before latching.
- Recommendation: reject, or mark as "no destination", any address that is unspecified, loopback, multicast or link-local. Policy on private ranges belongs in edge.

### P2-SDP-005 — Duplicate codec identities in the offer cause a false ErrRenumbered
- Severity: P1 · Layer: SDP · INFERENCE · Action: fix
- Location: `internal/sip/sdp/codec.go:45-59`
- Evidence: `byKey` keeps only the first answer codec per `name/rate/channels` key (`if _, dup := byKey[c.key()]; !dup`). Suppose an offer lists the same codec twice under different PTs, for example `opus/48000/2` as 111 and 96 with different fmtp, or `telephone-event/8000` as 101 and 126. If the answer accepts both with the same numbers, the second offer entry is compared against the first answer PT, and `a.PayloadType != o.PayloadType` returns `ErrRenumbered`. The edge maps that to 488 (`edge/media.go:113-120`), so a correct answer fails the call.
- Reference: RFC 3264 §6.1 (multiple PTs for one encoding are legal); RFC 3551 §3.
- Confirm: unit test `TestNegotiateDuplicateKeyNotRenumbered` (audit: P2-SDP-005). Offer `[111 opus/48000/2, 96 opus/48000/2]`, answer the same list, and assert no error. Expected to fail.
- Recommendation: first match on the offer PT (exact number and key), and fall back to key matching only to detect a real renumber.

### P2-SDP-006 — isHexByte accepts control bytes 0x10-0x19 as hex digits
- Severity: P2 · Layer: SDP · INFERENCE (logic reproduced on a verbatim copy of the function: `isHexByte("\x10\x19") == true`) · Action: fix
- Location: `internal/sip/sdp/sdp.go:458-465` (`c := s[i] | 0x20`)
- Evidence: OR-ing 0x20 maps 0x10-0x19 onto '0'-'9'. `parseFingerprint` therefore accepts a fingerprint containing control bytes and stores it in `Fingerprint.Value` (`sdp.go:455`). The value only reaches `VerifyFingerprint`, where the mismatch tears the session down. No injection path was found, but the validation does not do what `sdp.go:424-427` claims.
- Reference: RFC 8122 §5 (fingerprint = 2UHEX *(":" 2UHEX)).
- Confirm: unit test `parseFingerprint("sha-256 " + 32 parts with "\x10\x11")` must return ok=false (expected to fail). Include this case in `FuzzParse`.
- Recommendation: fix it (compare ranges explicitly, or use `hex.DecodeString`).

### P2-SDP-007 — Code comments and docs overstate RFC 3264: the answerer's PT reuse is a SHOULD
- Severity: P2 · Layer: docs · INFERENCE · Action: fix (docs)
- Location: `internal/sip/sdp/codec.go:28-31` ("RFC 3264 §6 requires an answerer to use the offerer's payload-type numbers"), `sdp.go:20-23`.
- Evidence: RFC 3264 §6.1 says "that same payload type number SHOULD be used". Rejecting renumbering with 488 is a policy choice that interoperable peers can legally trigger. The comment presents that policy as a protocol requirement.
- Recommendation: correct the wording. Mention in docs/edge.md limitations that answers which renumber PTs get 488.

### P2-SDP-008 — The comment on Describe claims codec names are alphanumeric, but parseRTPMap does not enforce it
- Severity: P2 · Layer: docs · INFERENCE · Action: fix
- Location: `internal/sip/sdp/codec.go:73-77` vs `sdp.go:367-370` (only `name == "" || len(name) > 64` is checked).
- Evidence: rtpmap names can contain spaces, quotes, a lone CR (see P2-SDP-003) and any other byte pion keeps. `edge/media.go:137,336,513` pass the *unfiltered* offer list to `Describe` inside error text that is logged. slog's Text and JSON handlers quote these values, so this is not a log-forging vulnerability, but the stated safety property is false. Names only reach emitted SDP after `filterCodecs` (`edge/codecs.go:34-42`), which limits them to 4 names.
- Recommendation: either restrict names to RFC 4566 `token` characters in `parseRTPMap`, or remove the claim from the comment.

### P2-SDP-009 — Payload types above 255 fail the whole Parse, while 128-255 are skipped
- Severity: P2 · Layer: SDP · INFERENCE · Action: fix
- Location: `internal/sip/sdp/sdp.go:319-329`
- Evidence: `strconv.ParseUint(…, 10, 8)` returns an error for "256" and above, so `Parse` fails with "bad payload type". Values 128-255 parse and are then skipped by `pt > 127`. The comment says out-of-range values are skipped "rather than fail". The behaviour is inconsistent. It is harmless in practice.
- Confirm: `Parse` of `m=audio 4000 RTP/AVP 0 300` should succeed with [PCMU] according to the comment (expected to fail).

### P2-SDP-010 — ErrNoAudio does not distinguish a declined audio stream (port 0) from an absent one
- Severity: P2 · Layer: SDP · INFERENCE · Action: fix
- Location: `internal/sip/sdp/sdp.go:207-213`
- Evidence: suppose an answer rejects the audio stream (`m=audio 0 …`, the RFC 3264 §6 rejection). `Parse` returns `ErrNoAudio`, the same error as for an SDP with no audio section at all. Callers (`edge/media.go:279-282` and others) cannot tell a legitimate rejection from a malformed answer.
- Recommendation: add an `ErrAudioDeclined` sentinel.

### P2-SDP-011 — A browser answer always carries a=rtcp-mux, whether or not the offer did
- Severity: P2 · Layer: SDP · INFERENCE · Action: fix
- Location: `internal/edge/media.go:482-485` (`build.DTLS, build.RTCPMux = true, true`); `internal/sip/sdp/sdp.go:260-295` does not parse `rtcp-mux`, so no caller can check it.
- Evidence: RFC 5761 §5.1.1 says the answerer includes a=rtcp-mux only if the offer did. Every current browser offers it, so the practical impact is low.
- Recommendation: parse `rtcp-mux` into `Audio` and reject a non-mux WebRTC offer, since the leg supports only mux.

### P2-SDP-012 — sanitizeICEToken accepts a 4-character ice-pwd
- Severity: P2 · Layer: SDP · INFERENCE · Action: fix
- Location: `internal/sip/sdp/sdp.go:410-413`
- Evidence: the same 4-256 length bound applies to ufrag and pwd. RFC 5245 §15.4 requires ice-pwd to be 22-256 characters (ufrag 4-256). A short pwd weakens STUN message integrity on the leg FreeSBC terminates.

## Out-of-package observations (for the edge reviewer)
- `internal/edge/media.go:506-532` + `invite.go:1141`: `rebuildInDialogOffer` never calls `setWebRTCAnswer`/DTLS. A re-INVITE from FreeSWITCH toward a WebRTC client (for example a session-timer refresh or a hold) is therefore sent to the browser as a plain `RTP/AVP` offer with no ICE or fingerprint. A browser rejects it or treats it as a transport change. RFC 3264 §8, RFC 8839/8842. (INFERENCE, P1.)
- `internal/edge/media.go:130-137` passes the unfiltered offer list to `Describe` (see P2-SDP-008).

## Checklist items found clean
- Size and cardinality bounds: `MaxSize` is checked before `Unmarshal` (`sdp.go:185`); the section, attribute and format limits are checked before per-item work.
- Hostnames in c= are never resolved (`sdp.go:246-251`).
- An a=rtcp address is discarded; only the port is used (`sdp.go:280-289`).
- ICE tokens: CR, LF and non-token bytes are rejected (`sdp.go:410-422`).
- SHA-1 fingerprints are rejected (`sdp.go:435-444`).
- `Build` takes no fields from the other leg's body except the codec list (Name is filtered by edge; FMTP is the exception, P2-SDP-003).
- Declined sections carry no attributes and no c= line (`build.go:197-206`), so no keys or candidates ride along.
- o= version is incremented on every new offer (but not by one; P2-SDP-002). Session-id is FreeSBC-generated and not copied from a peer.
- Direction: media-level overrides session-level (RFC 4566 §5.13). The relay passes it through unreversed, which is correct for a middlebox.
- Go checklist: no goroutines, locks, maps shared across goroutines, `_ = err`, recover, `any`, or defer in loops. The package is pure functions.
- Per-RTP-packet work: none. `Codec.key` uses `fmt.Sprintf` per negotiation, not per packet.
- Transaction and dialog keying, ACK, timers, CANCEL, forking, glare and compact headers: not applicable to this package.

## Docs vs code
- design.md:1841-1844, design.md:3008, CLAUDE.md:42, `build.go:18-23` say "nothing is copied from the other leg's body". FMTP is copied verbatim (design.md:1855 says so itself). See P2-SDP-003.
- design.md:1861-1864 and 2918-2920 say the answer "preserves the offer's section count (RFC 3264 §6)" and "every non-audio section is declined". The count is preserved; order and media type are not. See P2-SDP-001.
- `codec.go:28-31`: "RFC 3264 §6 requires…". The RFC says SHOULD. See P2-SDP-007.
- `codec.go:75-76`: "codec names are alphanumeric by construction". False. See P2-SDP-008.

## Phase 3 inputs
- `FuzzParse(body []byte)`: must not panic. If it returns nil error, `Audio != nil`, `len(Codecs) > 0`, every PT is ≤ 127, and the Address is valid. Seed it with every body in `sdp_test.go`, plus lone-CR, 0x10-hex fingerprint, PT 300 and a 16 KiB boundary case.
- `FuzzParseBuildRoundTrip`: take Parse → Negotiate(self, self) → Build → pion Unmarshal. Assert that the result re-parses, has exactly `MediaCount` sections, contains no bare CR, and that the relayed section sits at the offer's audio index (P2-SDP-001).
- The SDP leak property test (P2-SDP-003, P2-SDP-004): put a sentinel IP and port in c=, o=, a=rtcp, a=candidate and a=fmtp of the upstream answer. Assert that only the fmtp channel leaks (expected), which makes the fmtp leak a FACT.
