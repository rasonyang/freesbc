# FreeSBC M5 — SRTP (SDES) Media Security Design

The media-security milestone: encrypt/decrypt the relayed media path with SRTP,
keyed via SDES (`a=crypto` in the SDP, RFC 4568). The B2BUA already rewrites SDP
to its own media ports and relays every packet through its own sockets, so the
SBC becomes the SRTP boundary — it terminates SRTP on a secure leg and
re-originates (or passes plaintext) toward the other leg. This is the first
milestone touching the media crypto path. Parent spec:
`freesbc-allinone-design.md` (media depth: RTP relay + SRTP, no transcoding;
SRTP key negotiation via SDES only; DTLS-SRTP excluded along with WebRTC).
M1–M4 complete and merged.

## 0. Reality baseline (existing code)

- `media/relay.go`: `forward(from, to, rtpKind)` runs four goroutines (RTP+RTCP
  × both directions) doing `read → latch.accept(src) → write to the other
  side's latched remote`. A raw byte copy today.
- `media/session.go`: `Session` holds two `PortPair`s and per-side RTP/RTCP
  latches; `Allocate → SetExpectedRemote → Start → Close`, silence watchdog.
- `sig/sdp.go`: `rewriteSDP(sdpBytes, ourIP, rtpPort)` rewrites `o=`/session
  `c=`/first-audio `m=` port to the SBC, declines other media sections (port 0);
  `remoteMediaIP` extracts the peer's media IP to arm the latch.
- `sig/b2bua.go`: the bridge — `onInvite` (A-leg answer), `placeCall`/
  `dialTarget` (B-leg offer + failover), early media via 18x (M3.3 Task 7).
- Dependencies: `pion/sdp/v3` present; `pion/srtp` + `pion/rtp` NOT yet in
  go.mod (M5 adds them). Signaling can be UDP/TCP/TLS (M3.1).

## 1. Decisions (confirmed 2026-07-17)

1. **SBC terminates and re-originates SRTP per leg.** Each leg is SRTP or
   plaintext independently; the SBC decrypts a secure leg and re-encrypts (or
   sends plaintext) toward the other. This *is* SRTP↔RTP interworking. (Settled
   by the parent design's B2BUA-owns-media model.)
2. **Per-peer 3-state policy, default `disabled`.** `Peer.SRTP` ∈
   {`disabled`, `optional`, `required`}. `disabled` (default) keeps every
   existing M1–M4 plaintext config working unchanged. `required` mandates
   `RTP/SAVP` + usable `a=crypto` (else reject/fail). `optional` = SRTP if the
   peer offers/accepts it, else plaintext.
3. **Suites: AES_CM_128_HMAC_SHA1_80 + AES_CM_128_HMAC_SHA1_32.** Offer both
   (80 first, the stronger auth tag); accept either. AES-256 and AEAD/GCM
   deferred.
4. **SDES only; SDES keys over non-TLS → warn-and-allow.** When a leg
   negotiates SRTP over a non-TLS transport, log one WARN and negotiate anyway
   (strictness is achieved by configuring the peer `transport: tls`). DTLS-SRTP
   excluded (parent design).

## 2. SRTP context model

An SRTP master key in SDES is a base64 `inline:` value = master key ‖ master
salt. For the AES_CM_128 suites that is **30 bytes** (16-byte key + 14-byte
salt). One pion/srtp context per *direction of one leg* protects both RTP and
RTCP (SRTP derives the RTP and RTCP session keys from the one master key).

Per call the SBC holds up to **four** contexts:

| Context | Key source | Used by |
|---|---|---|
| A-inbound (decrypt) | the key the A-peer advertised in its `a=crypto` | A→B relay: unprotect packets read from A |
| A-outbound (encrypt) | a fresh key the SBC generated + advertised to A | B→A relay: protect packets sent to A |
| B-inbound (decrypt) | the key the B-peer advertised in its `a=crypto` | B→A relay: unprotect packets read from B |
| B-outbound (encrypt) | a fresh key the SBC generated + advertised to B | A→B relay: protect packets sent to B |

A plaintext leg has both its contexts nil. Each context is touched by exactly
one direction's goroutine pair (the RTP and RTCP loops of that direction share
the one context) — see §5 for the concurrency note.

## 3. Components & module layout

| File | Change |
|---|---|
| `media/srtp.go` (new) | `CryptoSuite` enum (the two AES_CM_128 suites, with key/salt/tag sizes); `srtpContext` wrapping a `*srtp.Context` for one stream, exposing `protectRTP`/`unprotectRTP`/`protectRTCP`/`unprotectRTCP` returning `(out []byte, ok bool)` (ok=false drops the packet); a constructor from (suite, masterKeyValue). |
| `media/session.go` | `Session` gains `srtpIn [2]*srtpContext` and `srtpOut [2]*srtpContext` and `SetSRTP(side Side, inbound, outbound *srtpContext)` (called before `Start`). |
| `media/relay.go` | `forward` grows the decrypt→encrypt step (§5). |
| `sig/crypto.go` (new) | RFC 4568 `a=crypto` parse (`parseCrypto([]byte) []cryptoLine`) and generate (`newCryptoKey(suite)` → base64 inline; `cryptoAttr(tag, suite, key)`); suite support table; `selectCrypto(offered, ourPolicy)`. Pure, no I/O. |
| `sig/sdp.go` | A crypto-aware SDP build: set `m=` proto (`RTP/SAVP` vs `RTP/AVP`), inject/strip `a=crypto`, extract a leg's offered crypto. Reuses the existing topology-hiding rewrite. |
| `sig/b2bua.go` | Negotiate per leg (§4); build contexts; `SetSRTP` before `Start`; the 488/failover paths; the non-TLS WARN. |
| `config/schema.go`, `validate.go` | `Peer.SRTP string` (yaml `srtp`, default `disabled`); validate ∈ {disabled, optional, required}. |
| `sbc.example.yaml` | Document `srtp` per peer. |

`pion/srtp` (+ its `pion/rtp` transitive) is added to go.mod.

## 4. Negotiation flow

### 4.1 A-leg (SBC = UAS toward the caller)

The A-leg INVITE carries the offer. A is "secure-offered" iff its first audio
`m=` proto is `RTP/SAVP` **and** it carries at least one well-formed
`a=crypto`. Combine with the A-peer's policy:

```
A-peer srtp = disabled  → A is plaintext (ignore any crypto)
A-peer srtp = required  → A must be secure-offered with a SUPPORTED suite
                          → else 488 Not Acceptable Here
A-peer srtp = optional   → A is SRTP iff secure-offered (supported suite),
                          else plaintext
```

If A is SRTP: `selectCrypto` picks the first offered line whose suite we
support (80 preferred). Build **A-inbound** from that line's key; generate a
fresh key and build **A-outbound**. The SBC's 200 answer to A uses
`RTP/SAVP` + one `a=crypto` (tag 1, the selected suite, the SBC's A-key).

### 4.2 B-leg (SBC = UAC toward the target)

The SBC's outgoing INVITE offer to B is decided by the B-peer's policy:

```
B-peer srtp = required  → offer RTP/SAVP + a=crypto (both suites, fresh B-key)
B-peer srtp = disabled  → offer RTP/AVP, no crypto
B-peer srtp = optional   → MIRROR the A-leg: A secure → offer SRTP to B;
                          A plaintext → offer plaintext to B
```

B's answer (a 200, or an 18x early-media answer) is parsed:

```
offer was SRTP and answer is RTP/SAVP + usable a=crypto (supported suite)
    → build B-inbound (B's key) + B-outbound (the SBC's B-key B accepted)
offer was SRTP, B-peer required, but answer has no usable crypto
    → this target FAILS (failReal) → M4.1 failover to the next target
offer was plaintext → B is plaintext
```

The SBC never bridges a `required` leg down to plaintext: a `required` peer
that won't do SRTP is a failed leg, not a silent downgrade. (An operator who
wants a secure↔plaintext bridge configures one leg `disabled`/`optional` — that
downgrade is then intentional and operator-owned.)

### 4.3 Wiring

Once both legs are classified, hand the (up to four) contexts to the session
via `SetSRTP(SideA, aIn, aOut)` / `SetSRTP(SideB, bIn, bOut)` **before**
`Start` — including on the early-media path (a secure 18x answer must arm
SRTP before the first B→A packet). The existing latch arming, SDP topology
rewrite, and media Start ordering are otherwise unchanged.

### 4.4 disabled-peer that is offered SRTP

A `disabled` A-peer whose offer is `RTP/SAVP` is answered plaintext:
downgrade the answer to `RTP/AVP` and strip `a=crypto`. If the offer is
`RTP/SAVP` *only* (no plaintext fallback the peer would accept) the far end may
reject our AVP answer — that is the peer's choice, not an SBC error. We do NOT
488 a `disabled` peer merely for offering crypto; we answer plaintext and let
the peer decide. (Rationale: `disabled` means "this trunk is plaintext to us";
honoring that by answering AVP is the correct operator-intended behavior.)

### 4.5 Non-TLS keys

Whenever a leg ends up SRTP over a non-TLS signaling transport, log exactly one
WARN per leg: `SDES key over non-TLS (<transport>) with peer <name>`. Negotiate
anyway (decision 4). This is observability, not a gate.

## 5. Media path (relay)

`forward(from, to, rtpKind)` becomes:

```
read n, src from `from` socket
if !inLatch.accept(src): continue                    // unchanged latch gate
pkt := buf[:n]
if s.srtpIn[from] != nil:                             // secure sending leg
    pkt, ok = s.srtpIn[from].unprotect{RTP,RTCP}(pkt)
    if !ok: continue                                 // bad auth tag / replay → DROP
if s.srtpOut[to] != nil:                             // secure receiving leg
    pkt, ok = s.srtpOut[to].protect{RTP,RTCP}(pkt)
    if !ok: continue
update lastRx; write pkt to outLatch.target()
```

Interworking falls out: SRTP→SRTP = unprotect+protect (re-keyed); SRTP→RTP =
unprotect only; RTP→SRTP = protect only; RTP→RTP = neither (byte copy, exactly
today's behavior). A decrypt/encrypt failure **drops that packet** and
continues — the same fail-closed posture as a latch mismatch, and the tamper/
replay resistance a security SBC wants; it never tears the call down.

**Concurrency:** the RTP loop and the RTCP loop of one direction share one
context (e.g. A→B RTP unprotect and A→B RTCP unprotect both use `srtpIn[A]`).
The plan MUST verify `pion/srtp.Context`'s RTP and RTCP methods are safe for
concurrent use (the context guards per-SSRC RTP and RTCP state separately); if
they are not, split into distinct RTP and RTCP contexts derived from the same
master key. No context is ever shared across *directions*, so no cross-direction
locking is needed regardless.

## 6. Config

`Peer.SRTP string` (yaml `srtp`), default `disabled`. `withDefaults` fills
`""` → `"disabled"`. `validate` rejects anything not in
{`disabled`, `optional`, `required`} with a per-peer error. No global knob.

```yaml
peers:
  carrier:
    address: sip.carrier.com
    transport: tls
    srtp: required          # RTP/SAVP + a=crypto or the call fails
  pbx:
    address: 10.0.0.5:5060
    srtp: disabled          # plaintext RTP (default; may be omitted)
  softswitch:
    srtp: optional          # SRTP if offered/accepted, else RTP
```

## 7. Error handling

| Scenario | Behavior |
|---|---|
| `required` A-peer, offer not secure / unsupported suite | 488 Not Acceptable Here |
| `required` B-peer, answer not secure / unsupported suite | target fails (failReal) → M4.1 failover |
| Multiple `a=crypto` offered, some supported | select the first supported (80 preferred) |
| `disabled` peer offered `RTP/SAVP` | answer plaintext `RTP/AVP`, strip crypto (§4.4) |
| SRTP unprotect/protect failure at runtime (bad tag, replay) | drop that packet, keep the call up |
| SRTP negotiated over non-TLS transport | negotiate; one WARN per leg |
| Malformed `a=crypto` (bad base64, wrong key length) | treated as "no usable crypto" for policy purposes |
| Media-change re-INVITE (would rekey) | 501 (unchanged M3.3 behavior; rekey deferred) |
| Session-timer refresh re-INVITE (M4.3) | echoes established SDP incl. same a=crypto — no rekey, unchanged |

## 8. Testing

- **`sig/crypto.go`** (pure): parse valid/malformed/unsupported-suite/multiple-
  line/MKI-present `a=crypto`; `newCryptoKey` length + base64 round-trip per
  suite; `selectCrypto` (80 preferred, unsupported skipped, required-with-none).
- **`media/srtp.go` + relay** (packet-level, real pion/srtp on the far side):
  encrypt with the SBC's outbound key → a pion/srtp receiver decrypts it;
  the four interworking combinations (SRTP→SRTP re-keyed, SRTP→RTP, RTP→SRTP,
  RTP→RTP byte-identical); a tampered/replayed packet is dropped not relayed;
  SRTCP round-trip. Concurrency check per §5 under `-race`.
- **Integration** (stub carrier acting as a real SRTP endpoint): `required`/
  `optional`/`disabled` per leg; A-SRTP ↔ B-plaintext interworking end to end
  with a genuine decrypt on the far side; `required` A-peer with no crypto →
  488; `required` B-peer with no crypto → failover; a secure 18x early-media
  answer arms SRTP before the first packet. No regression to plaintext M1–M4
  calls, session timers, DNS-SRV/health, teardown.
- Full `go vet ./... && go test ./... -race` green.

## 9. Scope

**In M5:** SDES (`a=crypto`) negotiation (parse/generate/select),
AES_CM_128_HMAC_SHA1_80 + _32, per-peer `srtp` policy (disabled/optional/
required, mirror-for-optional on the B-leg offer), SBC-terminated SRTP with
SRTP↔RTP interworking in all four combinations, SRTCP, warn-on-non-TLS,
packet-drop on auth failure, early-media SRTP arming.

**Deferred (documented non-goals):**
- DTLS-SRTP (excluded with WebRTC by the parent design).
- MIKEY, ZRTP (SDES is the only key exchange).
- AES-256 and AEAD/GCM suites (only the two AES_CM_128 suites).
- Mid-call SRTP rekey — a media-change re-INVITE stays 501 (M3.3); only the
  M4.3 session-timer refresh (same key echoed) is supported.
- MKI-based multiple master keys and key-lifetime enforcement (an offered MKI
  or lifetime is accepted/parsed but ignored — single master key per leg).
- Per-peer crypto-suite selection config (the suite set is global/fixed).
- SRTP for non-audio sections (still declined at port 0, as today).
