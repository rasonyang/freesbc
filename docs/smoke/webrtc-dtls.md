# Smoke test: WebRTC ICE/DTLS with a real browser

A manual runbook for the edge plane's browser media path:

```
Browser (sip.js / web-sip-phone) ──WSS + ICE/DTLS-SRTP──▶ FreeSBC edge ──UDP + RTP──▶ FreeSWITCH
```

It covers what the unit tests cannot: a real browser's ICE agent, DTLS
stack and SRTP, against a real FreeSWITCH. Run it before merging a change
to `internal/media/webrtcleg.go`, `webrtcsession.go`, `mux.go` or
`internal/edge/media.go`, and whenever the pion modules are bumped.

It was written for the change that moved the DTLS fingerprint check into
the handshake (#29) and fixed the ICE agent leak when a leg is closed
during establishment (#16). Those two cases are the negative test (T5) and
the teardown test (T6).

## Versions under test

| Module | Version |
|---|---|
| `github.com/pion/ice/v4` | v4.4.1 |
| `github.com/pion/dtls/v3` | v3.1.8 |
| `github.com/pion/srtp/v3` | v3.0.12 |
| `github.com/pion/transport/v4` | v4.1.0 |

Confirm them with `go list -m github.com/pion/ice/v4 github.com/pion/dtls/v3
github.com/pion/srtp/v3` in the checkout you build. Record the FreeSBC
commit (`git rev-parse HEAD`; the `freesbc_build_info` metric shows the
`-X main.version` the binary was built with), the
browser and its version, the sip.js or web-sip-phone version, and the
FreeSWITCH version in your test notes.

## Prerequisites

- **FreeSWITCH** on a private address (here `10.77.0.10:5060`) with the
  stock `default` dialplan. The runbook uses the stock extensions `9196`
  (echo) and `9664` (music on hold), and a directory user `1000`. Its SIP
  profile must accept plain RTP/AVP from the SBC: FreeSBC terminates
  DTLS-SRTP and sends FreeSWITCH plain RTP. Shell access to `fs_cli` is
  needed for T2 and T3.
- **FreeSBC host** with a public address (here `203.0.113.7`) and a
  private one on the FreeSWITCH LAN (here `10.77.0.2`). Build with
  `go build -o freesbc ./cmd/freesbc`.
- **A WSS certificate the browser trusts.** A browser cannot click through
  a certificate warning on a WebSocket. Use a real certificate for the
  SBC's hostname, or in a lab a `mkcert` certificate whose CA is installed
  in the browser's trust store.
- **A browser client:** `web-sip-phone`, or any sip.js page, registered as
  `1000` with server URL `wss://<sbc-hostname>:18443`. Leave reliable
  provisionals (100rel) unsupported or supported, never *required*:
  FreeSBC does not relay PRACK, so an INVITE with `Require: 100rel` is
  answered `420 Bad Extension` (sip.js: keep `sipExtension100rel` at its
  default, not `Required`). The browser must offer `a=rtcp-mux`; every
  current browser does by default (`rtcpMuxPolicy: "require"`).
- **Chrome or Chromium** for `chrome://webrtc-internals`. Firefox works
  for the call tests; its equivalent page is `about:webrtc`.
- UDP from the browser to the public RTP range (`30000-39999` below) must
  be open, and UDP between `10.77.0.2` and FreeSWITCH.
- Optional but recommended: an `admin:` section so the Prometheus metrics
  are readable (see below).

### Minimal `edge.yaml`

```yaml
network:
  public:
    bind_ip: 0.0.0.0
    advertised_ip: 203.0.113.7    # what the browser is told
  private:
    bind_ip: 10.77.0.2

sip:
  public:
    wss:
      enabled: true
      bind: 0.0.0.0:18443
      cert_file: /etc/freesbc/wss-cert.pem   # trusted by the browser
      key_file: /etc/freesbc/wss-key.pem
  private:
    bind: 10.77.0.2:5060
  upstream:
    address: 10.77.0.10:5060      # FreeSWITCH: a literal IP:port
    transport: udp

rtp:
  public:
    bind_ip: 0.0.0.0
    advertised_ip: 203.0.113.7
    port_min: 30000
    port_max: 39999
  private:
    bind_ip: 10.77.0.2
    port_min: 40000
    port_max: 49999

webrtc:
  enabled: true
  ice_mode: lite
  rtcp_mux: true
  # dtls_cert_file / dtls_key_file are optional; without them FreeSBC
  # makes one self-signed identity per process.

listen:
  media:
    rtp_timeout: 5m

admin:
  listen: 127.0.0.1:8080
  auth:
    username: admin
    password_hash: "<bcrypt hash, cost >= 10>"
```

Check the file, then run it:

```sh
./freesbc check -c edge.yaml
./freesbc run -c edge.yaml 2>&1 | tee freesbc.log
```

Do not set `peers:` or `listen.sip`: those turn on the trunk plane, and a
trunk listener without peers fails validation.

## What to watch

**Metrics.** Read them with
`curl -s -u admin:<pw> http://127.0.0.1:8080/metrics | grep -E 'freesbc_(active|webrtc|rtp)'`.

| Metric | Meaning |
|---|---|
| `freesbc_active_webrtc_sessions` | browser media sessions alive now (gauge) |
| `freesbc_active_media_sessions` | all anchored media sessions, WebRTC included (gauge) |
| `freesbc_active_sip_dialogs` | confirmed edge dialogs (gauge) |
| `freesbc_webrtc_ice_failure_total` | browser legs that never completed ICE, including legs closed before they were established (CANCEL, tab closed) |
| `freesbc_webrtc_dtls_failure_total` | browser legs whose DTLS handshake failed, **including a fingerprint mismatch** |
| `freesbc_rtp_packets_rx_total` / `_tx_total` | packets relayed, folded in when a session ends |
| `freesbc_media_ports_in_use` | RTP port pairs held across all pools: +2 per browser call |

`freesbc_media_ports_in_use` / `_total` count RTP port pairs across every
pool, the edge's public and private ones included. A browser call holds
one pair in each, so `freesbc_media_ports_in_use` rises by 2 per call and
must return to its baseline afterwards. `ss` (below) shows the same from
the kernel's side.

**Log lines** (slog text on stderr, default level Info):

| Line | Meaning |
|---|---|
| `level=INFO msg="webrtc media established" media_session_id=… rtp_public_port=… rtp_private_port=…` | ICE and DTLS finished, the fingerprint matched, and the relay is running |
| `level=WARN msg="webrtc leg failed" err="media: ice failed: …"` | the browser never completed ICE |
| `level=WARN msg="webrtc leg failed" err="media: dtls handshake failed: …"` | the DTLS handshake failed for another reason |
| `level=WARN msg="webrtc leg failed" err="media: dtls peer certificate does not match the signalled fingerprint: …"` | the fingerprint check failed inside the handshake (T5) |
| `level=WARN msg="webrtc leg failed" err="media: webrtc session closed before establishment"` (or `…leg closed before it was established`) | the call ended while ICE/DTLS was still running (T6) |
| `level=INFO msg="call ended" sip_call_id=… stats=…` | the dialog ended and its media counters were folded in |
| `level=WARN msg="rejecting call: media setup failed" err=…` | the browser's offer was refused with 488 before any media was set up, for example an offer without `a=rtcp-mux` |

Neither fingerprint and no ICE password is ever logged. Lines starting
`ice ERROR` come from pion's own logger. `Failed to read UDP packet: … use
of closed network connection` after a leg closes is expected noise.

**Sockets.** Every browser leg holds one UDP socket in the public RTP range
and a pair in the private range:

```sh
ss -uanp 'sport >= :30000 and sport <= :39999' | grep -c freesbc   # public WebRTC legs
ss -uanp 'sport >= :40000 and sport <= :49999' | grep -c freesbc   # private RTP/RTCP (2 per call)
```

**Stopping FreeSBC.** Stop it only between cases, with no call up. On
the edge plane, shutdown (SIGINT/SIGTERM) ends every call's media but
sends no BYE, by design (`docs/design.md` §4.5): a browser still in a
call only sees its audio stop. That is not a regression. The trunk plane
does BYE its calls on shutdown, but this runbook does not use it.

**Goroutines.** FreeSBC does not export a goroutine count. The #16 leak
left pion ICE goroutines behind while the port was released correctly, so
`ss` alone cannot show it. For T6, end the run with `kill -QUIT <pid>`,
which makes the Go runtime dump every goroutine to stderr **and exits the
process**, then count the ICE goroutines:

```sh
kill -QUIT "$(pgrep -f 'freesbc run')"
grep -c 'github.com/pion/ice' freesbc.log
```

With no call up, the count must be 0.

**Browser.** Open `chrome://webrtc-internals` **before** placing the call,
then expand the `RTCPeerConnection` entry for the call:

- `iceConnectionState` → `connected` (or `completed`), and
  `connectionState` → `connected`.
- The `transport` stats: `dtlsState: connected`, `tlsVersion` DTLS 1.2
  (`FEFD`), `srtpCipher: AES_CM_128_HMAC_SHA1_80` (or `_32`), and
  `selectedCandidatePairId` set.
- The selected candidate pair: the remote candidate is
  `203.0.113.7:<port in 30000-39999>`, type `host`, and `state: succeeded`.
  It is never a FreeSWITCH or `10.77.0.x` address.
- `remote-certificate`: its `fingerprint` equals the `a=fingerprint` in the
  SBC's answer (the event log's `setRemoteDescription` shows the SDP).
- `inbound-rtp` (audio): `packetsReceived` and `bytesReceived` keep rising,
  and `audioLevel` is non-zero while audio plays. `outbound-rtp`:
  `packetsSent` keeps rising.
- The remote SDP has `a=ice-lite`, exactly one `a=candidate` of type
  `host`, `a=setup:passive` (or `active` if the browser offered `passive`),
  and `a=rtcp-mux`.

## Test cases

Before each case, note `freesbc_active_webrtc_sessions`, the two `ss`
counts and both failure counters. Unless a case says otherwise, every
gauge and socket count must return to that baseline within a few seconds
of the call ending.

### T1: browser registers and calls FreeSWITCH, audio both ways

1. Start FreeSBC with `edge.yaml`. Open `chrome://webrtc-internals` in
   another tab.
2. In the browser client, register as `1000`.
   **Expected:** the client shows registered. In `fs_cli`,
   `sofia status profile internal reg` lists `1000` with a Contact at the
   SBC's private address (`10.77.0.2`) carrying an `fsbc=` token.
3. Dial `9196` (echo).
   **Expected:** the call is answered. The log shows
   `webrtc media established` within a second or two of the answer, and
   `freesbc_active_webrtc_sessions` is 1. `ss` shows one more public
   socket and two more private sockets than the baseline.
4. Speak into the microphone.
   **Expected:** you hear yourself with a short delay. In
   webrtc-internals, `inbound-rtp` and `outbound-rtp` both count up, and
   `dtlsState` is `connected`.
5. Check the browser-side facts listed under **Browser** above: the
   selected pair, the remote certificate fingerprint, and the cipher.
6. Hang up from the browser.
   **Expected:** the log shows `call ended` with non-zero RTP counts for
   both sides in `stats` (`A` is the browser, `B` FreeSWITCH). The gauges
   and sockets return to baseline, and neither failure counter moved.

Repeat step 3 with `9664` (music on hold): music must play continuously,
with no gap after the first second (a gap would mean the relay started
late).

### T2: FreeSWITCH calls the browser

1. With `1000` registered, in `fs_cli` run
   `originate user/1000 &playback(local_stream://moh)`, or
   `originate user/1000 9196 XML default` for echo.
2. **Expected:** the browser rings. FreeSWITCH's INVITE reaches it
   through the SBC, and the offer the browser sees has `a=ice-lite`, one
   host candidate at `203.0.113.7`, and the SBC's fingerprint.
3. Answer in the browser.
   **Expected:** `webrtc media established` in the log, music (or echo)
   plays, and webrtc-internals shows the same state as T1 step 4.
4. Hang up from the browser.
   **Expected:** everything returns to baseline and the failure counters
   are unchanged.

### T3: re-INVITE and hold during the call

1. Call `9196` from the browser as in T1, and confirm echo.
2. Put the call on hold from the browser client (sip.js sends a re-INVITE
   with `a=sendonly`).
   **Expected:** a 200 OK comes back and the echo stops. In
   webrtc-internals there is **no** new DTLS handshake: `dtlsState` stays
   `connected`, and the ICE ufrag and the remote fingerprint in the new
   remote description are unchanged. The `ss` counts are unchanged, and
   the log has no new `webrtc media established` line.
3. Take the call off hold.
   **Expected:** echo resumes within about a second, on the same
   candidate pair.
4. Now let FreeSWITCH drive it. In `fs_cli`, find the call with
   `show channels`, then run `uuid_hold <uuid>` and, a few seconds later,
   `uuid_hold off <uuid>`.
   **Expected:** the browser accepts both re-INVITEs, and audio stops
   and resumes. The ICE credentials, fingerprint and DTLS role in the
   SBC's re-offer to the browser equal the ones in the original
   exchange.
5. Hang up. **Expected:** everything returns to baseline.

### T4: hang-up from each side

1. Call `9196` from the browser, then hang up from the **browser**.
   **Expected:** FreeSWITCH gets a BYE (`show channels` empties), the log
   shows `call ended`, and everything returns to baseline.
2. Call `9196` again. In `fs_cli`, run `uuid_kill <uuid>` (or
   `hupall`) so **FreeSWITCH** hangs up.
   **Expected:** the browser gets a BYE and shows the call ended, the log
   shows `call ended`, and everything returns to baseline.
3. Call `9196` again, then close the browser **tab** while the call is up.
   **Expected:** there is no BYE from the browser. Media stops, so after
   `listen.media.rtp_timeout` (5 minutes here; set `rtp_timeout: 30s` to
   shorten the test) the silence watchdog ends the call. FreeSWITCH gets
   a BYE, and everything returns to baseline.

### T5 (negative): mismatched fingerprint fails before any media

The browser's DTLS certificate must match the `a=fingerprint` in its
offer. With this change, FreeSBC checks it **inside** the DTLS handshake,
so a mismatch fails the handshake and nothing is relayed, not even the
first packets.

A browser will not sign a certificate that doesn't match its own SDP, so
tamper with the offer on the wire, after `setLocalDescription`. Do it in
the browser client's tab, in the devtools console, **before** registering:

```js
// Flip the first byte of the fingerprint in outgoing INVITEs. The length
// is unchanged, so Content-Length stays valid.
(() => {
  const send = WebSocket.prototype.send;
  WebSocket.prototype.send = function (data) {
    if (typeof data === 'string' && data.startsWith('INVITE ')) {
      data = data.replace(/(a=fingerprint:sha-256 )([0-9A-Fa-f]{2})/,
        (_, p, b) => p + (b.toUpperCase() === '00' ? '01' : '00'));
      console.log('fingerprint tampered');
    }
    return send.call(this, data);
  };
})();
```

(A single-page client that creates its WebSocket before you can paste
this needs a reload with the snippet in a devtools **Snippet** or a
local override. A TLS-intercepting proxy such as mitmproxy, rewriting the
same line, works too.)

1. Note both failure counters and `freesbc_rtp_packets_tx_total`. On the
   FreeSBC host, start
   `tcpdump -ni any 'udp and src host 10.77.0.2 and dst host 10.77.0.10 and portrange 40000-49999'`.
   This captures RTP from the SBC to FreeSWITCH.
2. Paste the snippet, register, and dial `9664`.
   **Expected:** the console prints `fingerprint tampered`, and signaling
   succeeds (the call is answered, because FreeSWITCH knows nothing of
   DTLS).
3. **Expected within the establishment window:** the log shows
   `level=WARN msg="webrtc leg failed" err="media: dtls peer certificate does not match the signalled fingerprint: …"`,
   with no `webrtc media established` line for this call.
   `freesbc_webrtc_dtls_failure_total` has risen by 1 and
   `freesbc_webrtc_ice_failure_total` has not. In webrtc-internals, ICE
   reaches `connected` but `dtlsState` goes to `failed` (Chrome may show
   `connectionState: failed`), and `inbound-rtp` never appears or stays
   at 0 packets.
4. **Expected:** the `tcpdump` from step 1 shows **no** packets for this
   call: FreeSBC relayed nothing to FreeSWITCH. (FreeSWITCH's own RTP
   toward the SBC, in the other direction, is not captured by this filter
   and is irrelevant.)
5. **Expected:** the call is torn down. Both ends get a BYE once the
   dialog is confirmed, and everything returns to baseline.
6. Reload the tab (the snippet is gone) and repeat T1 to confirm the
   untampered path still works.

If the snippet cannot be applied in your client, record T5 as "not run
manually". The unit tests `TestAuditMED002MediaFlowsBeforeFingerprintVerified`,
`TestAuditMED002HandshakeRejectsMismatchedFingerprint` and
`TestAuditMED002MediaFlowsOnlyAfterVerify` in `internal/media` cover it
with a pion-based browser.

### T6: tab closed or call cancelled during ICE/DTLS establishment (#16)

On a browser→FreeSWITCH call, FreeSBC allocates the WebRTC leg and starts
ICE/DTLS when the INVITE arrives, but the browser learns the SBC's ICE
credentials only from FreeSWITCH's answer. The whole ringing period is
therefore the "establishing" window that #16 leaked in.

Make FreeSWITCH ring without answering. A test extension works:

```xml
<extension name="ring_forever">
  <condition field="destination_number" expression="^9999$">
    <action application="ring_ready"/>
    <action application="sleep" data="60000"/>
    <action application="answer"/>
    <action application="playback" data="local_stream://moh"/>
  </condition>
</extension>
```

Dialling an unregistered directory user also rings until the timeout.

1. Record the baseline: the two `ss` counts,
   `freesbc_active_webrtc_sessions`, `freesbc_active_media_sessions` and
   `freesbc_webrtc_ice_failure_total`.
2. **Cancel during ringing.** Dial `9999`, and while it rings, hang up
   from the browser (sip.js sends CANCEL).
   **Expected:** the 487 reaches the browser. Within about a second, the
   log shows `webrtc leg failed` with `…closed before …established`, the
   ICE failure counter rises by 1, and the gauges and `ss` counts are
   back at baseline.
3. **Close the tab during ringing.** Dial `9999`, then close the browser
   tab while it rings.
   **Expected:** the same as step 2 once FreeSBC ends the INVITE. At the
   latest, the 30 s establishment deadline releases the public socket even
   if the INVITE is still pending. The private pair is released when the
   INVITE ends; when FreeSWITCH gives up, the 5-minute INVITE backstop
   CANCELs.
4. **Close the tab during the DTLS handshake itself.** This window is
   short, so widen it: on the browser machine, block UDP to the SBC's
   public RTP range. For example, on Linux:
   `sudo iptables -I OUTPUT -p udp -d 203.0.113.7 --dport 30000:39999 -j DROP`.
   Then dial `9196`. The call is answered but ICE cannot complete. Close
   the tab within a few seconds, then remove the rule
   (`sudo iptables -D OUTPUT …`).
   **Expected:** after the dialog ends (BYE, or the watchdog), or at the
   latest the 30 s establishment deadline, the public and private sockets
   are released. `freesbc_active_webrtc_sessions` returns to baseline.
5. Repeat steps 2 and 3 about 20 times (a script driving sip.js is fine).
   **Expected:** the `ss` counts and gauges return to baseline after every
   iteration, and FreeSBC's RSS (`ps -o rss= -p <pid>`) stays flat across
   the iterations.
6. With no call up, dump the goroutines as described under **Goroutines**
   (this stops FreeSBC).
   **Expected:** `grep -c 'github.com/pion/ice' freesbc.log` is 0 and no
   goroutine stack mentions `media.(*WebRTCLeg).establish`. Before #16, a
   loop like this left about 6 pion ICE goroutines per cancelled leg.

## Recording results

For each case, record pass or fail, the metric deltas, the relevant log
lines (redact the Call-IDs if needed), and a webrtc-internals dump for T1
and T5 (the **Create Dump** button). Attach them to the PR that changed the
media path (for the #29/#16 change, which is already merged, comment on
issue #29), and note the versions from the table at the top.
