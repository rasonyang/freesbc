package edge

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/media"
	fsip "github.com/freesbc/freesbc/internal/sip"
	"github.com/freesbc/freesbc/internal/sip/sdp"
)

// mediaSession is one call's anchored media. Exactly one of rtp and webrtc
// is set: a plain SIP phone gets an RTP↔RTP relay, a browser gets a
// DTLS-SRTP leg on the public side.
//
// The two are kept as distinct types rather than hidden behind one
// interface because their packet paths genuinely differ — four sockets
// with symmetric latching versus one ICE-muxed socket — and an interface
// wide enough to cover both would have to expose that difference anyway.
// What they DO share is this wrapper's lifecycle contract, which is the
// part the signaling plane actually depends on.
type mediaSession struct {
	rtp    *media.Session
	webrtc *media.WebRTCSession

	// publicPort and privatePort are what the two SDP bodies advertise.
	publicPort  int
	privatePort int

	// mu guards codecs and applied, which the INVITE path, re-INVITEs from
	// either side and the logs all touch.
	mu sync.Mutex
	// codecs is the list negotiated for this call, for logs and metrics.
	codecs []sdp.Codec
	// applied is the media address each side was last pointed at from
	// signaling, indexed by plane. It is what tells an answer or re-offer
	// that MOVES a side's media (which re-arms the latch) from one that
	// restates it (which must not: re-latching mid-call drops audio).
	applied [2]netip.AddrPort

	closeOnce sync.Once
}

// negotiated is the codec list currently agreed for the call.
func (m *mediaSession) negotiated() []sdp.Codec {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.codecs
}

// setNegotiated records a newly agreed codec list.
func (m *mediaSession) setNegotiated(cs []sdp.Codec) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codecs = cs
}

// seedApplied records the address a side was seeded with at allocation.
func (m *mediaSession) seedApplied(p plane, addr netip.AddrPort) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.applied[p] = addr
}

// Close releases every socket, port reservation and relay goroutine.
// Idempotent.
func (m *mediaSession) Close() error {
	m.closeOnce.Do(func() {
		if m.rtp != nil {
			_ = m.rtp.Close()
		}
		if m.webrtc != nil {
			_ = m.webrtc.Close()
		}
	})
	return nil
}

// Done is closed when the media session ends — including by its own
// silence watchdog, which is how a call whose signaling was lost still
// gets reclaimed.
func (m *mediaSession) Done() <-chan struct{} {
	if m.webrtc != nil {
		return m.webrtc.Done()
	}
	return m.rtp.Done()
}

// Stats returns the session's packet counters.
func (m *mediaSession) Stats() media.Stats {
	if m.webrtc != nil {
		return m.webrtc.Stats()
	}
	return m.rtp.Stats()
}

// IsWebRTC reports whether the public leg is a browser leg.
func (m *mediaSession) IsWebRTC() bool { return m.webrtc != nil }

// rtpLeg returns the plain RTP↔RTP relay behind this session. It fails
// when the session is a browser leg instead, so a caller whose correctness
// rests on "this leg is never WebRTC" states that invariant and has it
// checked rather than dereferencing a nil.
func (m *mediaSession) rtpLeg() (*media.Session, error) {
	if m.rtp == nil {
		return nil, errors.New("proxy: expected a plain RTP session, got a WebRTC leg")
	}
	return m.rtp, nil
}

// offerResult is what buildUpstreamOffer produces: the SDP to send on and
// the dialog it belongs to.
type offerResult struct {
	// dialog owns the media session this offer allocated, the o= identity
	// its bodies are built with and the answer already sent. The offer
	// result itself is per-exchange; the dialog outlives it.
	dialog *dialog

	sdp []byte
	// offer is the parsed offer this exchange is answering — the public
	// client's for an outbound call, FreeSWITCH's for an inbound one. It
	// is retained so the answer can be built with the same media-section
	// count (RFC 3264 §6) and intersected against the right codec list.
	offer *sdp.Session
}

// sess is the media session this exchange is negotiating for.
func (o *offerResult) sess() *mediaSession { return o.dialog.session() }

var (
	// errNoUsableCodec maps to 488: the two sides share no codec and
	// FreeSBC does not transcode.
	errNoUsableCodec = errors.New("proxy: no usable codec in common")
	// errRenumbered maps to 488 as well: an answerer that renumbered a
	// payload type would need every RTP packet's PT byte rewritten, which
	// is transcoding-adjacent work this phase does not do.
	errRenumbered = errors.New("proxy: answer renumbered a payload type")
)

// negotiateError maps an sdp.Negotiate failure onto the proxy's own two
// sentinels, which rejectMedia turns into a 488.
func negotiateError(err error) error {
	if errors.Is(err, sdp.ErrRenumbered) {
		return fmt.Errorf("%w: %v", errRenumbered, err)
	}
	return fmt.Errorf("%w: %v", errNoUsableCodec, err)
}

// buildUpstreamOffer takes a public client's offer and produces the plain
// RTP offer FreeSWITCH will see, allocating the media session behind it.
//
// The upstream body is CONSTRUCTED, never derived: nothing is copied from
// the public offer except the negotiated codec list. That is what makes
// "do not pass browser ICE candidates to FreeSWITCH" and "FreeSWITCH never
// learns the public endpoint's address" structural properties rather than
// a list of attributes someone remembered to strip.
func (s *Server) buildUpstreamOffer(ctx context.Context, d *dialog, offerBody []byte) (*offerResult, error) {
	offer, err := s.parseSDP(offerBody)
	if err != nil {
		return nil, fmt.Errorf("proxy: public offer: %w", err)
	}
	codecs := filterCodecs(offer.Audio.Codecs)
	if !sdp.HasMedia(codecs) {
		return nil, fmt.Errorf("%w: client offered %s", errNoUsableCodec, sdp.Describe(offer.Audio.Codecs))
	}

	var sess *mediaSession
	if offer.Audio.WebRTC() {
		if !s.webrtcEnabled {
			return nil, errors.New("proxy: a WebRTC offer arrived but webrtc.enabled is false")
		}
		if err := requireRTCPMux(offer); err != nil {
			return nil, err
		}
		sess, err = s.allocateWebRTC(ctx, offer)
	} else {
		sess, err = s.allocateRTP(offer)
	}
	if err != nil {
		return nil, err
	}
	sess.codecs = codecs
	// From here the session belongs to the dialog: every failure below
	// leaves it to the dialog's own end(), which is the single teardown.
	d.attach(sess)

	// A fresh session identity: the upstream body is FreeSBC's own offer,
	// not a relay of the client's, so it must not reuse the client's o=
	// line (which would leak the client's session id and, in some stacks,
	// its address).
	id, version := d.nextOrigin(planePrivate)
	body, err := sdp.Build{
		Address:        s.topo.privateMediaIP,
		Port:           sess.privatePort,
		Codecs:         codecs,
		Direction:      offer.Audio.Direction,
		SessionID:      id,
		SessionVersion: version,
	}.Marshal()
	if err != nil {
		return nil, fmt.Errorf("proxy: build upstream offer: %w", err)
	}
	return &offerResult{dialog: d, sdp: body, offer: offer}, nil
}

// allocateRTP builds the RTP↔RTP session for a plain SIP phone: side A in
// the public plane, side B in the private one.
func (s *Server) allocateRTP(offer *sdp.Session) (*mediaSession, error) {
	sess, err := media.AllocateAcross(s.pubPool, s.privPool, media.SessionConfig{
		// Loose latching on the PUBLIC leg (media.LatchLoose, the config
		// name for "symmetric RTP"): a phone behind a hard NAT cannot be
		// trusted to signal the source address its RTP actually comes from
		// — some put an unroutable fake IP in c=/Via and send from the
		// NATed one — so the first inbound packet from any source is
		// accepted and fixes the send-destination to the real source. The
		// SDP-seeded address still carries outbound audio until that first
		// packet arrives (see latch.seed). The PRIVATE leg stays strict:
		// FreeSWITCH's signalled address over wg0 is trustworthy, and
		// strict mode already tolerates a NAT-rewritten port.
		Latch: [2]media.LatchMode{media.LatchLoose, media.LatchStrict},
	})
	if err != nil {
		return nil, err
	}
	// Seed the public side from the client's own offer so audio can flow
	// toward it immediately; its first packet still corrects the port
	// (symmetric RTP through NAT).
	remote := netip.AddrPortFrom(offer.Audio.Address, uint16(offer.Audio.Port))
	sess.SetRemote(media.SideA, remote)
	if offer.Audio.RTCPPort > 0 {
		sess.SetRTCPRemote(media.SideA, netip.AddrPortFrom(offer.Audio.Address, uint16(offer.Audio.RTCPPort)))
	}
	ms := &mediaSession{
		rtp:         sess,
		publicPort:  sess.RTPPort(media.SideA),
		privatePort: sess.RTPPort(media.SideB),
	}
	ms.seedApplied(planePublic, remote)
	return ms, nil
}

// parseSDP parses a body from either side under the edge's address
// policy: a loopback c= is accepted only when one of the SBC's own media
// planes advertises a loopback address (a single-host lab). The media
// pools apply the same policy per plane before sending anything.
func (s *Server) parseSDP(body []byte) (*sdp.Session, error) {
	return sdp.ParseWithOptions(body, sdp.ParseOptions{
		AllowLoopback: s.topo.publicMediaIP.IsLoopback() || s.topo.privateMediaIP.IsLoopback(),
	})
}

// allocateWebRTC builds the browser leg and its private RTP pair, and
// starts ICE/DTLS in the background so the SDP answer can go out
// immediately — the browser cannot begin its connectivity checks until it
// has our ICE credentials, so waiting here would deadlock.
func (s *Server) allocateWebRTC(ctx context.Context, offer *sdp.Session) (*mediaSession, error) {
	a := offer.Audio
	cfg := media.WebRTCLegConfig{
		AdvertisedIP: s.topo.publicMediaIP,
		RemoteUfrag:  a.ICEUfrag,
		RemotePwd:    a.ICEPwd,
		RemoteSetup:  a.Setup,
		Identity:     s.identity,
	}
	// The a=fingerprint is checked inside the DTLS handshake, so a peer
	// with the wrong certificate never gets a media path at all.
	if a.Fingerprint != nil {
		cfg.RemoteFingerprintHash = a.Fingerprint.Hash
		cfg.RemoteFingerprintValue = a.Fingerprint.Value
	}
	leg, err := media.NewWebRTCLeg(s.pubPool, cfg)
	if err != nil {
		return nil, err
	}
	sess, err := media.NewWebRTCSession(leg, s.privPool, media.WebRTCSessionConfig{
		PrivateLatch: media.LatchStrict,
		Log:          s.log,
	})
	if err != nil {
		_ = leg.Close()
		return nil, err
	}
	// Establishment runs on its own context, not the request's: the
	// INVITE transaction finishes as soon as the answer is sent, long
	// before the browser has finished ICE.
	leg.Start(context.WithoutCancel(ctx), 0)
	fingerprint := a.Fingerprint
	go func() {
		if err := sess.Start(context.Background()); err != nil {
			s.log.Warn("webrtc leg failed", "err", err)
			s.metrics.WebRTCFailure(err)
			return
		}
		// The a=fingerprint from signaling is the only thing binding the
		// DTLS peer to the call. The handshake already refused a
		// mismatched peer (sess.Start then fails with
		// ErrFingerprintMismatch); this re-check is defence in depth, and
		// the relay carries no media for a leg that was never verified.
		if fingerprint != nil {
			if err := leg.VerifyFingerprint(fingerprint.Hash, fingerprint.Value); err != nil {
				// The message deliberately does not echo either
				// fingerprint: one is attacker-supplied and the other is
				// our own identity.
				s.log.Warn("webrtc peer certificate does not match the signalled fingerprint; tearing down media", "err", err)
				s.metrics.WebRTCFailure(err)
				_ = sess.Close()
				return
			}
		}
		s.log.Info("webrtc media established",
			"media_session_id", sess.PublicPort(),
			"rtp_public_port", sess.PublicPort(),
			"rtp_private_port", sess.PrivateRTPPort())
	}()
	return &mediaSession{
		webrtc:      sess,
		publicPort:  sess.PublicPort(),
		privatePort: sess.PrivateRTPPort(),
	}, nil
}

// forkAnswer returns the body the caller is sent with one response of a
// forwarded INVITE, negotiating it the first time the response's fork (its
// To tag) sends a body.
//
// Every fork's answer is its own (RFC 3264 §6): negotiated against the
// ORIGINAL offer — never against a previous fork's agreement, whose narrow
// taste must not cost this one its codecs — built with the fork's own o=
// identity, and restated byte for byte whenever the same fork repeats it.
// Whichever fork's answer was seen last is the one the anchored media
// follows, so a 2xx from a fork that is not the one ringing re-points the
// media to the address it signalled.
//
// A nil body with a nil error means there is nothing to put in the relayed
// response (a body-less provisional).
func (s *Server) forkAnswer(l *inviteLeg, res *sip.Response) ([]byte, error) {
	d := l.dialog()
	f := d.fork(fsip.ToTag(res))
	if prev := d.forkAnswer(f); prev != nil {
		// A restated answer (the 200 echoing a body-bearing 183, say): the
		// body this fork already has — re-negotiating would re-latch media
		// under it.
		s.followFork(l, f)
		return prev, nil
	}
	if len(res.Body()) == 0 {
		if res.StatusCode/100 != 2 {
			return nil, nil
		}
		// A body-less 2xx on a fork that never answered. A far end that
		// answered in one early dialog and confirmed in another without
		// restating (the To tag of a 183 and a 200 need not match) means
		// the answer the media already follows.
		if a := d.lastApplied(); a != nil {
			return d.forkAnswer(a), nil
		}
		return nil, errNoAnswer
	}
	return s.negotiateFork(l, f, res.Body())
}

// negotiateFork negotiates one fork's answer, points the media at it and
// builds the caller's body.
func (s *Server) negotiateFork(l *inviteLeg, f *earlyFork, answerBody []byte) ([]byte, error) {
	answer, err := s.parseSDP(answerBody)
	if err != nil {
		return nil, fmt.Errorf("proxy: answer: %w", err)
	}
	offer := l.offer.offer
	agreed, err := sdp.Negotiate(filterCodecs(offer.Audio.Codecs), answer.Audio.Codecs)
	if err != nil {
		return nil, negotiateError(err)
	}
	sess := l.offer.sess()
	if l.callee != calleeUpstream {
		// A client or carrier leg is always the plain RTP relay (an inbound
		// call is never offered to a browser as WebRTC) — checked rather
		// than assumed, because reaching into the wrong leg would be a nil
		// dereference on the call path.
		if _, err := sess.rtpLeg(); err != nil {
			return nil, err
		}
	}
	remote := netip.AddrPortFrom(answer.Audio.Address, uint16(answer.Audio.Port))
	var rtcp netip.AddrPort
	if answer.Audio.RTCPPort > 0 {
		rtcp = netip.AddrPortFrom(answer.Audio.Address, uint16(answer.Audio.RTCPPort))
	}

	d := l.dialog()
	callerPlane := planePublic
	if l.callee.calleePlane() == planePublic {
		callerPlane = planePrivate
	}
	addr, port := s.anchorFor(sess, callerPlane)
	id, version := d.nextForkOrigin(f)
	build := sdp.Build{
		Address:        addr,
		Port:           port,
		Codecs:         agreed,
		Direction:      answer.Audio.Direction,
		SessionID:      id,
		SessionVersion: version,
	}
	if callerPlane == planePublic && sess.webrtc != nil {
		s.setWebRTCAnswer(&build, sess.webrtc.Leg())
	}
	body, err := build.MarshalDeclining(offer)
	if err != nil {
		return nil, err
	}
	d.setForkAnswer(f, body, agreed, remote, rtcp)
	s.followFork(l, f)
	return body, nil
}

// followFork points the callee-facing media side at the address a fork's
// answer signalled, unless it already follows that fork.
func (s *Server) followFork(l *inviteLeg, f *earlyFork) {
	d := l.dialog()
	if d.lastApplied() == f {
		return
	}
	remote, rtcp, codecs := d.forkMedia(f)
	sess := l.offer.sess()
	s.pointMedia(sess, l.callee.calleePlane(), remote, rtcp)
	sess.setNegotiated(codecs)
	d.setApplied(f)
}

// pointMedia arms one side of the session with a media address signalled
// in SDP, and starts the plain RTP relay.
//
// Seeding the latch is what lets the side's first packet be accepted and
// gives the reverse direction a destination. When the side was already
// pointed somewhere else — another fork's answer, a failed gateway, a
// re-offer that moved the far end's port — the latch is re-armed first:
// once latched, an unsolicited packet cannot move it, and neither can a
// plain seed, so an authorised change of address has to say so. An answer
// that restates the address the side already follows leaves the latch
// alone.
func (s *Server) pointMedia(sess *mediaSession, p plane, remote, rtcp netip.AddrPort) {
	sess.mu.Lock()
	prev := sess.applied[p]
	sess.applied[p] = remote
	sess.mu.Unlock()
	moved := prev.IsValid() && prev != remote

	if sess.webrtc != nil {
		// The browser side is ICE's business, not SDP's; only the private
		// side follows signaling.
		if p == planePrivate {
			if moved {
				sess.webrtc.RelatchPrivate(remote)
			}
			sess.webrtc.SetPrivateRemote(remote)
		}
		return
	}
	side := media.SideB
	if p == planePublic {
		side = media.SideA
	}
	if moved {
		sess.rtp.Relatch(side, remote)
	}
	sess.rtp.SetRemote(side, remote)
	if rtcp.IsValid() {
		sess.rtp.SetRTCPRemote(side, rtcp)
	}
	// Start is idempotent: the first anchored answer starts the relay, and
	// every later one (another fork, another gateway) is a no-op.
	sess.rtp.Start()
}

// buildPublicOffer is the mirror of buildUpstreamOffer for a call coming
// FROM FreeSWITCH: the private body is the offer, and the client sees a
// constructed public one.
//
// The public leg cannot be WebRTC here: a DTLS-SRTP offer requires the
// answerer's fingerprint and ICE credentials to be known, and an offer by
// definition has not seen them. Browser-terminated inbound calls are
// therefore relayed as... they are not: FreeSBC offers plain RTP to a UDP
// phone and, for a WebSocket client, still offers plain RTP — which a
// browser will reject. That limitation is documented in the README and is
// what a future re-INVITE/offerless-INVITE path would address.
func (s *Server) buildPublicOffer(d *dialog, offerBody []byte) (*offerResult, error) {
	offer, err := s.parseSDP(offerBody)
	if err != nil {
		return nil, fmt.Errorf("proxy: upstream offer: %w", err)
	}
	codecs := filterCodecs(offer.Audio.Codecs)
	if !sdp.HasMedia(codecs) {
		return nil, fmt.Errorf("%w: upstream offered %s", errNoUsableCodec, sdp.Describe(offer.Audio.Codecs))
	}
	sess, err := media.AllocateAcross(s.pubPool, s.privPool, media.SessionConfig{
		// Same policy as allocateRTP: the public leg (the answering phone)
		// latches loosely so a hard-NAT phone's real RTP source — which
		// may differ from the IP it signalled — is what fixes the
		// send-destination; the private FreeSWITCH leg stays strict.
		Latch: [2]media.LatchMode{media.LatchLoose, media.LatchStrict},
	})
	if err != nil {
		return nil, err
	}
	// The upstream offer is on side B (private).
	remote := netip.AddrPortFrom(offer.Audio.Address, uint16(offer.Audio.Port))
	sess.SetRemote(media.SideB, remote)
	if offer.Audio.RTCPPort > 0 {
		sess.SetRTCPRemote(media.SideB, netip.AddrPortFrom(offer.Audio.Address, uint16(offer.Audio.RTCPPort)))
	}
	ms := &mediaSession{
		rtp:         sess,
		publicPort:  sess.RTPPort(media.SideA),
		privatePort: sess.RTPPort(media.SideB),
		codecs:      codecs,
	}
	ms.seedApplied(planePrivate, remote)
	// From here the session belongs to the dialog: every failure below
	// leaves it to the dialog's own end(), which is the single teardown.
	d.attach(ms)
	id, version := d.nextOrigin(planePublic)
	body, err := sdp.Build{
		Address:        s.topo.publicMediaIP,
		Port:           ms.publicPort,
		Codecs:         codecs,
		Direction:      offer.Audio.Direction,
		SessionID:      id,
		SessionVersion: version,
	}.Marshal()
	if err != nil {
		return nil, err
	}
	return &offerResult{dialog: d, sdp: body, offer: offer}, nil
}

// anchorFor is the address and port this session presents on one plane —
// what a body built toward that plane must advertise. It is what keeps a
// re-negotiation on the ports it already holds: nothing here allocates.
func (s *Server) anchorFor(m *mediaSession, p plane) (netip.Addr, int) {
	if p == planePublic {
		return s.topo.publicMediaIP, m.publicPort
	}
	return s.topo.privateMediaIP, m.privatePort
}

// requireRTCPMux refuses a browser offer without a=rtcp-mux. The WebRTC
// leg is a single ICE component carrying RTP and RTCP together, so every
// body toward the browser states a=rtcp-mux; an answer may do that only
// when its offer did (RFC 5761 §5.1.1), so a non-mux offer is rejected
// (488) rather than answered with an attribute it did not offer.
func requireRTCPMux(offer *sdp.Session) error {
	if !offer.Audio.RTCPMux {
		return errors.New("proxy: WebRTC offer without a=rtcp-mux; only muxed RTCP is supported")
	}
	return nil
}

// setWebRTCAnswer fills in the browser-facing half of a body: the ICE-Lite
// credentials, the DTLS role and FreeSBC's own fingerprint.
//
// Every in-dialog body toward the browser — the answer to its re-offer and
// a re-offer FreeSWITCH makes to it — must restate exactly these values:
// changing any of them would look like an ICE restart or a new DTLS
// association and tear down the media path the session is still using.
// That is why the initial answer and every in-dialog body are built by the
// same function rather than side by side.
func (s *Server) setWebRTCAnswer(build *sdp.Build, leg *media.WebRTCLeg) {
	ufrag, pwd := leg.LocalCredentials()
	build.DTLS, build.RTCPMux = true, true
	build.ICEUfrag, build.ICEPwd = ufrag, pwd
	build.Setup = leg.DTLSSetup()
	build.Fingerprint = &sdp.Fingerprint{
		Hash:  s.identity.FingerprintHash,
		Value: s.identity.FingerprintValue,
	}
}

// rebuildInDialogOffer rewrites a re-INVITE's offer body for the far side.
//
// This exists because forwarding an in-dialog body unchanged would hand
// each side the other's media address MID-CALL — the anchor would simply
// fall away on the first hold, unhold or session-timer refresh, and for a
// browser the body would carry its ICE candidates and DTLS fingerprint
// straight to FreeSWITCH. Like the initial offer, the outgoing body is
// CONSTRUCTED rather than derived; unlike it, nothing is allocated: the
// session keeps the ports it already holds.
//
// Codec changes ARE conveyed (the offerer's list, filtered to what the
// proxy relays, with its payload numbers), so a re-offer that drops or
// adds a codec still works without transcoding.
func (s *Server) rebuildInDialogOffer(d *dialog, body []byte, toward plane) ([]byte, *sdp.Session, error) {
	offer, err := s.parseSDP(body)
	if err != nil {
		return nil, nil, fmt.Errorf("proxy: in-dialog offer: %w", err)
	}
	codecs := filterCodecs(offer.Audio.Codecs)
	if !sdp.HasMedia(codecs) {
		return nil, nil, fmt.Errorf("%w: re-offer had %s", errNoUsableCodec, sdp.Describe(offer.Audio.Codecs))
	}
	sess := d.session()
	if toward == planePrivate && sess.webrtc != nil {
		// The browser's re-offer is answered with the same a=rtcp-mux the
		// initial answer carried, which RFC 5761 §5.1.1 allows only when
		// the offer has it too.
		if err := requireRTCPMux(offer); err != nil {
			return nil, nil, err
		}
	}
	addr, port := s.anchorFor(sess, toward)
	id, version := d.nextOrigin(toward)
	build := sdp.Build{
		Address: addr,
		Port:    port,
		Codecs:  codecs,
		// The direction passes through unreversed: FreeSBC is a relay in
		// the middle, so a caller putting the call on hold (sendonly) must
		// present as sendonly to the far end too.
		Direction:      offer.Audio.Direction,
		SessionID:      id,
		SessionVersion: version,
	}
	if toward == planePublic && sess.webrtc != nil {
		// A re-offer toward a browser describes the SAME DTLS-SRTP stream:
		// the profile, ICE-Lite credentials, fingerprint and the DTLS role
		// already in use (RFC 5763 §5, RFC 8842 §5.3). A plain RTP/AVP
		// re-offer would be refused, or taken as a request to drop the
		// secure transport.
		s.setWebRTCAnswer(&build, sess.webrtc.Leg())
	}
	out, err := build.Marshal()
	if err != nil {
		return nil, nil, fmt.Errorf("proxy: build in-dialog offer: %w", err)
	}
	return out, offer, nil
}

// rebuildInDialogAnswer rewrites the answer to a re-INVITE for the near
// side, and records the newly agreed codec list on the session. It also
// returns the far end's answer as parsed, for the media update the 2xx
// applies.
func (s *Server) rebuildInDialogAnswer(d *dialog, offer *sdp.Session, body []byte, toward plane) ([]byte, *sdp.Session, error) {
	answer, err := s.parseSDP(body)
	if err != nil {
		return nil, nil, fmt.Errorf("proxy: in-dialog answer: %w", err)
	}
	agreed, err := sdp.Negotiate(filterCodecs(offer.Audio.Codecs), answer.Audio.Codecs)
	if err != nil {
		return nil, nil, negotiateError(err)
	}
	sess := d.session()
	sess.setNegotiated(agreed)

	addr, port := s.anchorFor(sess, toward)
	id, version := d.nextOrigin(toward)
	build := sdp.Build{
		Address:        addr,
		Port:           port,
		Codecs:         agreed,
		Direction:      answer.Audio.Direction,
		SessionID:      id,
		SessionVersion: version,
	}
	if toward == planePublic && sess.webrtc != nil {
		s.setWebRTCAnswer(&build, sess.webrtc.Leg())
	}
	out, err := build.MarshalDeclining(offer)
	if err != nil {
		return nil, nil, err
	}
	return out, answer, nil
}
