package edge

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"github.com/freesbc/freesbc/internal/media"
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

	// codecs is the list negotiated for this call, for logs and metrics.
	codecs []sdp.Codec

	closeOnce sync.Once
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
	offer, err := sdp.Parse(offerBody)
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
	id, version := d.nextOrigin()
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
	sess.SetRemote(media.SideA, netip.AddrPortFrom(offer.Audio.Address, uint16(offer.Audio.Port)))
	if offer.Audio.RTCPPort > 0 {
		sess.SetRTCPRemote(media.SideA, netip.AddrPortFrom(offer.Audio.Address, uint16(offer.Audio.RTCPPort)))
	}
	return &mediaSession{
		rtp:         sess,
		publicPort:  sess.RTPPort(media.SideA),
		privatePort: sess.RTPPort(media.SideB),
	}, nil
}

// allocateWebRTC builds the browser leg and its private RTP pair, and
// starts ICE/DTLS in the background so the SDP answer can go out
// immediately — the browser cannot begin its connectivity checks until it
// has our ICE credentials, so waiting here would deadlock.
func (s *Server) allocateWebRTC(ctx context.Context, offer *sdp.Session) (*mediaSession, error) {
	a := offer.Audio
	leg, err := media.NewWebRTCLeg(s.pubPool, media.WebRTCLegConfig{
		AdvertisedIP: s.topo.publicMediaIP,
		RemoteUfrag:  a.ICEUfrag,
		RemotePwd:    a.ICEPwd,
		RemoteSetup:  a.Setup,
		Identity:     s.identity,
	})
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
		// DTLS peer to the call. Verify it AFTER the handshake and drop
		// the session on a mismatch: without this check, anyone who could
		// answer the ICE checks could take over the media path.
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

// applyUpstreamAnswer processes FreeSWITCH's answer and produces the body
// the public client will see.
//
// Two things happen here that the call depends on: the private media latch
// is armed with the address FreeSWITCH signalled (so its first packet is
// accepted and the reverse direction gets a destination), and the codec
// list is intersected down to what both ends agreed on.
func (s *Server) applyUpstreamAnswer(res *offerResult, answerBody []byte, publicIsWebRTC bool) ([]byte, error) {
	answer, err := sdp.Parse(answerBody)
	if err != nil {
		return nil, fmt.Errorf("proxy: upstream answer: %w", err)
	}
	sess := res.sess()
	agreed, err := sdp.Negotiate(sess.codecs, answer.Audio.Codecs)
	if err != nil {
		return nil, negotiateError(err)
	}
	sess.codecs = agreed

	// Arm the private-side latch with the address FreeSWITCH will send
	// from. Until this happens the relay has nowhere to forward to and
	// (under strict latching) would reject FreeSWITCH's own packets.
	if sess.webrtc != nil {
		sess.webrtc.SetPrivateRemote(netip.AddrPortFrom(answer.Audio.Address, uint16(answer.Audio.Port)))
	} else {
		sess.rtp.SetRemote(media.SideB, netip.AddrPortFrom(answer.Audio.Address, uint16(answer.Audio.Port)))
		if answer.Audio.RTCPPort > 0 {
			sess.rtp.SetRTCPRemote(media.SideB, netip.AddrPortFrom(answer.Audio.Address, uint16(answer.Audio.RTCPPort)))
		}
		sess.rtp.Start()
	}

	id, version := res.dialog.nextOrigin()
	build := sdp.Build{
		Address:        s.topo.publicMediaIP,
		Port:           sess.publicPort,
		Codecs:         agreed,
		Direction:      answer.Audio.Direction,
		SessionID:      id,
		SessionVersion: version,
	}
	if publicIsWebRTC {
		s.setWebRTCAnswer(&build, sess.webrtc.Leg())
	}
	return build.MarshalDeclining(res.offer)
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
	offer, err := sdp.Parse(offerBody)
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
	sess.SetRemote(media.SideB, netip.AddrPortFrom(offer.Audio.Address, uint16(offer.Audio.Port)))
	if offer.Audio.RTCPPort > 0 {
		sess.SetRTCPRemote(media.SideB, netip.AddrPortFrom(offer.Audio.Address, uint16(offer.Audio.RTCPPort)))
	}
	ms := &mediaSession{
		rtp:         sess,
		publicPort:  sess.RTPPort(media.SideA),
		privatePort: sess.RTPPort(media.SideB),
		codecs:      codecs,
	}
	// From here the session belongs to the dialog: every failure below
	// leaves it to the dialog's own end(), which is the single teardown.
	d.attach(ms)
	id, version := d.nextOrigin()
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

// applyPublicAnswer processes the client's answer to an inbound call and
// produces the body FreeSWITCH will see.
func (s *Server) applyPublicAnswer(res *offerResult, answerBody []byte) ([]byte, error) {
	answer, err := sdp.Parse(answerBody)
	if err != nil {
		return nil, fmt.Errorf("proxy: public answer: %w", err)
	}
	sess := res.sess()
	agreed, err := sdp.Negotiate(sess.codecs, answer.Audio.Codecs)
	if err != nil {
		return nil, negotiateError(err)
	}
	sess.codecs = agreed
	sess.rtp.SetRemote(media.SideA, netip.AddrPortFrom(answer.Audio.Address, uint16(answer.Audio.Port)))
	if answer.Audio.RTCPPort > 0 {
		sess.rtp.SetRTCPRemote(media.SideA, netip.AddrPortFrom(answer.Audio.Address, uint16(answer.Audio.RTCPPort)))
	}
	sess.rtp.Start()

	id, version := res.dialog.nextOrigin()
	return sdp.Build{
		Address:        s.topo.privateMediaIP,
		Port:           sess.privatePort,
		Codecs:         agreed,
		Direction:      answer.Audio.Direction,
		SessionID:      id,
		SessionVersion: version,
	}.MarshalDeclining(res.offer)
}

// applyPSTNAnswer processes a PSTN carrier's answer (to the offer FreeSBC
// sent on behalf of a FreeSWITCH-bridged call) and produces the body
// FreeSWITCH will see.
//
// It deliberately does NOT Start the relay: a call may fail over across
// several gateways, each of which may answer once, and the pump guards the
// single Start with a sync.Once shared by every attempt. It also never
// touches the private leg's latch (Side B, FreeSWITCH-facing) — that
// address cannot change mid-call, and a re-latch there would race the
// packets FreeSWITCH is already sending.
//
// rePoint is the failover re-latch: when an earlier attempt already latched
// Side A to a gateway that failed, the latch would decline this attempt's
// answer as a hijack (SetRemote's seed is refused once latched). Relatch
// first re-arms the latch to the answering gateway's IP, so its media is
// accepted and its address becomes the new send target.
func (s *Server) applyPSTNAnswer(res *offerResult, answerBody []byte, rePoint bool) ([]byte, error) {
	answer, err := sdp.Parse(answerBody)
	if err != nil {
		return nil, fmt.Errorf("proxy: carrier answer: %w", err)
	}
	// Every attempt negotiates against the ORIGINAL offer FreeSWITCH made,
	// never the session's live codec list: the list is shrunk to each
	// previous attempt's agreement (below), and a failed gateway's narrow
	// taste must not cost the next gateway its codecs. The session list
	// stays in step afterwards so later relays describe what is agreed.
	base := filterCodecs(res.offer.Audio.Codecs)
	agreed, err := sdp.Negotiate(base, answer.Audio.Codecs)
	if err != nil {
		return nil, negotiateError(err)
	}
	// A carrier gateway is never a browser, so this leg is always the plain
	// RTP relay — checked rather than assumed, because reaching into the
	// wrong leg would be a nil dereference on the call path.
	sess := res.sess()
	rtp, err := sess.rtpLeg()
	if err != nil {
		return nil, err
	}
	sess.codecs = agreed
	if rePoint {
		rtp.Relatch(media.SideA, answer.Audio.Address)
	}
	rtp.SetRemote(media.SideA, netip.AddrPortFrom(answer.Audio.Address, uint16(answer.Audio.Port)))
	if answer.Audio.RTCPPort > 0 {
		rtp.SetRTCPRemote(media.SideA, netip.AddrPortFrom(answer.Audio.Address, uint16(answer.Audio.RTCPPort)))
	}
	id, version := res.dialog.nextOrigin()
	return sdp.Build{
		Address:        s.topo.privateMediaIP,
		Port:           sess.privatePort,
		Codecs:         agreed,
		Direction:      answer.Audio.Direction,
		SessionID:      id,
		SessionVersion: version,
	}.MarshalDeclining(res.offer)
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

// setWebRTCAnswer fills in the browser-facing half of an answer: the
// ICE-Lite credentials, the DTLS role and FreeSBC's own fingerprint.
//
// A re-INVITE's answer must restate exactly these values — changing any of
// them would look like an ICE restart and tear down the media path the
// session is still using — which is why the initial answer and the
// in-dialog one are built by the same function rather than side by side.
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
	offer, err := sdp.Parse(body)
	if err != nil {
		return nil, nil, fmt.Errorf("proxy: in-dialog offer: %w", err)
	}
	codecs := filterCodecs(offer.Audio.Codecs)
	if !sdp.HasMedia(codecs) {
		return nil, nil, fmt.Errorf("%w: re-offer had %s", errNoUsableCodec, sdp.Describe(offer.Audio.Codecs))
	}
	addr, port := s.anchorFor(d.session(), toward)
	id, version := d.nextOrigin()
	out, err := sdp.Build{
		Address: addr,
		Port:    port,
		Codecs:  codecs,
		// The direction passes through unreversed: FreeSBC is a relay in
		// the middle, so a caller putting the call on hold (sendonly) must
		// present as sendonly to the far end too.
		Direction:      offer.Audio.Direction,
		SessionID:      id,
		SessionVersion: version,
	}.Marshal()
	if err != nil {
		return nil, nil, fmt.Errorf("proxy: build in-dialog offer: %w", err)
	}
	return out, offer, nil
}

// rebuildInDialogAnswer rewrites the answer to a re-INVITE for the near
// side, and records the newly agreed codec list on the session.
func (s *Server) rebuildInDialogAnswer(d *dialog, offer *sdp.Session, body []byte, toward plane) ([]byte, error) {
	answer, err := sdp.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("proxy: in-dialog answer: %w", err)
	}
	agreed, err := sdp.Negotiate(filterCodecs(offer.Audio.Codecs), answer.Audio.Codecs)
	if err != nil {
		return nil, negotiateError(err)
	}
	sess := d.session()
	sess.codecs = agreed

	addr, port := s.anchorFor(sess, toward)
	id, version := d.nextOrigin()
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
	return build.MarshalDeclining(offer)
}
