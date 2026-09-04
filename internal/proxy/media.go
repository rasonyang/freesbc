package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/freesbc/freesbc/internal/media"
	"github.com/freesbc/freesbc/internal/sdp"
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

	// sessionID is the o= session identifier FreeSBC uses for every body
	// it generates on this session. It must stay constant for the life of
	// the session (RFC 4566): a changed id means a NEW session, which some
	// endpoints answer by tearing the old one down.
	sessionID uint64

	// version is the o= version counter for bodies FreeSBC generates on
	// this session. RFC 4566 requires it to increase on every re-offer for
	// the same session id, and some endpoints use it to decide whether a
	// re-offer changed anything.
	version uint64

	// lastAnswer is the body FreeSBC built for the near side the first
	// time the far side answered. A 200 OK that restates the answer
	// already sent in a reliable provisional must repeat OUR body, not
	// re-run negotiation — re-latching mid-call would drop audio.
	lastAnswer []byte

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

// offerResult is what buildUpstreamOffer produces: the SDP to send on and
// the media session it belongs to.
type offerResult struct {
	sess *mediaSession
	sdp  []byte
	// offer is the parsed offer this exchange is answering — the public
	// client's for an outbound call, FreeSWITCH's for an inbound one. It
	// is retained so the answer can be built with the same media-section
	// count (RFC 3264 §6) and intersected against the right codec list.
	offer *sdp.Session
}

var (
	// errNoUsableCodec maps to 488: the two sides share no codec and
	// FreeSBC does not transcode.
	errNoUsableCodec = errors.New("proxy: no usable codec in common")
	// errRenumbered maps to 488 as well: an answerer that renumbered a
	// payload type would need every RTP packet's PT byte rewritten, which
	// is transcoding-adjacent work this phase does not do.
	errRenumbered = errors.New("proxy: answer renumbered a payload type")
)

// buildUpstreamOffer takes a public client's offer and produces the plain
// RTP offer FreeSWITCH will see, allocating the media session behind it.
//
// The upstream body is CONSTRUCTED, never derived: nothing is copied from
// the public offer except the negotiated codec list. That is what makes
// "do not pass browser ICE candidates to FreeSWITCH" and "FreeSWITCH never
// learns the public endpoint's address" structural properties rather than
// a list of attributes someone remembered to strip.
func (s *Server) buildUpstreamOffer(ctx context.Context, offerBody []byte) (*offerResult, error) {
	offer, err := sdp.Parse(offerBody)
	if err != nil {
		return nil, fmt.Errorf("proxy: public offer: %w", err)
	}
	codecs := sdp.Filter(offer.Audio.Codecs)
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

	body, err := sdp.Build{
		Address:   s.topo.privateMediaIP,
		Port:      sess.privatePort,
		Codecs:    codecs,
		Direction: offer.Audio.Direction,
		// A fresh session identity: the upstream body is FreeSBC's own
		// offer, not a relay of the client's, so it must not reuse the
		// client's o= line (which would leak the client's session id and,
		// in some stacks, its address).
		SessionID:      sess.sessionID,
		SessionVersion: sess.nextVersion(),
	}.Marshal()
	if err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("proxy: build upstream offer: %w", err)
	}
	return &offerResult{sess: sess, sdp: body, offer: offer}, nil
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
		sessionID:   newSessionID(),
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
		sessionID:   newSessionID(),
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
	agreed, err := sdp.Intersect(res.sess.codecs, answer.Audio.Codecs)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errNoUsableCodec, err)
	}
	if o, a, yes := sdp.NeedsRenumber(res.sess.codecs, answer.Audio.Codecs); yes {
		return nil, fmt.Errorf("%w: offered %s, answered %s", errRenumbered, o, a)
	}
	res.sess.codecs = agreed

	// Arm the private-side latch with the address FreeSWITCH will send
	// from. Until this happens the relay has nowhere to forward to and
	// (under strict latching) would reject FreeSWITCH's own packets.
	if res.sess.webrtc != nil {
		res.sess.webrtc.SetPrivateRemote(netip.AddrPortFrom(answer.Audio.Address, uint16(answer.Audio.Port)))
	} else {
		res.sess.rtp.SetRemote(media.SideB, netip.AddrPortFrom(answer.Audio.Address, uint16(answer.Audio.Port)))
		if answer.Audio.RTCPPort > 0 {
			res.sess.rtp.SetRTCPRemote(media.SideB, netip.AddrPortFrom(answer.Audio.Address, uint16(answer.Audio.RTCPPort)))
		}
		res.sess.rtp.Start()
	}

	build := sdp.Build{
		Address:        s.topo.publicMediaIP,
		Port:           res.sess.publicPort,
		Codecs:         agreed,
		Direction:      answer.Audio.Direction,
		SessionID:      res.sess.sessionID,
		SessionVersion: res.sess.nextVersion(),
	}
	if publicIsWebRTC {
		leg := res.sess.webrtc.Leg()
		ufrag, pwd := leg.LocalCredentials()
		build.Secure = true
		build.DTLS = true
		build.RTCPMux = true
		build.ICEUfrag = ufrag
		build.ICEPwd = pwd
		build.Setup = leg.DTLSSetup()
		build.Fingerprint = &sdp.Fingerprint{
			Hash:  s.identity.FingerprintHash,
			Value: s.identity.FingerprintValue,
		}
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
func (s *Server) buildPublicOffer(offerBody []byte) (*offerResult, error) {
	offer, err := sdp.Parse(offerBody)
	if err != nil {
		return nil, fmt.Errorf("proxy: upstream offer: %w", err)
	}
	codecs := sdp.Filter(offer.Audio.Codecs)
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
		sessionID:   newSessionID(),
	}
	body, err := sdp.Build{
		Address:        s.topo.publicMediaIP,
		Port:           ms.publicPort,
		Codecs:         codecs,
		Direction:      offer.Audio.Direction,
		SessionID:      ms.sessionID,
		SessionVersion: ms.nextVersion(),
	}.Marshal()
	if err != nil {
		_ = ms.Close()
		return nil, err
	}
	return &offerResult{sess: ms, sdp: body, offer: offer}, nil
}

// applyPublicAnswer processes the client's answer to an inbound call and
// produces the body FreeSWITCH will see.
func (s *Server) applyPublicAnswer(res *offerResult, answerBody []byte) ([]byte, error) {
	answer, err := sdp.Parse(answerBody)
	if err != nil {
		return nil, fmt.Errorf("proxy: public answer: %w", err)
	}
	agreed, err := sdp.Intersect(res.sess.codecs, answer.Audio.Codecs)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errNoUsableCodec, err)
	}
	if o, a, yes := sdp.NeedsRenumber(res.sess.codecs, answer.Audio.Codecs); yes {
		return nil, fmt.Errorf("%w: offered %s, answered %s", errRenumbered, o, a)
	}
	res.sess.codecs = agreed
	res.sess.rtp.SetRemote(media.SideA, netip.AddrPortFrom(answer.Audio.Address, uint16(answer.Audio.Port)))
	if answer.Audio.RTCPPort > 0 {
		res.sess.rtp.SetRTCPRemote(media.SideA, netip.AddrPortFrom(answer.Audio.Address, uint16(answer.Audio.RTCPPort)))
	}
	res.sess.rtp.Start()

	return sdp.Build{
		Address:        s.topo.privateMediaIP,
		Port:           res.sess.privatePort,
		Codecs:         agreed,
		Direction:      answer.Audio.Direction,
		SessionID:      res.sess.sessionID,
		SessionVersion: res.sess.nextVersion(),
	}.MarshalDeclining(res.offer)
}

// newSessionID returns a fresh SDP o= session identifier. RFC 4566 wants
// it to be "globally unique"; a nanosecond clock reading is what every
// implementation actually uses.
func newSessionID() uint64 { return uint64(time.Now().UnixNano()) }

// nextVersion returns the next o= version for a body generated on this
// session.
func (m *mediaSession) nextVersion() uint64 {
	m.version++
	return m.version
}

// portFor and addressFor select the anchor this session presents on one
// plane. They are what keeps a re-negotiation on the ports it already
// holds: nothing here allocates.
func (m *mediaSession) portFor(p plane) int {
	if p == planePublic {
		return m.publicPort
	}
	return m.privatePort
}

func (s *Server) addressFor(p plane) netip.Addr {
	if p == planePublic {
		return s.topo.publicMediaIP
	}
	return s.topo.privateMediaIP
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
func (s *Server) rebuildInDialogOffer(sess *mediaSession, body []byte, toward plane) ([]byte, *sdp.Session, error) {
	offer, err := sdp.Parse(body)
	if err != nil {
		return nil, nil, fmt.Errorf("proxy: in-dialog offer: %w", err)
	}
	codecs := sdp.Filter(offer.Audio.Codecs)
	if !sdp.HasMedia(codecs) {
		return nil, nil, fmt.Errorf("%w: re-offer had %s", errNoUsableCodec, sdp.Describe(offer.Audio.Codecs))
	}
	out, err := sdp.Build{
		Address: s.addressFor(toward),
		Port:    sess.portFor(toward),
		Codecs:  codecs,
		// The direction passes through unreversed: FreeSBC is a relay in
		// the middle, so a caller putting the call on hold (sendonly) must
		// present as sendonly to the far end too.
		Direction:      offer.Audio.Direction,
		SessionID:      sess.sessionID,
		SessionVersion: sess.nextVersion(),
	}.Marshal()
	if err != nil {
		return nil, nil, fmt.Errorf("proxy: build in-dialog offer: %w", err)
	}
	return out, offer, nil
}

// rebuildInDialogAnswer rewrites the answer to a re-INVITE for the near
// side, and records the newly agreed codec list on the session.
func (s *Server) rebuildInDialogAnswer(sess *mediaSession, offer *sdp.Session, body []byte, toward plane) ([]byte, error) {
	answer, err := sdp.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("proxy: in-dialog answer: %w", err)
	}
	agreed, err := sdp.Intersect(sdp.Filter(offer.Audio.Codecs), answer.Audio.Codecs)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errNoUsableCodec, err)
	}
	if o, a, yes := sdp.NeedsRenumber(sdp.Filter(offer.Audio.Codecs), answer.Audio.Codecs); yes {
		return nil, fmt.Errorf("%w: offered %s, answered %s", errRenumbered, o, a)
	}
	sess.codecs = agreed

	build := sdp.Build{
		Address:        s.addressFor(toward),
		Port:           sess.portFor(toward),
		Codecs:         agreed,
		Direction:      answer.Audio.Direction,
		SessionID:      sess.sessionID,
		SessionVersion: sess.nextVersion(),
	}
	// A browser-facing answer must restate the SAME ICE credentials,
	// fingerprint and DTLS role as the original: a re-INVITE that changed
	// any of them would look like an ICE restart and tear down the media
	// path the session is still using.
	if toward == planePublic && sess.webrtc != nil {
		leg := sess.webrtc.Leg()
		ufrag, pwd := leg.LocalCredentials()
		build.Secure, build.DTLS, build.RTCPMux = true, true, true
		build.ICEUfrag, build.ICEPwd = ufrag, pwd
		build.Setup = leg.DTLSSetup()
		build.Fingerprint = &sdp.Fingerprint{
			Hash:  s.identity.FingerprintHash,
			Value: s.identity.FingerprintValue,
		}
	}
	return build.MarshalDeclining(offer)
}
