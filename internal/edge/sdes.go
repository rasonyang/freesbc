package edge

import (
	"errors"
	"fmt"

	"github.com/freesbc/freesbc/internal/config"
	"github.com/freesbc/freesbc/internal/media"
	"github.com/freesbc/freesbc/internal/sip/sdp"
)

// SDES-SRTP on a public leg (RFC 4568). The public leg of a plain-RTP call
// can be SRTP keyed by a=crypto lines in the SDP, per the srtp policy of
// the far end (edge.srtp for registered clients, edge.carriers.<name>.srtp
// for a carrier). The switch leg is always plain RTP/AVP, so the relay
// decrypts what the public side sends and encrypts what it is sent
// (internal/media/sdes.go); nothing is transcoded.
//
// The state lives on the call's mediaSession. A body toward the public leg
// is built from it (sdesOffer for an offer, the plan of planAnswer for an
// answer); a body from the public leg is parsed into a plan (planAnswer
// for its offer, checkAnswer for its answer), and the plan is committed to
// the media only when the exchange takes effect, so a refused re-offer
// leaves the keys in force untouched.

// srtpPolicy is the SDES policy in force for one public leg.
type srtpPolicy uint8

const (
	srtpOff      srtpPolicy = iota // plain RTP/AVP; crypto lines are ignored
	srtpOptional                   // offer SAVP, accept an AVP answer or offer
	srtpRequired                   // SAVP only
	// srtpImpossible is "required" on a leg whose signaling cannot carry
	// keys safely (not TLS, no allow_insecure_sdes): every offer or answer
	// is refused, so the operator's "required" is never silently weakened.
	srtpImpossible
)

// errSDES is the root of every SDES refusal: rejectMedia maps it to 488.
var errSDES = errors.New("proxy: SDES-SRTP not negotiable")

var (
	// errSDESInsecure maps to 488: srtp is required for this far end but its
	// signaling transport would carry the keys in the clear.
	errSDESInsecure = fmt.Errorf("%w: srtp is required but the signaling transport is not TLS (edge.allow_insecure_sdes is off)", errSDES)
	// errSDESRequired maps to 488: the far end offered or answered plain RTP
	// where SRTP is required.
	errSDESRequired = fmt.Errorf("%w: srtp is required but the far end offered or answered plain RTP", errSDES)
	// errSDESDowngrade maps to 488: an SRTP leg cannot go back to plain RTP.
	errSDESDowngrade = fmt.Errorf("%w: the offer or answer would drop SRTP on an SRTP leg", errSDES)
	// errSDESNoCrypto maps to 488: an RTP/SAVP section with no usable a=crypto.
	errSDESNoCrypto = fmt.Errorf("%w: SRTP section without a usable a=crypto line", errSDES)
	// errSDESAnswer maps to 488: the answer selected no line FreeSBC offered.
	errSDESAnswer = fmt.Errorf("%w: SRTP answer selects no offered a=crypto line", errSDES)
)

// legSRTPPolicy is the policy for a public leg. carrier names the carrier
// ("" for a registered client) and transport is the leg's signaling
// transport (a client's registration transport). Browser (ws/wss) legs are
// WebRTC and never consult it.
func (s *Server) legSRTPPolicy(carrier, transport string) srtpPolicy {
	cfg := s.boot
	name, secure := cfg.Edge.SRTP, transport == "tls" || transport == "wss"
	if carrier != "" {
		name, secure = config.SRTPOff, false
		for _, c := range cfg.CarrierList() {
			if c.Name == carrier {
				name, secure = c.SRTP, c.Transport == config.CarrierTLS
				break
			}
		}
	}
	if secure || cfg.Edge.AllowInsecureSDES {
		switch name {
		case config.SRTPOptional:
			return srtpOptional
		case config.SRTPRequired:
			return srtpRequired
		}
		return srtpOff
	}
	if name == config.SRTPRequired {
		return srtpImpossible
	}
	return srtpOff
}

// sdesLeg is a call's SDES state, guarded by the mediaSession's mu. It
// exists only on a plain-RTP session whose public leg has a policy.
type sdesLeg struct {
	policy srtpPolicy
	// offered is what FreeSBC offers while the leg is undecided: one line
	// per supported suite, generated once so a repeated offer is identical.
	offered []sdp.Crypto
	// on says the leg negotiated SRTP; plain says an optional leg
	// negotiated RTP/AVP and stays plain.
	on, plain bool
	// local is the key FreeSBC protects its packets with; peer the key the
	// far end protects its own with. Valid when on.
	local, peer sdp.Crypto
}

// sdesPlan is the outcome of one offer or answer, applied by commit.
type sdesPlan struct {
	sdes        bool
	plain       bool
	local, peer sdp.Crypto
}

// newSDESLeg returns the state for a policy, nil for off.
func newSDESLeg(p srtpPolicy) *sdesLeg {
	if p == srtpOff {
		return nil
	}
	return &sdesLeg{policy: p}
}

// SDES reports whether the public leg has negotiated SRTP.
func (m *mediaSession) SDES() bool {
	if m.sdes == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sdes.on
}

// initialOffer is the line set FreeSBC offers on a new leg.
func (m *mediaSession) initialOffer() ([]sdp.Crypto, error) {
	if m.sdes.offered == nil {
		lines, err := sdp.OfferCrypto()
		if err != nil {
			return nil, err
		}
		m.sdes.offered = lines
	}
	return m.sdes.offered, nil
}

// sdesOffer returns the a=crypto lines of an offer toward the public leg,
// nil for a plain offer. An SRTP leg repeats the one line in force, so a
// re-offer never changes the keys; a leg that settled on plain stays plain.
func (m *mediaSession) sdesOffer() ([]sdp.Crypto, error) {
	if m.sdes == nil {
		return nil, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sdes.policy == srtpImpossible {
		return nil, errSDESInsecure
	}
	if m.sdes.on {
		return []sdp.Crypto{m.sdes.local}, nil
	}
	if m.sdes.plain {
		return nil, nil
	}
	return m.initialOffer()
}

// answerSet is the line set an answer to the current offer is matched
// against: the first offer's full set until the leg is decided, so each
// fork of a call may pick its own suite.
func (m *mediaSession) answerSet(initial bool) ([]sdp.Crypto, error) {
	if initial {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.initialOffer()
	}
	return m.sdesOffer()
}

// planAnswer plans FreeSBC's answer to the public side's offer a. An
// RTP/SAVP offer with a usable line is answered SRTP, with the key already
// in force when the suite is unchanged; plain is answered plain unless the
// policy or the leg's state forbids it.
func (m *mediaSession) planAnswer(a *sdp.Audio) (sdesPlan, error) {
	if m.sdes == nil {
		return sdesPlan{}, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.sdes
	if st.policy == srtpImpossible {
		return sdesPlan{}, errSDESInsecure
	}
	if !a.SDES() {
		switch {
		case st.on:
			return sdesPlan{}, errSDESDowngrade
		case st.policy == srtpRequired:
			return sdesPlan{}, errSDESRequired
		}
		return sdesPlan{plain: true}, nil
	}
	peer, ok := sdp.SelectCrypto(a.Crypto)
	if !ok {
		return sdesPlan{}, errSDESNoCrypto
	}
	local := st.local
	if !st.on || local.Suite != peer.Suite {
		var err error
		if local, err = sdp.NewCrypto(peer.Tag, peer.Suite); err != nil {
			return sdesPlan{}, err
		}
	}
	local.Tag = peer.Tag
	return sdesPlan{sdes: true, local: local, peer: peer}, nil
}

// checkAnswer plans the handling of the public side's answer a to an offer
// that carried the lines in offered. The answer must select one of them by
// tag and suite; its key is the peer's.
func (m *mediaSession) checkAnswer(a *sdp.Audio, offered []sdp.Crypto) (sdesPlan, error) {
	if m.sdes == nil {
		return sdesPlan{}, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.sdes
	if st.policy == srtpImpossible {
		return sdesPlan{}, errSDESInsecure
	}
	if len(offered) == 0 { // a plain offer: only a plain answer fits
		if a.SDES() {
			return sdesPlan{}, errSDESAnswer
		}
		return sdesPlan{plain: true}, nil
	}
	if !a.SDES() {
		if st.on {
			return sdesPlan{}, errSDESDowngrade
		}
		if st.policy == srtpRequired {
			return sdesPlan{}, errSDESRequired
		}
		return sdesPlan{plain: true}, nil
	}
	for _, c := range a.Crypto {
		for _, o := range offered {
			if c.Tag == o.Tag && c.Suite == o.Suite {
				return sdesPlan{sdes: true, local: o, peer: c}, nil
			}
		}
	}
	if len(a.Crypto) == 0 {
		return sdesPlan{}, errSDESNoCrypto
	}
	return sdesPlan{}, errSDESAnswer
}

// commit applies a plan: the keys go to the media (a key already in force
// changes nothing, a new one re-keys in place) and the leg's state follows.
func (m *mediaSession) commit(p sdesPlan) error {
	if m.sdes == nil || (!p.sdes && !p.plain) {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.plain {
		if !m.sdes.on {
			m.sdes.plain = true
		}
		return nil
	}
	if m.rtp == nil {
		return errors.New("proxy: SDES keys for a session without a plain RTP leg")
	}
	// Remote first: a packet arriving under the peer's new key is accepted
	// before anything is sent under ours.
	if err := m.rtp.SetSDESRemote(media.SideA, mediaKey(p.peer)); err != nil {
		return fmt.Errorf("proxy: SDES peer key: %w", err)
	}
	if err := m.rtp.SetSDESLocal(media.SideA, mediaKey(p.local)); err != nil {
		return fmt.Errorf("proxy: SDES local key: %w", err)
	}
	m.sdes.on, m.sdes.plain = true, false
	m.sdes.local, m.sdes.peer = p.local, p.peer
	return nil
}

// mediaKey converts a signalled line to the relay's key type.
func mediaKey(c sdp.Crypto) media.SDESKey {
	return media.SDESKey{Suite: media.SDESSuite(c.Suite), Key: c.Key, Salt: c.Salt}
}

// answerLines is the a=crypto content of a body that answers the public
// side: the one line in the plan, none for a plain answer.
func (p sdesPlan) answerLines() []sdp.Crypto {
	if p.sdes {
		return []sdp.Crypto{p.local}
	}
	return nil
}
