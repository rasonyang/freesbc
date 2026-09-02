package media

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/srtp/v3"
)

// WebRTCLeg is the browser-facing half of a media session: ICE-Lite over
// one UDP socket, then DTLS on that socket, then SRTP/SRTCP keyed from the
// DTLS handshake (spec §9).
//
// It deliberately does NOT use pion/webrtc.PeerConnection. The proxy owns
// the media session, the SDP and the leg lifecycle; Pion supplies protocol
// primitives only — ice.Agent for connectivity checks, dtls.Conn for the
// handshake and key export, srtp.Context for the transforms.
//
// Lifecycle: NewWebRTCLeg (allocates the socket and ICE credentials, so
// the answer SDP can be built) → Start (background: ICE accept, DTLS
// handshake, SRTP keying; publishes readiness on Ready) → Close.
type WebRTCLeg struct {
	pool *PlanePool
	conn *net.UDPConn
	port int

	// localUfrag/localPwd are OUR ICE credentials, generated up front so
	// they can go into the SDP answer before any packet arrives.
	localUfrag string
	localPwd   string

	identity *DTLSIdentity

	// remote credentials and DTLS role, set from the browser's offer.
	remoteUfrag string
	remotePwd   string
	dtlsClient  bool

	ready     chan struct{}
	readyOnce sync.Once

	// mu guards every field below. They are created by the establish
	// goroutine and read (and closed) by Close, which any goroutine may
	// call at any time — including before establish has finished. Without
	// the lock those are plain unsynchronized cross-goroutine accesses,
	// which the race detector correctly flags on any teardown that races
	// establishment.
	mu    sync.Mutex
	agent *ice.Agent
	mux   *ice.UDPMuxDefault
	demux *demux
	// in/out are the SRTP contexts once DTLS has keyed: in decrypts what
	// the browser sends, out encrypts what we send it.
	in     *SRTPContext
	out    *SRTPContext
	srtpEP *muxEndpoint
	// peerCerts is the established connection's state accessor, kept so
	// VerifyFingerprint can hash the peer certificate after the handshake.
	peerCerts func() (dtls.State, bool)
	err       error
	// established records that the handshake completed, so a later
	// (normal) Close does not retroactively stamp the leg as failed.
	established bool

	closeOnce sync.Once
	closed    chan struct{}
}

// setErr records the establishment outcome. Callers read it via Err, which
// waits on ready first — the channel close is the happens-before edge that
// makes the value visible; the lock is what keeps the write itself from
// racing a concurrent Close.
func (l *WebRTCLeg) setErr(err error) {
	l.mu.Lock()
	if l.err == nil {
		l.err = err
	}
	l.mu.Unlock()
}

func (l *WebRTCLeg) loadErr() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.err
}

// WebRTCLegConfig is what the signaling plane knows before the leg exists.
type WebRTCLegConfig struct {
	// AdvertisedIP is the public media address written into the SDP
	// candidate and c= line. ICE candidates are rewritten to it, so a
	// NAT'ed deployment advertises the reachable address while the socket
	// binds the private one.
	AdvertisedIP netip.Addr
	// RemoteUfrag/RemotePwd come from the browser's offer.
	RemoteUfrag string
	RemotePwd   string
	// RemoteSetup is the browser's a=setup value. "actpass" or "active"
	// makes FreeSBC the DTLS server (we answer a=setup:passive);
	// "passive" makes it the client.
	RemoteSetup string
	// Identity is the DTLS certificate to present.
	Identity *DTLSIdentity
	// HandshakeTimeout bounds ICE + DTLS establishment. Zero uses a
	// 30-second default, which comfortably covers a slow browser without
	// letting a half-open leg pin a port indefinitely.
	HandshakeTimeout time.Duration
}

// ErrWebRTCNotReady is returned by accessors called before the handshake
// completes.
var ErrWebRTCNotReady = errors.New("media: webrtc leg not established")

// NewWebRTCLeg allocates the leg's socket and ICE identity. It performs no
// network I/O beyond binding, so the caller can build and send the SDP
// answer immediately and only then Start the handshake.
func NewWebRTCLeg(pool *PlanePool, cfg WebRTCLegConfig) (*WebRTCLeg, error) {
	if cfg.Identity == nil {
		return nil, errors.New("media: webrtc leg needs a DTLS identity")
	}
	if cfg.RemoteUfrag == "" || cfg.RemotePwd == "" {
		return nil, errors.New("media: webrtc leg needs the remote ICE credentials")
	}
	if !cfg.AdvertisedIP.IsValid() {
		return nil, errors.New("media: webrtc leg needs an advertised media address")
	}
	conn, err := pool.allocateSingle()
	if err != nil {
		return nil, err
	}
	ufrag, pwd, err := newICECredentials()
	if err != nil {
		_ = conn.Close()
		pool.release(conn.LocalAddr().(*net.UDPAddr).Port)
		return nil, err
	}
	l := &WebRTCLeg{
		pool:        pool,
		conn:        conn,
		port:        conn.LocalAddr().(*net.UDPAddr).Port,
		localUfrag:  ufrag,
		localPwd:    pwd,
		identity:    cfg.Identity,
		remoteUfrag: cfg.RemoteUfrag,
		remotePwd:   cfg.RemotePwd,
		// RFC 5763 §5: when the offer says actpass the answerer picks, and
		// the conventional pick for a gateway with a stable address is the
		// server role (a=setup:passive). Only an explicit a=setup:passive
		// from the browser makes us the client.
		dtlsClient: cfg.RemoteSetup == "passive",
		ready:      make(chan struct{}),
		closed:     make(chan struct{}),
	}
	return l, nil
}

// Port is the public UDP port this leg listens on — the port that goes
// into the SDP answer's m= line and host candidate.
func (l *WebRTCLeg) Port() int { return l.port }

// LocalCredentials are the ICE ufrag/pwd for the SDP answer.
func (l *WebRTCLeg) LocalCredentials() (ufrag, pwd string) { return l.localUfrag, l.localPwd }

// DTLSSetup is the a=setup value the answer must carry.
func (l *WebRTCLeg) DTLSSetup() string {
	if l.dtlsClient {
		return "active"
	}
	return "passive"
}

// Ready is closed once the leg is established or has failed; Err then
// reports which.
func (l *WebRTCLeg) Ready() <-chan struct{} { return l.ready }

// Err returns the establishment error, or nil once the leg is up. It is
// only meaningful after Ready is closed.
func (l *WebRTCLeg) Err() error {
	<-l.ready
	return l.loadErr()
}

// Start drives ICE and DTLS in the background. ctx cancels establishment;
// once established, the leg lives until Close.
func (l *WebRTCLeg) Start(ctx context.Context, timeout time.Duration) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	go func() {
		err := l.establish(ctx, timeout)
		if err != nil {
			// Publish the error BEFORE tearing down, then let Close
			// close the ready channel: a caller that wakes on Ready must
			// find every resource already released, or a "leg failed"
			// signal would race the port actually returning to the pool.
			l.setErr(err)
			_ = l.Close()
			return
		}
		l.mu.Lock()
		l.established = true
		l.mu.Unlock()
		l.readyOnce.Do(func() { close(l.ready) })
	}()
}

func (l *WebRTCLeg) establish(ctx context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// --- ICE-Lite ---
	//
	// A lite agent never sends connectivity checks; it answers them and
	// lets the full-ICE peer nominate. Host candidates are the only kind
	// it may offer (RFC 5245 §4.2), which is exactly right for a gateway
	// with one stable public media address. NAT1To1IPs rewrites that host
	// candidate to the advertised address, so a NAT'ed deployment binds
	// privately and advertises publicly without a STUN round trip.
	loggerFactory := logging.NewDefaultLoggerFactory()
	loggerFactory.DefaultLogLevel = logging.LogLevelError
	mux := ice.NewUDPMuxDefault(ice.UDPMuxParams{UDPConn: l.conn, Logger: loggerFactory.NewLogger("ice")})
	l.mu.Lock()
	l.mux = mux
	l.mu.Unlock()
	agent, err := ice.NewAgent(&ice.AgentConfig{
		Lite:           true,
		CandidateTypes: []ice.CandidateType{ice.CandidateTypeHost},
		NetworkTypes:   []ice.NetworkType{ice.NetworkTypeUDP4, ice.NetworkTypeUDP6},
		UDPMux:         mux,
		LocalUfrag:     l.localUfrag,
		LocalPwd:       l.localPwd,
		LoggerFactory:  loggerFactory,
		// A single-host deployment may legitimately serve media on
		// loopback (an all-on-one-box lab, and every test in this
		// package); excluding it would make those setups fail ICE for no
		// security gain, since the socket is bound to exactly the address
		// the operator configured either way.
		IncludeLoopback: true,
	})
	if err != nil {
		return fmt.Errorf("media: ice agent: %w", err)
	}
	l.mu.Lock()
	l.agent = agent
	l.mu.Unlock()
	// pion requires a candidate handler before gathering. FreeSBC does not
	// use the gathered candidates in SDP — it advertises exactly one host
	// candidate at the configured public address (see sdpx.Build) — so the
	// handler is intentionally empty; gathering exists only to give the
	// agent a local candidate to answer connectivity checks from.
	if err := agent.OnCandidate(func(ice.Candidate) {}); err != nil {
		return fmt.Errorf("media: ice candidate handler: %w", err)
	}
	if err := agent.GatherCandidates(); err != nil {
		return fmt.Errorf("media: ice gather: %w", err)
	}
	// A lite agent is always controlled, so Accept (not Dial) is the
	// correct side regardless of which end offered.
	iceConn, err := agent.Accept(ctx, l.remoteUfrag, l.remotePwd)
	if err != nil {
		return fmt.Errorf("media: ice accept: %w", err)
	}

	// --- DTLS over the same socket ---
	dm := newDemux(iceConn)
	l.mu.Lock()
	l.demux = dm
	l.srtpEP = dm.srtp
	l.mu.Unlock()

	dtlsCfg := &dtls.Config{
		Certificates: []tls.Certificate{l.identity.Certificate},
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{
			dtls.SRTP_AES128_CM_HMAC_SHA1_80,
			dtls.SRTP_AES128_CM_HMAC_SHA1_32,
		},
		// The peer certificate is self-signed by design; WebRTC binds it
		// to the session through the a=fingerprint line in signaling, and
		// the caller verifies that separately (see VerifyFingerprint).
		// Skipping chain verification here is the correct behavior, not a
		// weakening — there is no PKI to verify against.
		InsecureSkipVerify: true,
		ClientAuth:         dtls.RequireAnyClientCert,
	}
	var dtlsConn *dtls.Conn
	if l.dtlsClient {
		dtlsConn, err = dtls.Client(dm.dtls, dm.dtls.RemoteAddr(), dtlsCfg)
	} else {
		dtlsConn, err = dtls.Server(dm.dtls, dm.dtls.RemoteAddr(), dtlsCfg)
	}
	if err != nil {
		return fmt.Errorf("media: dtls setup: %w", err)
	}
	// dtls.Client/Server only build the connection; the handshake itself
	// runs here, under the establishment deadline, so a peer that opens
	// the flow and then goes quiet cannot pin the port past the timeout.
	if err := dtlsConn.HandshakeContext(ctx); err != nil {
		_ = dtlsConn.Close()
		return fmt.Errorf("media: dtls handshake: %w", err)
	}
	l.mu.Lock()
	l.peerCerts = dtlsConn.ConnectionState
	l.mu.Unlock()

	// --- SRTP keying (RFC 5764 §4.2) ---
	if err := l.deriveSRTP(dtlsConn); err != nil {
		return err
	}
	// The DTLS connection has done its job (it exists only to key SRTP);
	// its records are already drained by the demultiplexer, and closing it
	// here would tear the shared socket down. It is retained only so a
	// late renegotiation attempt is absorbed rather than reaching SRTP.
	go func() {
		<-l.closed
		_ = dtlsConn.Close()
	}()
	return nil
}

// deriveSRTP exports the DTLS keying material and splits it into the two
// SRTP contexts, per RFC 5764 §4.2: the exporter produces
// client_key ‖ server_key ‖ client_salt ‖ server_salt, and which half is
// "ours" depends on whether we ran the handshake as client or server.
func (l *WebRTCLeg) deriveSRTP(conn *dtls.Conn) error {
	profileID, ok := conn.SelectedSRTPProtectionProfile()
	if !ok {
		return errors.New("media: dtls peer negotiated no SRTP profile")
	}
	profile, err := srtpProfileFor(profileID)
	if err != nil {
		return err
	}
	keyLen, err := profile.KeyLen()
	if err != nil {
		return fmt.Errorf("media: srtp profile: %w", err)
	}
	saltLen, err := profile.SaltLen()
	if err != nil {
		return fmt.Errorf("media: srtp profile: %w", err)
	}
	state, ok := conn.ConnectionState()
	if !ok {
		return errors.New("media: dtls connection state unavailable")
	}
	material, err := state.ExportKeyingMaterial(srtpExporterLabel, nil, keyLen*2+saltLen*2)
	if err != nil {
		return fmt.Errorf("media: dtls key export: %w", err)
	}
	off := 0
	clientKey := material[off : off+keyLen]
	off += keyLen
	serverKey := material[off : off+keyLen]
	off += keyLen
	clientSalt := material[off : off+saltLen]
	off += saltLen
	serverSalt := material[off : off+saltLen]

	// The writer of a direction keys it: whichever role WE played picks
	// our outbound key, and the peer's role picks the key we decrypt with.
	ourKey, ourSalt := serverKey, serverSalt
	theirKey, theirSalt := clientKey, clientSalt
	if l.dtlsClient {
		ourKey, ourSalt = clientKey, clientSalt
		theirKey, theirSalt = serverKey, serverSalt
	}
	out, err := NewSRTPContextFromKeys(profile, ourKey, ourSalt)
	if err != nil {
		return err
	}
	in, err := NewSRTPContextFromKeys(profile, theirKey, theirSalt)
	if err != nil {
		return err
	}
	l.mu.Lock()
	l.in, l.out = in, out
	l.mu.Unlock()
	return nil
}

// srtpExporterLabel is the RFC 5764 §4.2 exporter label.
const srtpExporterLabel = "EXTRACTOR-dtls_srtp"

func srtpProfileFor(id dtls.SRTPProtectionProfile) (srtp.ProtectionProfile, error) {
	switch id {
	case dtls.SRTP_AES128_CM_HMAC_SHA1_80:
		return srtp.ProtectionProfileAes128CmHmacSha1_80, nil
	case dtls.SRTP_AES128_CM_HMAC_SHA1_32:
		return srtp.ProtectionProfileAes128CmHmacSha1_32, nil
	default:
		return 0, fmt.Errorf("media: unsupported SRTP protection profile %d", id)
	}
}

// VerifyFingerprint checks the peer certificate the DTLS handshake
// produced against the a=fingerprint the browser signalled. This is the
// ONLY binding between the signaling identity and the media path in
// WebRTC, so a mismatch must fail the leg.
func (l *WebRTCLeg) VerifyFingerprint(hash, value string) error {
	select {
	case <-l.ready:
	default:
		return ErrWebRTCNotReady
	}
	if err := l.loadErr(); err != nil {
		return err
	}
	if hash != "sha-256" {
		return fmt.Errorf("media: unsupported fingerprint hash %q", hash)
	}
	got, err := l.peerFingerprint()
	if err != nil {
		return err
	}
	if !strings.EqualFold(got, value) {
		return errors.New("media: DTLS peer certificate does not match the signalled fingerprint")
	}
	return nil
}

// peerFingerprint hashes the peer's leaf certificate the way RFC 8122 §5
// requires: SHA-256 over the DER, uppercase hex joined by colons.
func (l *WebRTCLeg) peerFingerprint() (string, error) {
	l.mu.Lock()
	get := l.peerCerts
	l.mu.Unlock()
	if get == nil {
		return "", ErrWebRTCNotReady
	}
	state, ok := get()
	if !ok || len(state.PeerCertificates) == 0 {
		return "", errors.New("media: DTLS peer presented no certificate")
	}
	sum := sha256.Sum256(state.PeerCertificates[0])
	hexed := hex.EncodeToString(sum[:])
	parts := make([]string, 0, len(sum))
	for i := 0; i < len(hexed); i += 2 {
		parts = append(parts, strings.ToUpper(hexed[i:i+2]))
	}
	return strings.Join(parts, ":"), nil
}

// SRTPContexts returns the leg's inbound (decrypt) and outbound (encrypt)
// contexts, or ErrWebRTCNotReady before the handshake completes.
func (l *WebRTCLeg) SRTPContexts() (in, out *SRTPContext, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.in == nil || l.out == nil {
		return nil, nil, ErrWebRTCNotReady
	}
	return l.in, l.out, nil
}

// Conn returns the established media endpoint: reads yield SRTP/SRTCP
// packets from the browser, writes send them back over the selected
// candidate pair.
func (l *WebRTCLeg) Conn() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.srtpEP == nil {
		return nil, ErrWebRTCNotReady
	}
	return l.srtpEP, nil
}

// Close releases the leg's socket, ICE agent and port reservation.
// Idempotent and safe from any goroutine.
func (l *WebRTCLeg) Close() error {
	l.closeOnce.Do(func() {
		close(l.closed)
		// Take the handles under the lock, then close them outside it:
		// establish may still be running and holding the lock briefly, and
		// pion's Close paths can block.
		l.mu.Lock()
		dm, agent, mux := l.demux, l.agent, l.mux
		if !l.established && l.err == nil {
			l.err = errors.New("media: webrtc leg closed before it was established")
		}
		l.mu.Unlock()

		if dm != nil {
			_ = dm.Close()
		}
		if agent != nil {
			_ = agent.Close()
		}
		if mux != nil {
			// Closing the mux closes the underlying UDP socket.
			_ = mux.Close()
		}
		_ = l.conn.Close()
		l.pool.release(l.port)
		// Unblock anyone waiting on establishment, last: everything above
		// has already been released by the time Ready fires.
		l.readyOnce.Do(func() { close(l.ready) })
	})
	return nil
}

// newICECredentials generates an RFC 5245-conformant ufrag/pwd pair. The
// lengths are the WebRTC norm (4-byte ufrag, 24-byte password) and the
// alphabet is base64url without padding, which is inside the ice-char set.
//
// These are secrets: an attacker who learns the pwd can answer
// connectivity checks and hijack the media path. They must never be logged
// at normal levels (spec §16).
func newICECredentials() (ufrag, pwd string, err error) {
	buf := make([]byte, 3+18)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("media: ice credentials: %w", err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(buf[:3]), enc.EncodeToString(buf[3:]), nil
}
