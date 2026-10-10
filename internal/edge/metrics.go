package edge

import (
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/media"
)

// Metrics are the edge proxy's counters and gauges.
//
// Deliberately free of high-cardinality labels (spec §17): a Call-ID
// belongs in a log line or a trace, never in a metric, because each
// distinct value would create a permanent time series. Status classes are a
// bounded set; request methods and transports come off the wire, so they
// are bounded here (metricMethods, metricTransports) with one "OTHER"
// bucket each rather than labelled by whatever a client wrote
// (P2-EDG-002).
type Metrics struct {
	// requestsIn is a fixed table, one counter per known method (plus
	// OTHER) per known transport (plus OTHER): no request can add a row.
	requestsIn   [len(metricMethods) + 1][len(metricTransports) + 1]atomic.Uint64
	responsesOut sync.Map // status class ("2xx") → *atomic.Uint64

	registrations       atomic.Int64 // gauge
	subscriptions       atomic.Int64 // gauge
	registrationTotal   atomic.Uint64
	registrationFailure atomic.Uint64

	dialogs        atomic.Int64 // gauge
	sessions       atomic.Int64 // gauge: calls holding a session slot
	draining       atomic.Int64 // gauge: 1 while the edge is in drain mode
	mediaSessions  atomic.Int64 // gauge
	webrtcSessions atomic.Int64 // gauge

	portFailures  atomic.Uint64
	iceFailures   atomic.Uint64
	dtlsFailures  atomic.Uint64
	handlerPanics atomic.Uint64

	// parseFailures counts messages sipgo's parser rejected on a read, one
	// counter per known transport plus OTHER (sipgolog.go).
	parseFailures [len(metricTransports) + 1]atomic.Uint64

	// admissionDrops counts public requests dropped silently by the
	// admission policy, one counter per (fixed) reason (admission.go).
	admissionDrops [numDropReasons]atomic.Uint64

	// callsEnded counts confirmed calls by the reason they ended
	// (dialog.go), one counter per (fixed) reason.
	callsEnded [numEndReasons]atomic.Uint64

	// inviteRejects counts final responses the edge itself originated to an
	// out-of-dialog INVITE, one counter per (fixed) reason (invite.go).
	inviteRejects [numInviteRejects]atomic.Uint64

	// streamConns is the gauge of open stream connections per transport
	// (streamTransports); streamRefused counts connections refused at
	// accept, streamClosed connections closed by policy, both by (fixed)
	// reason (stream.go).
	streamConns   [len(streamTransports)]atomic.Int64
	streamRefused [numStreamRefusals]atomic.Uint64
	streamClosed  [numStreamCloses]atomic.Uint64

	// carrierReqs counts requests of the carrier path by (carrier,
	// direction, method) — key "carrier/direction/method". The carrier is a
	// configured name or "unknown", the direction one of two, the method
	// folded like requestsIn, so the set is bounded.
	carrierReqs sync.Map // string → *atomic.Uint64

	// carrierRegs is the live carrier registration count per carrier name
	// (a configured name, so the set is bounded), replaced whole by
	// SetCarrierRegistrations.
	carrierRegsMu sync.Mutex
	carrierRegs   map[string]int64

	// Media byte/packet totals of finished sessions, folded in at call
	// teardown. A scrape adds the live sessions' own atomic counters on top
	// (rtpTotals). mediaMu makes "drop from live, add to finished" one step
	// against a scrape, so a session is never counted twice or missed.
	mediaMu      sync.Mutex
	liveMedia    map[any]func() media.Stats
	rtpPacketsRx atomic.Uint64
	rtpPacketsTx atomic.Uint64
	rtpBytesRx   atomic.Uint64
	rtpBytesTx   atomic.Uint64
}

func NewMetrics() *Metrics { return &Metrics{} }

func bump(m *sync.Map, key string) {
	v, ok := m.Load(key)
	if !ok {
		v, _ = m.LoadOrStore(key, new(atomic.Uint64))
	}
	v.(*atomic.Uint64).Add(1)
}

// metricOther is the label of the bucket every unknown method or
// transport is counted in.
const metricOther = "OTHER"

// metricMethods are the request methods counted under their own label: the
// methods sipgo names (RFC 3261 and its extensions). Anything else is
// OTHER.
var metricMethods = [...]sip.RequestMethod{
	sip.INVITE, sip.ACK, sip.CANCEL, sip.BYE, sip.REGISTER, sip.OPTIONS,
	sip.SUBSCRIBE, sip.NOTIFY, sip.REFER, sip.INFO, sip.MESSAGE, sip.PRACK,
	sip.UPDATE, sip.PUBLISH,
}

// metricTransports are the transports counted under their own label,
// matched case-insensitively and labelled in upper case as a Via writes
// them (RFC 3261 §20.42). Anything else is OTHER.
var metricTransports = [...]string{"UDP", "TCP", "TLS", "WS", "WSS"}

func methodIndex(method string) int {
	for i, m := range metricMethods {
		if string(m) == method {
			return i
		}
	}
	return len(metricMethods)
}

func transportIndex(transport string) int {
	for i, t := range metricTransports {
		if strings.EqualFold(t, transport) {
			return i
		}
	}
	return len(metricTransports)
}

// RequestIn counts one received request by method and transport, each
// folded into a bounded label set.
func (m *Metrics) RequestIn(method, transport string) {
	m.requestsIn[methodIndex(method)][transportIndex(transport)].Add(1)
}

func (m *Metrics) ResponseOut(code int) {
	if code < 100 || code > 699 {
		return
	}
	bump(&m.responsesOut, strconv.Itoa(code/100)+"xx")
}

func (m *Metrics) Registered()            { m.registrationTotal.Add(1) }
func (m *Metrics) RegistrationFailed()    { m.registrationFailure.Add(1) }
func (m *Metrics) SetRegistrations(n int) { m.registrations.Store(int64(n)) }

// SetSubscriptions publishes the live subscription record count.
func (m *Metrics) SetSubscriptions(n int) { m.subscriptions.Store(int64(n)) }

func (m *Metrics) PortAllocationFailed() { m.portFailures.Add(1) }

// AdmissionDropped counts one public request dropped by admission.
func (m *Metrics) AdmissionDropped(r dropReason) { m.admissionDrops[r].Add(1) }

// CallEnded counts one confirmed call that ended, by reason.
func (m *Metrics) CallEnded(r endReason) { m.callsEnded[r].Add(1) }

// InviteRejected counts one out-of-dialog INVITE the edge refused itself.
func (m *Metrics) InviteRejected(r inviteReject) { m.inviteRejects[r].Add(1) }

// StreamConnOpened and StreamConnClosed move the open-connection gauge of
// one stream transport.
func (m *Metrics) StreamConnOpened(transport string) {
	if i := streamIndex(transport); i >= 0 {
		m.streamConns[i].Add(1)
	}
}

func (m *Metrics) StreamConnClosed(transport string) {
	if i := streamIndex(transport); i >= 0 {
		m.streamConns[i].Add(-1)
	}
}

// StreamRefused counts one connection refused at accept.
func (m *Metrics) StreamRefused(r streamRefusal) { m.streamRefused[r].Add(1) }

// StreamClosed counts one connection closed by policy.
func (m *Metrics) StreamClosed(r streamClose) { m.streamClosed[r].Add(1) }

// CarrierRequest counts one request of the carrier path.
func (m *Metrics) CarrierRequest(carrier, direction, method string) {
	label := metricOther
	if i := methodIndex(method); i < len(metricMethods) {
		label = string(metricMethods[i])
	}
	bump(&m.carrierReqs, carrier+"/"+direction+"/"+label)
}

// SetCarrierRegistrations publishes the live carrier registration counts
// per carrier name.
func (m *Metrics) SetCarrierRegistrations(counts map[string]int) {
	next := make(map[string]int64, len(counts))
	for k, v := range counts {
		next[k] = int64(v)
	}
	m.carrierRegsMu.Lock()
	m.carrierRegs = next
	m.carrierRegsMu.Unlock()
}

// HandlerPanicked counts a SIP handler panic the guard recovered.
func (m *Metrics) HandlerPanicked() { m.handlerPanics.Add(1) }

// ParseFailed counts one read sipgo's parser rejected, by transport (folded
// into the bounded label set).
func (m *Metrics) ParseFailed(transport string) { m.parseFailures[transportIndex(transport)].Add(1) }

// SetSessions publishes the dialog table's session count.
func (m *Metrics) SetSessions(n int) { m.sessions.Store(int64(n)) }

// SetDraining publishes the drain-mode gauge.
func (m *Metrics) SetDraining(on bool) {
	if on {
		m.draining.Store(1)
	} else {
		m.draining.Store(0)
	}
}

func (m *Metrics) DialogStarted() { m.dialogs.Add(1) }
func (m *Metrics) DialogEnded()   { m.dialogs.Add(-1) }

// MediaStarted counts a confirmed session and registers its counters as
// live: key identifies the session and stats reads its atomic counters.
func (m *Metrics) MediaStarted(webrtc bool, key any, stats func() media.Stats) {
	m.mediaSessions.Add(1)
	if webrtc {
		m.webrtcSessions.Add(1)
	}
	m.mediaMu.Lock()
	if m.liveMedia == nil {
		m.liveMedia = map[any]func() media.Stats{}
	}
	m.liveMedia[key] = stats
	m.mediaMu.Unlock()
}

// MediaEnded moves a finished session from live to the process totals and
// drops the gauges. The final counters are read again under mediaMu, after
// the session closed: counters only grow, so the folded value is never below
// what an earlier scrape saw live and the totals never go backwards.
func (m *Metrics) MediaEnded(webrtc bool, key any, stats func() media.Stats) {
	m.mediaSessions.Add(-1)
	if webrtc {
		m.webrtcSessions.Add(-1)
	}
	m.mediaMu.Lock()
	defer m.mediaMu.Unlock()
	if _, ok := m.liveMedia[key]; !ok {
		return
	}
	delete(m.liveMedia, key)
	t := stats().Total()
	m.rtpPacketsRx.Add(t.RTPPacketsRx)
	m.rtpPacketsTx.Add(t.RTPPacketsTx)
	m.rtpBytesRx.Add(t.RTPBytesRx)
	m.rtpBytesTx.Add(t.RTPBytesTx)
}

// rtpTotals is the finished sessions' totals plus the live sessions'
// current counters, sampled now.
func (m *Metrics) rtpTotals() media.LegStats {
	m.mediaMu.Lock()
	defer m.mediaMu.Unlock()
	t := media.LegStats{
		RTPPacketsRx: m.rtpPacketsRx.Load(),
		RTPPacketsTx: m.rtpPacketsTx.Load(),
		RTPBytesRx:   m.rtpBytesRx.Load(),
		RTPBytesTx:   m.rtpBytesTx.Load(),
	}
	for _, stats := range m.liveMedia {
		l := stats().Total()
		t.RTPPacketsRx += l.RTPPacketsRx
		t.RTPPacketsTx += l.RTPPacketsTx
		t.RTPBytesRx += l.RTPBytesRx
		t.RTPBytesTx += l.RTPBytesTx
	}
	return t
}

// WebRTCFailure classifies a browser-leg failure as ICE or DTLS, so an
// operator can tell "the browser never reached us" from "it reached us and
// the handshake failed" — very different problems.
func (m *Metrics) WebRTCFailure(err error) {
	if err == nil {
		return
	}
	switch {
	case errors.Is(err, media.ErrDTLSHandshake), errors.Is(err, media.ErrFingerprintMismatch):
		m.dtlsFailures.Add(1)
	default:
		// ICE is the catch-all: media.ErrICEFailed, ErrWebRTCNotReady, and
		// a leg closed before it established all mean the browser's media
		// never reached us.
		m.iceFailures.Add(1)
	}
}

// Snapshot is the flat view the admin API and the Prometheus exporter
// render.
type Snapshot struct {
	ActiveRegistrations  int64
	ActiveSubscriptions  int64
	ActiveDialogs        int64
	ActiveSessions       int64
	ActiveMediaSessions  int64
	ActiveWebRTCSessions int64

	// Draining is true while the edge refuses new INVITEs (drain.go).
	Draining bool

	RegistrationTotal   uint64
	RegistrationFailure uint64

	RequestsIn   map[string]uint64
	ResponsesOut map[string]uint64

	RTPPacketsRx uint64
	RTPPacketsTx uint64
	RTPBytesRx   uint64
	RTPBytesTx   uint64

	MediaPortAllocationFailures uint64
	WebRTCICEFailures           uint64
	WebRTCDTLSFailures          uint64
	HandlerPanics               uint64

	// ParseFailures is keyed by upper-case transport (or OTHER); every
	// transport is present, zero or not.
	ParseFailures map[string]uint64

	// AdmissionDrops is keyed by drop reason (dropReasonLabels); every
	// reason is present, zero or not.
	AdmissionDrops map[string]uint64

	// CallsEnded is keyed by end reason (endReasonLabels), InviteRejects by
	// reject reason (inviteRejectLabels); every reason is present, zero or
	// not.
	CallsEnded    map[string]uint64
	InviteRejects map[string]uint64

	// StreamConnections is the open stream connections by lower-case
	// transport (tcp, tls, ws, wss), every one present. StreamRefused is
	// keyed by refusal reason and StreamClosed by policy-close reason, every
	// reason present.
	StreamConnections map[string]int64
	StreamRefused     map[string]uint64
	StreamClosed      map[string]uint64

	// CarrierRequests is keyed "carrier/direction/method".
	CarrierRequests map[string]uint64

	// CarrierRegistrations is the live registration count per carrier.
	CarrierRegistrations map[string]int64
}

func (m *Metrics) Snapshot() Snapshot {
	rtp := m.rtpTotals()
	s := Snapshot{
		ActiveRegistrations:  m.registrations.Load(),
		ActiveSubscriptions:  m.subscriptions.Load(),
		ActiveDialogs:        m.dialogs.Load(),
		ActiveSessions:       m.sessions.Load(),
		ActiveMediaSessions:  m.mediaSessions.Load(),
		ActiveWebRTCSessions: m.webrtcSessions.Load(),
		Draining:             m.draining.Load() == 1,
		RegistrationTotal:    m.registrationTotal.Load(),
		RegistrationFailure:  m.registrationFailure.Load(),
		RequestsIn:           map[string]uint64{},
		ResponsesOut:         map[string]uint64{},
		RTPPacketsRx:         rtp.RTPPacketsRx,
		RTPPacketsTx:         rtp.RTPPacketsTx,
		RTPBytesRx:           rtp.RTPBytesRx,
		RTPBytesTx:           rtp.RTPBytesTx,

		MediaPortAllocationFailures: m.portFailures.Load(),
		HandlerPanics:               m.handlerPanics.Load(),
		WebRTCICEFailures:           m.iceFailures.Load(),
		WebRTCDTLSFailures:          m.dtlsFailures.Load(),
		AdmissionDrops:              map[string]uint64{},
		CallsEnded:                  map[string]uint64{},
		InviteRejects:               map[string]uint64{},
		ParseFailures:               map[string]uint64{},
		CarrierRequests:             map[string]uint64{},
		CarrierRegistrations:        map[string]int64{},
		StreamConnections:           map[string]int64{},
		StreamRefused:               map[string]uint64{},
		StreamClosed:                map[string]uint64{},
	}
	for i, t := range streamTransports {
		s.StreamConnections[t] = m.streamConns[i].Load()
	}
	for r := range m.streamRefused {
		s.StreamRefused[streamRefusalLabels[r]] = m.streamRefused[r].Load()
	}
	for r := 1; r < len(m.streamClosed); r++ {
		s.StreamClosed[streamCloseLabels[r]] = m.streamClosed[r].Load()
	}
	m.carrierRegsMu.Lock()
	for k, v := range m.carrierRegs {
		s.CarrierRegistrations[k] = v
	}
	m.carrierRegsMu.Unlock()
	m.carrierReqs.Range(func(k, v any) bool {
		s.CarrierRequests[k.(string)] = v.(*atomic.Uint64).Load()
		return true
	})
	for i := range m.parseFailures {
		label := metricOther
		if i < len(metricTransports) {
			label = metricTransports[i]
		}
		s.ParseFailures[label] = m.parseFailures[i].Load()
	}
	for r := range m.admissionDrops {
		s.AdmissionDrops[dropReasonLabels[r]] = m.admissionDrops[r].Load()
	}
	for r := range m.callsEnded {
		s.CallsEnded[endReasonLabels[r]] = m.callsEnded[r].Load()
	}
	for r := range m.inviteRejects {
		s.InviteRejects[inviteRejectLabels[r]] = m.inviteRejects[r].Load()
	}
	for i := range m.requestsIn {
		method := metricOther
		if i < len(metricMethods) {
			method = string(metricMethods[i])
		}
		for j := range m.requestsIn[i] {
			n := m.requestsIn[i][j].Load()
			if n == 0 {
				continue // as before: a label pair appears once it is counted
			}
			transport := metricOther
			if j < len(metricTransports) {
				transport = metricTransports[j]
			}
			s.RequestsIn[method+"/"+transport] = n
		}
	}
	m.responsesOut.Range(func(k, v any) bool {
		s.ResponsesOut[k.(string)] = v.(*atomic.Uint64).Load()
		return true
	})
	return s
}
