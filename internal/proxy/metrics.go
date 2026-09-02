package proxy

import (
	"errors"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/freesbc/freesbc/internal/media"
)

// Metrics are the edge proxy's counters and gauges.
//
// Deliberately free of high-cardinality labels (spec §17): a Call-ID
// belongs in a log line or a trace, never in a metric, because each
// distinct value would create a permanent time series. Methods and status
// classes are bounded sets and are safe to label by.
type Metrics struct {
	requestsIn   sync.Map // "method/transport" → *atomic.Uint64
	responsesOut sync.Map // status class ("2xx") → *atomic.Uint64

	dropped atomic.Uint64

	registrations       atomic.Int64 // gauge
	registrationTotal   atomic.Uint64
	registrationFailure atomic.Uint64

	dialogs        atomic.Int64 // gauge
	mediaSessions  atomic.Int64 // gauge
	webrtcSessions atomic.Int64 // gauge

	portFailures atomic.Uint64
	iceFailures  atomic.Uint64
	dtlsFailures atomic.Uint64

	// Media byte/packet totals, accumulated at call teardown from each
	// session's own counters. Sampling live sessions instead would need a
	// registry walk on every scrape.
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

func (m *Metrics) RequestIn(method, transport string) { bump(&m.requestsIn, method+"/"+transport) }

func (m *Metrics) ResponseOut(code int) {
	if code < 100 || code > 699 {
		return
	}
	bump(&m.responsesOut, strconv.Itoa(code/100)+"xx")
}

func (m *Metrics) Dropped()               { m.dropped.Add(1) }
func (m *Metrics) Registered()            { m.registrationTotal.Add(1) }
func (m *Metrics) RegistrationFailed()    { m.registrationFailure.Add(1) }
func (m *Metrics) SetRegistrations(n int) { m.registrations.Store(int64(n)) }
func (m *Metrics) PortAllocationFailed()  { m.portFailures.Add(1) }

func (m *Metrics) DialogStarted() { m.dialogs.Add(1) }
func (m *Metrics) DialogEnded()   { m.dialogs.Add(-1) }

func (m *Metrics) MediaStarted(webrtc bool) {
	m.mediaSessions.Add(1)
	if webrtc {
		m.webrtcSessions.Add(1)
	}
}

// MediaEnded folds a finished session's counters into the process totals
// and drops the gauges.
func (m *Metrics) MediaEnded(webrtc bool, st media.Stats) {
	m.mediaSessions.Add(-1)
	if webrtc {
		m.webrtcSessions.Add(-1)
	}
	m.rtpPacketsRx.Add(st.PublicRTPPacketsRx + st.PrivateRTPPacketsRx)
	m.rtpPacketsTx.Add(st.PublicRTPPacketsTx + st.PrivateRTPPacketsTx)
	m.rtpBytesRx.Add(st.PublicRTPBytesRx + st.PrivateRTPBytesRx)
	m.rtpBytesTx.Add(st.PublicRTPBytesTx + st.PrivateRTPBytesTx)
}

// WebRTCFailure classifies a browser-leg failure as ICE or DTLS, so an
// operator can tell "the browser never reached us" from "it reached us and
// the handshake failed" — very different problems.
func (m *Metrics) WebRTCFailure(err error) {
	if err == nil {
		return
	}
	switch {
	case errors.Is(err, media.ErrWebRTCNotReady):
		m.iceFailures.Add(1)
	case containsAny(err.Error(), "dtls", "fingerprint", "srtp"):
		m.dtlsFailures.Add(1)
	default:
		m.iceFailures.Add(1)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) <= len(s) && indexFold(s, sub) >= 0 {
			return true
		}
	}
	return false
}

// indexFold is a tiny ASCII case-insensitive substring search; the inputs
// are short error strings, so a full strings.ToLower allocation per call
// is not worth it.
func indexFold(s, sub string) int {
	lower := func(b byte) byte {
		if b >= 'A' && b <= 'Z' {
			return b + 32
		}
		return b
	}
outer:
	for i := 0; i+len(sub) <= len(s); i++ {
		for j := 0; j < len(sub); j++ {
			if lower(s[i+j]) != lower(sub[j]) {
				continue outer
			}
		}
		return i
	}
	return -1
}

// Snapshot is the flat view the admin API and the Prometheus exporter
// render.
type Snapshot struct {
	ActiveRegistrations  int64
	ActiveDialogs        int64
	ActiveMediaSessions  int64
	ActiveWebRTCSessions int64

	RegistrationTotal   uint64
	RegistrationFailure uint64

	RequestsIn   map[string]uint64
	ResponsesOut map[string]uint64
	Dropped      uint64

	RTPPacketsRx uint64
	RTPPacketsTx uint64
	RTPBytesRx   uint64
	RTPBytesTx   uint64

	MediaPortAllocationFailures uint64
	WebRTCICEFailures           uint64
	WebRTCDTLSFailures          uint64
}

func (m *Metrics) Snapshot() Snapshot {
	s := Snapshot{
		ActiveRegistrations:  m.registrations.Load(),
		ActiveDialogs:        m.dialogs.Load(),
		ActiveMediaSessions:  m.mediaSessions.Load(),
		ActiveWebRTCSessions: m.webrtcSessions.Load(),
		RegistrationTotal:    m.registrationTotal.Load(),
		RegistrationFailure:  m.registrationFailure.Load(),
		Dropped:              m.dropped.Load(),
		RequestsIn:           map[string]uint64{},
		ResponsesOut:         map[string]uint64{},
		RTPPacketsRx:         m.rtpPacketsRx.Load(),
		RTPPacketsTx:         m.rtpPacketsTx.Load(),
		RTPBytesRx:           m.rtpBytesRx.Load(),
		RTPBytesTx:           m.rtpBytesTx.Load(),

		MediaPortAllocationFailures: m.portFailures.Load(),
		WebRTCICEFailures:           m.iceFailures.Load(),
		WebRTCDTLSFailures:          m.dtlsFailures.Load(),
	}
	m.requestsIn.Range(func(k, v any) bool {
		s.RequestsIn[k.(string)] = v.(*atomic.Uint64).Load()
		return true
	})
	m.responsesOut.Range(func(k, v any) bool {
		s.ResponsesOut[k.(string)] = v.(*atomic.Uint64).Load()
		return true
	})
	return s
}
