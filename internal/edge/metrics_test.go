package edge

import (
	"errors"
	"fmt"
	"testing"

	"github.com/freesbc/freesbc/internal/media"
)

// TestWebRTCFailureClassification proves the ICE/DTLS split is decided by
// the media package's sentinels (errors.Is through whatever context the
// failure site wrapped), not by matching message text.
func TestWebRTCFailureClassification(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		ice, tls uint64
	}{
		{"nil", nil, 0, 0},
		{"ice", fmt.Errorf("start: %w", media.ErrICEFailed), 1, 0},
		{"not ready", media.ErrWebRTCNotReady, 1, 0},
		{"unclassified", errors.New("something else"), 1, 0},
		{"dtls", fmt.Errorf("start: %w", media.ErrDTLSHandshake), 0, 1},
		{"fingerprint", fmt.Errorf("verify: %w", media.ErrFingerprintMismatch), 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMetrics()
			m.WebRTCFailure(tc.err)
			s := m.Snapshot()
			if s.WebRTCICEFailures != tc.ice || s.WebRTCDTLSFailures != tc.tls {
				t.Errorf("ice=%d dtls=%d, want ice=%d dtls=%d",
					s.WebRTCICEFailures, s.WebRTCDTLSFailures, tc.ice, tc.tls)
			}
		})
	}
}

// audit: P2-EDG-002
//
// Request counters are labelled from a bounded set: known methods and
// transports keep their own label, and anything a client invents lands
// in OTHER.
func TestRequestInLabelsAreBounded(t *testing.T) {
	m := NewMetrics()
	m.RequestIn("INVITE", "UDP")
	m.RequestIn("INVITE", "udp")
	m.RequestIn("REGISTER", "wss")
	for i := 0; i < 100; i++ {
		m.RequestIn(fmt.Sprintf("X%d", i), "UDP")
		m.RequestIn("BYE", fmt.Sprintf("T%d", i))
	}
	got := m.Snapshot().RequestsIn
	want := map[string]uint64{
		"INVITE/UDP":   2,
		"REGISTER/WSS": 1,
		"OTHER/UDP":    100,
		"BYE/OTHER":    100,
	}
	if len(got) != len(want) {
		t.Fatalf("RequestsIn = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("RequestsIn[%q] = %d, want %d (all: %v)", k, got[k], v, got)
		}
	}
}

// Live sessions count in the RTP totals, and a session moving from live to
// finished is neither double counted nor allowed to move the totals back.
func TestRTPTotalsIncludeLiveSessions(t *testing.T) {
	m := NewMetrics()
	var live media.Stats
	live.A.RTPPacketsRx, live.B.RTPPacketsTx = 10, 4
	live.A.RTPBytesRx, live.B.RTPBytesTx = 1000, 400
	stats := func() media.Stats { return live }
	key := new(int)

	m.MediaStarted(false, key, stats)
	if s := m.Snapshot(); s.RTPPacketsRx != 10 || s.RTPPacketsTx != 4 || s.RTPBytesRx != 1000 || s.RTPBytesTx != 400 {
		t.Fatalf("live session not counted: %+v", s)
	}
	live.A.RTPPacketsRx = 12 // grows while live
	if s := m.Snapshot(); s.RTPPacketsRx != 12 {
		t.Fatalf("live growth not seen: %d", s.RTPPacketsRx)
	}
	before := m.Snapshot().RTPPacketsRx
	m.MediaEnded(false, key, stats)
	m.MediaEnded(false, key, stats) // a repeat must not fold twice
	after := m.Snapshot()
	if after.RTPPacketsRx != before || after.RTPPacketsTx != 4 || after.RTPBytesRx != 1000 {
		t.Fatalf("totals moved across close: before %d after %+v", before, after)
	}
	// A second session adds on top of the finished total.
	m.MediaStarted(false, new(int), func() media.Stats {
		var st media.Stats
		st.A.RTPPacketsRx = 5
		return st
	})
	if got := m.Snapshot().RTPPacketsRx; got != 17 {
		t.Fatalf("second session: got %d want 17", got)
	}
}
