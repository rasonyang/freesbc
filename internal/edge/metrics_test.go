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
