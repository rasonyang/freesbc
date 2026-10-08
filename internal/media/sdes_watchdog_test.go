package media

import (
	"testing"
	"time"
)

// Unauthenticated packets must not feed the silence watchdog: a flood of
// forgeries cannot keep a dead SDES call alive.
func TestSDESForgeriesDoNotRefreshWatchdog(t *testing.T) {
	s := newLooseSession(t, 21400, 21407, 400*time.Millisecond)
	if err := s.SetSDESRemote(SideA, sdesKey(SDESAESCM128HMACSHA180, 14, 0x11)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSDESLocal(SideA, sdesKey(SDESAESCM128HMACSHA180, 14, 0x22)); err != nil {
		t.Fatal(err)
	}
	s.Start()
	a := dialSide(t, s, SideA)
	r := &sdesRig{seq: 1}
	deadline := time.After(3 * time.Second)
	for {
		_, _ = a.Write(r.rtpPacket("forged"))
		select {
		case <-s.Done():
			if s.Cause() != CloseSilence {
				t.Fatalf("cause = %v", s.Cause())
			}
			return
		case <-deadline:
			t.Fatal("forged packets kept the session alive")
		case <-time.After(20 * time.Millisecond):
		}
	}
}
