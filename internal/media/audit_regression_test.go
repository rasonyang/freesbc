package media

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// Regression tests for audit findings that had no test in the audit
// itself. They draw ports from 24700-24999, which the audit suites leave
// free.

// audit: P2-MED-012
//
// Start must be a one-shot transition out of legAllocated. A second Start
// used to launch a second establish over the same socket, whose ICE agent
// replaced the first in l.agent and was never closed; a Start after Close
// launched an establish nobody would ever tear down.
func TestAuditMED012StartIsOneShot(t *testing.T) {
	pool := newAuditPool("public", 24700, 24739, "127.0.0.1")
	id, err := ProcessDTLSIdentity()
	if err != nil {
		t.Fatal(err)
	}
	cfg := WebRTCLegConfig{
		AdvertisedIP: netip.MustParseAddr("127.0.0.1"), Identity: id,
		RemoteUfrag: "abcd", RemotePwd: "0123456789abcdef012345",
	}
	// Warm up pion's package-level state so it is not counted as a leak.
	if warm, err := NewWebRTCLeg(pool.PlanePool, cfg); err == nil {
		warm.Start(context.Background(), 50*time.Millisecond)
		<-warm.Ready()
	}
	baseline, _ := auditWaitGoroutines(0, 0, 500*time.Millisecond)

	const establishTimeout = 200 * time.Millisecond
	t.Run("TwiceThenClose", func(t *testing.T) {
		leg, err := NewWebRTCLeg(pool.PlanePool, cfg)
		if err != nil {
			t.Fatal(err)
		}
		leg.Start(context.Background(), time.Hour)
		leg.Start(context.Background(), time.Hour)
		time.Sleep(50 * time.Millisecond) // let both establishes build an agent
		_ = leg.Close()
		<-leg.Ready()
	})
	t.Run("AfterClose", func(t *testing.T) {
		leg, err := NewWebRTCLeg(pool.PlanePool, cfg)
		if err != nil {
			t.Fatal(err)
		}
		_ = leg.Close()
		leg.Start(context.Background(), establishTimeout)
		<-leg.Ready()
		if leg.Err() == nil {
			t.Error("a leg started after Close reported success")
		}
	})
	time.Sleep(establishTimeout + 100*time.Millisecond)
	if inUse, _ := pool.Stats(); inUse != 0 {
		t.Errorf("pool in use after closing every leg: %d, want 0", inUse)
	}
	if got, ok := auditWaitGoroutines(baseline, 2, 5*time.Second); !ok {
		t.Errorf("P2-MED-012: goroutines did not return to baseline: baseline=%d now=%d; stacks %v",
			baseline, got, auditGoroutineSummary("pion/ice", "pion/transport", "media.(*WebRTCLeg)"))
	}
}
