package media

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// audit: P3-MED-BALANCE
//
// Port-pool and goroutine balance across the media layer's exit paths:
// normal Close, Close before Start, Start after Close, partial
// AllocateAcross failure, silence timeout, WebRTC handshake timeout,
// NewWebRTCSession failure, WebRTCSession Start with a cancelled context,
// and WebRTCSession Close while Start waits on the leg. After every path
// both pools must be empty and the goroutine count back to baseline.
func TestAuditMediaPortPoolAndGoroutineBalance(t *testing.T) {
	pub := newAuditPool("public", 47300, 47339, "127.0.0.1")
	priv := newAuditPool("private", 47340, 47379, "127.0.0.1")
	tiny := newAuditPool("tiny", 47380, 47381, "127.0.0.1") // exactly one pair
	id, err := ProcessDTLSIdentity()
	if err != nil {
		t.Fatal(err)
	}
	legCfg := WebRTCLegConfig{
		AdvertisedIP: netip.MustParseAddr("127.0.0.1"), Identity: id,
		RemoteUfrag: "abcd", RemotePwd: "0123456789abcdef012345",
	}
	// Warm pion's package-level goroutines.
	if warm, err := NewWebRTCLeg(pub.PlanePool, legCfg); err == nil {
		warm.Start(context.Background(), 50*time.Millisecond)
		<-warm.Ready()
	}
	baseline, _ := auditWaitGoroutines(0, 0, 500*time.Millisecond)

	check := func(t *testing.T) {
		t.Helper()
		for _, p := range []*auditPool{pub, priv, tiny} {
			deadline := time.Now().Add(2 * time.Second)
			for {
				inUse, _ := p.Stats()
				if inUse == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Errorf("pool %s: %d pairs still in use, want 0", p.name, inUse)
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
		}
	}

	t.Run("SessionCloseAfterStart", func(t *testing.T) {
		s, err := pub.Allocate(SessionConfig{Timeout: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		s.Start()
		_ = s.Close()
		_ = s.Close()
		check(t)
	})
	t.Run("SessionCloseBeforeStart_StartAfterClose", func(t *testing.T) {
		s, err := pub.Allocate(SessionConfig{Timeout: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		_ = s.Close()
		if s.Start() {
			t.Error("Start after Close reported that it started the session")
		}
		check(t)
	})
	t.Run("AllocateAcrossPartialFailure", func(t *testing.T) {
		hold, err := AllocateAcross(pub.PlanePool, tiny.PlanePool, SessionConfig{Timeout: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := AllocateAcross(pub.PlanePool, tiny.PlanePool, SessionConfig{}); !errors.Is(err, ErrPortsExhausted) {
			t.Fatalf("want ErrPortsExhausted, got %v", err)
		}
		_ = hold.Close()
		check(t)
	})
	t.Run("SessionSilenceTimeout", func(t *testing.T) {
		s, err := pub.Allocate(SessionConfig{Timeout: 100 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		s.Start()
		select {
		case <-s.Done():
		case <-time.After(3 * time.Second):
			t.Fatal("silent session never timed out")
		}
		check(t)
	})
	t.Run("WebRTCLegHandshakeTimeout", func(t *testing.T) {
		leg, err := NewWebRTCLeg(pub.PlanePool, legCfg)
		if err != nil {
			t.Fatal(err)
		}
		leg.Start(context.Background(), 150*time.Millisecond)
		<-leg.Ready()
		if leg.Err() == nil {
			t.Fatal("leg with no peer established")
		}
		check(t)
	})
	t.Run("NewWebRTCSessionPrivateExhausted", func(t *testing.T) {
		hold, err := tiny.allocatePair()
		if err != nil {
			t.Fatal(err)
		}
		leg, err := NewWebRTCLeg(pub.PlanePool, legCfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewWebRTCSession(leg, tiny.PlanePool, WebRTCSessionConfig{}); !errors.Is(err, ErrPortsExhausted) {
			t.Fatalf("want ErrPortsExhausted, got %v", err)
		}
		_ = leg.Close() // the caller still owns the leg
		hold.Close()
		tiny.release(hold.RTPPort())
		check(t)
	})
	t.Run("WebRTCSessionStartCancelled", func(t *testing.T) {
		leg, err := NewWebRTCLeg(pub.PlanePool, legCfg)
		if err != nil {
			t.Fatal(err)
		}
		sess, err := NewWebRTCSession(leg, priv.PlanePool, WebRTCSessionConfig{Timeout: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		leg.Start(context.Background(), 30*time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if err := sess.Start(ctx); err == nil {
			t.Fatal("Start with an expiring context and no browser succeeded")
		}
		check(t)
	})
	t.Run("WebRTCSessionCloseWhileStartWaits", func(t *testing.T) {
		leg, err := NewWebRTCLeg(pub.PlanePool, legCfg)
		if err != nil {
			t.Fatal(err)
		}
		sess, err := NewWebRTCSession(leg, priv.PlanePool, WebRTCSessionConfig{Timeout: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		leg.Start(context.Background(), 30*time.Second)
		errc := make(chan error, 1)
		go func() { errc <- sess.Start(context.Background()) }()
		time.Sleep(50 * time.Millisecond)
		_ = sess.Close()
		select {
		case err := <-errc:
			if err == nil {
				t.Error("Start reported success for a session closed before establishment")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Start did not return after Close")
		}
		check(t)
	})

	if got, ok := auditWaitGoroutines(baseline, 2, 5*time.Second); !ok {
		t.Errorf("goroutines not back to baseline after all exit paths: baseline=%d now=%d; %v",
			baseline, got, auditGoroutineSummary("pion/ice", "pion/dtls", "pion/transport", "internal/media"))
	}
}
