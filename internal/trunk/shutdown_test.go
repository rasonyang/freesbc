package trunk

import (
	"testing"
	"time"
)

// audit: P2-TRK-017
// The shutdown gate refuses new calls once draining, and reports idle only
// once every bridged call has returned; a call bridged while draining is
// told to end.
func TestCallGateDrain(t *testing.T) {
	var g callGate
	if !g.admit() {
		t.Fatal("admit refused before drain")
	}
	if g.bridge() || g.bridge() {
		t.Fatal("bridge reported draining before drain")
	}
	idle := g.drain()
	if g.admit() {
		t.Error("admit accepted a call after drain began")
	}
	g.unbridge()
	select {
	case <-idle:
		t.Fatal("idle with one bridged call left")
	case <-time.After(20 * time.Millisecond):
	}
	if !g.bridge() {
		t.Error("a call bridged while draining was not told to end")
	}
	g.unbridge()
	g.unbridge()
	select {
	case <-idle:
	case <-time.After(time.Second):
		t.Fatal("not idle after every bridged call returned")
	}

	var empty callGate
	select {
	case <-empty.drain():
	default:
		t.Error("draining a gate with no calls must be idle at once")
	}
}
