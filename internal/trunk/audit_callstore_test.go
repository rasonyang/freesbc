package trunk

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/freesbc/freesbc/internal/config"
)

func auditBareServer(t *testing.T) *Server {
	t.Helper()
	store := config.NewStore(mustMinimalCfg(t))
	return NewServer(store, NewMediaPool(store), slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// audit: P2-TRK-002
// RFC 3261 §12: a dialog is Call-ID + local tag + remote tag. Two live calls
// whose A-legs share a Call-ID (a peer reusing a Call-ID, or a forking
// upstream proxy delivering the same INVITE twice with different branches)
// are distinct dialogs. Ending one must not remove the other from the store.
func TestAuditCallStoreSameCallIDOverwrite(t *testing.T) {
	s := auditBareServer(t)

	_, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel1()
	defer cancel2()
	c1 := &call{id: "dup-callid", bID: "b-1", cancel: cancel1,
		aSDP: legSDP{fromTag: "caller-tag", toTag: "sbc-tag-1"}}
	c2 := &call{id: "dup-callid", bID: "b-2", cancel: cancel2,
		aSDP: legSDP{fromTag: "caller-tag", toTag: "sbc-tag-2"}}

	s.registerCall(c1)
	s.registerCall(c2)
	if got := s.ActiveCalls(); got != 2 {
		t.Errorf("after registering two distinct dialogs sharing a Call-ID: ActiveCalls = %d, want 2", got)
	}

	s.endCall(c1)
	if got := s.ActiveCalls(); got != 1 {
		t.Errorf("after ending call 1: ActiveCalls = %d, want 1 (call 2 is still live)", got)
	}
	if _, ok := s.lookupLeg("dup-callid"); !ok {
		t.Errorf("after ending call 1: call 2's A-leg is no longer indexed; its refreshes would get 501")
	}
	if ctx2.Err() != nil {
		t.Errorf("ending call 1 cancelled call 2's kick context")
	}
	if !s.KillCall("dup-callid") {
		t.Errorf("KillCall cannot reach live call 2 after call 1 ended")
	}
}

// audit: P2-TRK-002
// KillCall by the admin id must target one specific call. With two live
// calls under the same A-leg Call-ID, the store keeps only the last one, so
// the first is unreachable from admin while still bridged.
func TestAuditCallStoreFirstCallUnkillable(t *testing.T) {
	s := auditBareServer(t)
	ctx1, cancel1 := context.WithCancel(context.Background())
	_, cancel2 := context.WithCancel(context.Background())
	defer cancel1()
	defer cancel2()
	c1 := &call{id: "dup2", bID: "b-1", cancel: cancel1}
	c2 := &call{id: "dup2", bID: "b-2", cancel: cancel2}
	s.registerCall(c1)
	s.registerCall(c2)
	if len(s.Calls()) != 2 {
		t.Errorf("Calls() lists %d records, want 2 live calls", len(s.Calls()))
	}
	s.KillCall("dup2")
	s.KillCall("dup2")
	if ctx1.Err() == nil {
		t.Errorf("call 1 is still bridged but no KillCall can reach it")
	}
}
