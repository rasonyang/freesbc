package edge

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// Timing-based over real UDP loopback: re-run once before treating a flake
// as failure.

// TestNon2xxAckIsAbsorbedWithoutAckMissed: the switch challenges the INVITE
// with 407 and the caller's hop-by-hop ACK reuses the INVITE branch, so
// sipgo hands it to the server transaction. Nothing may park on it: no
// "ACK missed" Warn once the transaction ends (Timer I, 5 s on UDP), and the
// ACK is not relayed (the edge's own client transaction ACKs the switch).
func TestNon2xxAckIsAbsorbedWithoutAckMissed(t *testing.T) {
	h, rec := startHarnessRecorded(t, false)
	phone := newUDPClient(t)
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 407, "Proxy Authentication Required", nil))
		return true
	})

	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30099))
	if res := phone.do(t, invite, h.publicUDP); res.StatusCode != 407 {
		t.Fatalf("INVITE: got %d, want 407", res.StatusCode)
	}
	callID := invite.CallID().Value()

	deadline := time.Now().Add(3 * time.Second)
	absorbed := false
	for !absorbed && time.Now().Before(deadline) {
		for _, r := range rec.snapshot() {
			if r.msg == "ACK to a non-2xx final absorbed" && r.attrs["sip_call_id"] == callID {
				absorbed = true
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !absorbed {
		t.Error("the caller's non-2xx ACK never reached the drainer")
	}

	// Past Timer I, where sipgo would have logged "ACK missed" on the edge.
	time.Sleep(6 * time.Second)
	for _, r := range rec.snapshot() {
		if r.msg == "ACK missed" {
			t.Errorf("sipgo logged %q at %v", r.msg, r.level)
		}
	}
	// The edge's own hop ACK for the 407 is the transaction layer's and never
	// reaches the switch's ACK handler; a relayed one would.
	if acks := h.fs.received(sip.ACK); len(acks) != 0 {
		t.Errorf("switch saw %d relayed ACKs, want none", len(acks))
	}
}

// TestAckReusingInviteBranchTo2xxIsForwarded: a client that reuses the
// INVITE branch for the ACK of a 2xx matches the server transaction, so
// sipgo never calls the ACK handler. The edge must still forward it.
func TestAckReusingInviteBranchTo2xxIsForwarded(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)

	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30099))
	res := phone.do(t, invite, h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: got %d, want 200", res.StatusCode)
	}
	branch, _ := invite.Via().Params.Get("branch")
	if branch == "" {
		t.Fatal("INVITE carries no branch")
	}
	sendAckBranch(t, phone, invite, res, h.publicUDP, branch)
	if acks := h.fs.waitFor(sip.ACK, 1, 3*time.Second); len(acks) != 1 {
		t.Fatalf("switch saw %d ACKs, want 1", len(acks))
	}

	bye := buildBye(phone, invite, res)
	if r := phone.do(t, bye, h.publicUDP); r.StatusCode != 200 {
		t.Errorf("BYE: got %d", r.StatusCode)
	}
	waitForRelease(t, h)
}

// TestDrainAcksBoundAfter2xx is #170's remaining part: after a 2xx final the
// drainAcks goroutine ends at ack2xxWait, not with the transaction (Timer L,
// 32 s); after a non-2xx it still lives until the transaction's Done.
func TestDrainAcksBoundAfter2xx(t *testing.T) {
	const bound = 300 * time.Millisecond
	pubUDP, priv, up := freePort(t), freePort(t), freePort(t)
	h := newHarness(t, harnessYAML(t, []string{fmt.Sprintf("127.0.0.1:%d", up)},
		pubUDP, 0, 0, nextMediaBase(t), harnessCarrierSources), priv)
	h.srv.ack2xxWait = bound
	h.upstream = fmt.Sprintf("127.0.0.1:%d", up)
	h.fs = startFakeSwitch(t, h.upstream)
	h.run()
	phone := newUDPClient(t)

	// 2xx: the call's drainer is gone soon after the bound.
	before := drainerIDs()
	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30099))
	res := phone.do(t, invite, h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: got %d, want 200", res.StatusCode)
	}
	mine := newDrainers(t, before)
	sendAck(t, phone, invite, res, h.publicUDP)
	if left := waitDrainersGone(mine, bound+2*time.Second); left != 0 {
		t.Errorf("2xx: %d drainAcks goroutines still running past the %v bound", left, bound)
	}
	if r := phone.do(t, buildBye(phone, invite, res), h.publicUDP); r.StatusCode != 200 {
		t.Errorf("BYE: got %d", r.StatusCode)
	}
	waitForRelease(t, h)

	// Non-2xx: the bound does not apply; the drainer ends with the
	// transaction (Timer I, 5 s on UDP, after the branch-reusing ACK).
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 486, "Busy Here", nil))
		return true
	})
	before = drainerIDs()
	invite = phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30099))
	if res := phone.do(t, invite, h.publicUDP); res.StatusCode != 486 {
		t.Fatalf("INVITE: got %d, want 486", res.StatusCode)
	}
	mine = newDrainers(t, before)
	time.Sleep(bound + time.Second)
	if left := waitDrainersGone(mine, 0); left != len(mine) {
		t.Fatalf("non-2xx: drainAcks ended before the transaction (%d of %d left)", left, len(mine))
	}
	if left := waitDrainersGone(mine, 10*time.Second); left != 0 {
		t.Errorf("non-2xx: %d drainAcks goroutines outlived the transaction", left)
	}
}

// drainerIDs is the set of goroutine IDs running a drainAcks goroutine.
func drainerIDs() map[string]bool {
	buf := make([]byte, 16<<20)
	n := runtime.Stack(buf, true)
	ids := map[string]bool{}
	for _, g := range strings.Split(string(buf[:n]), "\n\n") {
		if strings.Contains(g, "(*Server).drainAcks.func") {
			ids[strings.Fields(g)[1]] = true
		}
	}
	return ids
}

// newDrainers waits briefly for the drainer guard starts once the INVITE
// handler returns, and reports the drainers not in before.
func newDrainers(t *testing.T, before map[string]bool) map[string]bool {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		mine := map[string]bool{}
		for id := range drainerIDs() {
			if !before[id] {
				mine[id] = true
			}
		}
		if len(mine) > 0 {
			return mine
		}
		if time.Now().After(deadline) {
			t.Fatal("no drainAcks goroutine started for the INVITE")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitDrainersGone waits up to d for the drainers in ids to end, and
// reports how many are left.
func waitDrainersGone(ids map[string]bool, d time.Duration) int {
	deadline := time.Now().Add(d)
	for {
		left := 0
		for id := range drainerIDs() {
			if ids[id] {
				left++
			}
		}
		if left == 0 || time.Now().After(deadline) {
			return left
		}
		time.Sleep(20 * time.Millisecond)
	}
}
