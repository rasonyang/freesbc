package edge

// upstreams_test.go exercises the multi-FreeSWITCH pool end to end: the
// hash placement of a user's registrations and calls (D1/D5), the dialog
// record beating that hash once a call is up (D5), and the passive
// cooldown driving failover on both the REGISTER path (D2/D6) and the
// INVITE path (D6).
//
// The dead node in the failover tests is 192.0.2.1:5060, TEST-NET-1: the
// UDP socket is bound to 127.0.0.1 and a send to a non-local destination
// fails immediately with EINVAL, so the failover is triggered
// deterministically rather than by waiting for a timeout.

import (
	"fmt"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// userForNode returns a user whose hash names the pool node at idx
// (upstreamNames is sorted, so idx 0 is the alphabetically first node).
// skip names users to avoid, which is how a test gets two DISTINCT users
// that share a node.
//
// The search is a scan, not a magic constant: it stays correct if the hash
// or the pool ever changes, and the bound is generous — with two or three
// nodes a hit arrives within a couple of tries.
func userForNode(t *testing.T, topo *topology, idx int, skip ...string) string {
	t.Helper()
	for i := 0; i < 10000; i++ {
		u := fmt.Sprintf("user%d", i)
		if int(hashUpstreamUser(u)%uint64(len(topo.upstreamNames))) != idx {
			continue
		}
		skipThis := false
		for _, s := range skip {
			if s == u {
				skipThis = true
				break
			}
		}
		if !skipThis {
			return u
		}
	}
	t.Fatalf("no user hashing to node index %d of %v", idx, topo.upstreamNames)
	return ""
}

// nodeIndex is the position of a node in the sorted pool, which is the
// index userForNode's hash test uses.
func nodeIndex(t *testing.T, topo *topology, name string) int {
	t.Helper()
	for i, n := range topo.upstreamNames {
		if n == name {
			return i
		}
	}
	t.Fatalf("node %q is not in the pool %v", name, topo.upstreamNames)
	return -1
}

// waitForCall waits for the dialog record a 2xx commits. Both INVITE paths
// relay the final response BEFORE they commit the dialog, so a test that
// sends the next in-dialog request immediately would race the commit and
// could be routed by the no-record fallback instead of the record it means
// to exercise.
func waitForCall(t *testing.T, h *harness, callID string) dialogRoute {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if r, ok := h.srv.dialogs.routeFor(callID); ok {
			return r
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("dialog %s was never committed", callID)
	return dialogRoute{}
}

// authHeader is the Authorization a phone sends after a challenge. The
// value is irrelevant to the fake switch (it accepts any credential) but
// its presence is what turns the second REGISTER into the accepted one.
func authHeader(user string) string {
	return fmt.Sprintf(`Digest username="%s", realm="example.com", nonce="abc123nonce", uri="sip:example.com", response="deadbeefdeadbeefdeadbeefdeadbeef", algorithm=MD5`, user)
}

// registerUser drives the two-step digest REGISTER a phone performs —
// unauthenticated (challenged), then credentialed (accepted) — and returns
// both responses.
func registerUser(t *testing.T, c *client, user, dest string) (*sip.Response, *sip.Response) {
	t.Helper()
	first := c.do(t, c.buildRegister(user, "example.com", 600, ""), dest)
	if first.StatusCode != 401 {
		t.Fatalf("first REGISTER for %s: got %d, want 401", user, first.StatusCode)
	}
	second := c.do(t, c.buildRegister(user, "example.com", 600, authHeader(user)), dest)
	if second.StatusCode != 200 {
		t.Fatalf("authenticated REGISTER for %s: got %d, want 200", user, second.StatusCode)
	}
	return first, second
}

// TestUpstreamHashPlacement proves the per-user placement the pool is
// built on: a user's REGISTER, its refresh and the call it later places
// all start on the same node, and the other node sees none of them.
//
// The refresh is the sharp half. It must land on the node that holds the
// binding — the switches share a registration database, not a memory, so
// a refresh that followed a different hash would leave the phone
// registered on one switch while the other still believed the stale
// binding was live.
func TestUpstreamHashPlacement(t *testing.T) {
	addrA := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	addrB := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	h, switches := startHarnessUpstreams(t, "", "", map[string]string{"fs-a": addrA, "fs-b": addrB})
	fsA, fsB := switches["fs-a"], switches["fs-b"]
	topo := h.srv.topo

	user := userForNode(t, topo, nodeIndex(t, topo, "fs-a"))
	phone := newUDPClient(t)

	registerUser(t, phone, user, h.publicUDP)
	if got := len(fsA.waitFor(sip.REGISTER, 2, 3*time.Second)); got != 2 {
		t.Fatalf("fs-a saw %d REGISTERs for %s, want 2 (challenge + credential)", got, user)
	}
	if got := len(fsB.received(sip.REGISTER)); got != 0 {
		t.Errorf("fs-b saw %d REGISTERs for a user that hashes to fs-a", got)
	}

	// The refresh: an authenticated REGISTER straight to the registrar,
	// exactly what a phone sends at half the granted expiry.
	refresh := phone.do(t, phone.buildRegister(user, "example.com", 600, authHeader(user)), h.publicUDP)
	if refresh.StatusCode != 200 {
		t.Fatalf("REGISTER refresh: got %d, want 200", refresh.StatusCode)
	}
	if got := len(fsA.waitFor(sip.REGISTER, 3, 3*time.Second)); got != 3 {
		t.Errorf("fs-a saw %d REGISTERs after the refresh, want 3", got)
	}
	if got := len(fsB.received(sip.REGISTER)); got != 0 {
		t.Errorf("fs-b saw %d REGISTERs; the refresh moved nodes", got)
	}

	// A second user, hashing to the OTHER node, registers there — the
	// placement is per user, not "the first node".
	other := userForNode(t, topo, nodeIndex(t, topo, "fs-b"))
	registerUser(t, phone, other, h.publicUDP)
	if got := len(fsB.waitFor(sip.REGISTER, 2, 3*time.Second)); got != 2 {
		t.Errorf("fs-b saw %d REGISTERs for %s, want 2", got, other)
	}
	if got := len(fsA.received(sip.REGISTER)); got != 3 {
		t.Errorf("fs-a saw %d REGISTERs; a user hashing to fs-b registered through it", got)
	}

	// A call from the same user starts on the same node: the hash is over
	// the From user, and it is the same function the REGISTER used.
	invite := phone.buildInvite(user, "2002", "example.com", phoneOfferSDP(freePort(t)))
	res := phone.do(t, invite, h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: got %d, want 200", res.StatusCode)
	}
	if got := len(fsA.waitFor(sip.INVITE, 1, 3*time.Second)); got != 1 {
		t.Errorf("fs-a saw %d INVITEs from %s, want 1", got, user)
	}
	if got := len(fsB.received(sip.INVITE)); got != 0 {
		t.Errorf("fs-b saw %d INVITEs from a user that hashes to fs-a", got)
	}

	// The in-dialog traffic follows the same node, which is where the
	// dialog was established.
	sendAck(t, phone, invite, res, h.publicUDP)
	bye := buildBye(phone, invite, res)
	if byeRes := phone.do(t, bye, h.publicUDP); byeRes.StatusCode != 200 {
		t.Fatalf("BYE: got %d, want 200", byeRes.StatusCode)
	}
	if got := len(fsA.waitFor(sip.BYE, 1, 3*time.Second)); got != 1 {
		t.Errorf("fs-a saw %d BYEs, want 1", got)
	}
	if got := len(fsB.received(sip.BYE)); got != 0 {
		t.Errorf("fs-b saw %d BYEs from a call it never carried", got)
	}
	waitForRelease(t, h)
}

// TestUpstreamDialogStickiness is the record-beats-hash case (D5), the
// guarantee that a dialog never migrates between switches mid-call.
//
// The phone registers through the node its hash names (fs-a), so that is
// where its binding lives. A DIFFERENT node (fs-b) then calls it, exactly
// as FreeSWITCH would when the call arrives on the switch that owns the
// trunk. The dialog's record names fs-b, and the phone's own in-dialog
// traffic must go back there — the hash would send it to fs-a, which
// knows nothing about the call and would answer 481.
func TestUpstreamDialogStickiness(t *testing.T) {
	addrA := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	addrB := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	h, switches := startHarnessUpstreams(t, "", "", map[string]string{"fs-a": addrA, "fs-b": addrB})
	fsA, fsB := switches["fs-a"], switches["fs-b"]
	topo := h.srv.topo

	user := userForNode(t, topo, nodeIndex(t, topo, "fs-a"))
	phone := newUDPClient(t)
	registerUser(t, phone, user, h.publicUDP)

	stored := fsA.contacts()
	if len(stored) != 1 {
		t.Fatalf("fs-a stored %d contacts, want 1", len(stored))
	}
	var target sip.Uri
	if err := sip.ParseUri(stored[0], &target); err != nil {
		t.Fatalf("stored contact %q unparseable: %v", stored[0], err)
	}

	// The phone answers the inbound call: a 200 with its own SDP, a
	// Contact, a To tag, and the Record-Route set echoed in order (the
	// UAS half of RFC 3261 §12.1.1).
	toTag := sip.GenerateTagN(12)
	phoneRTP := freePort(t) // outside the handler: freePort may t.Fatal
	phone.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(phoneOfferSDP(phoneRTP)))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: phone.contactURI(user)})
		res.To().Params.Add("tag", toTag)
		for _, hh := range req.GetHeaders("Record-Route") {
			if rr, ok := hh.(*sip.RecordRouteHeader); ok {
				res.AppendHeader(&sip.RecordRouteHeader{Address: rr.Address})
			}
		}
		_ = tx.Respond(res)
	})

	// fs-b calls the contact fs-a registered — the switches share a
	// registration database, so fs-b holds the binding fs-a accepted.
	callRes := fsB.call(t, target, h.privateSIP, phoneOfferSDP(fsB.rtpPort))
	if callRes.StatusCode != 200 {
		t.Fatalf("inbound INVITE from fs-b: got %d, want 200", callRes.StatusCode)
	}

	var invite *sip.Request
	select {
	case got := <-phone.inbound:
		if got.Method != sip.INVITE {
			t.Fatalf("the phone received %s, want INVITE", got.Method)
		}
		invite = got
	case <-time.After(5 * time.Second):
		t.Fatal("fs-b's INVITE never reached the phone")
	}

	// The record the proxy committed for this dialog names fs-b — that is
	// what the assertions below depend on, so wait for it rather than race
	// it.
	rec := waitForCall(t, h, fsip.CallID(invite))
	if rec.privateRemote != addrB {
		t.Fatalf("dialog PrivateRemote = %q, want fs-b's address %q", rec.privateRemote, addrB)
	}

	// fs-b, the UAC of this dialog, owes the ACK. It travels the private
	// branch, so it is the proof that the dialog was committed rather
	// than of the public routing rule under test.
	fsB.sendAckTo2xx(t, callRes)

	// The phone ends the call. This request is in-dialog and arrives on
	// the PUBLIC side, so directionFor resolves it from the dialog record
	// — fs-b — not from the user's hash (fs-a).
	bye := phoneUASBye(t, phone, invite, toTag)
	if byeRes := phone.do(t, bye, h.publicUDP); byeRes.StatusCode != 200 {
		t.Fatalf("phone BYE: got %d, want 200", byeRes.StatusCode)
	}
	if got := len(fsB.waitFor(sip.BYE, 1, 3*time.Second)); got != 1 {
		t.Errorf("fs-b saw %d BYEs, want 1 (the record did not beat the hash)", got)
	}

	// fs-a saw the REGISTERs (the hash put the binding there) and nothing
	// else: the call never touched it.
	if got := len(fsA.received(sip.REGISTER)); got != 2 {
		t.Errorf("fs-a saw %d REGISTERs, want 2", got)
	}
	for _, m := range []sip.RequestMethod{sip.INVITE, sip.ACK, sip.BYE} {
		if got := len(fsA.received(m)); got != 0 {
			t.Errorf("fs-a saw %d %s of a call carried by fs-b", got, m)
		}
	}
	waitForRelease(t, h)
}

// phoneUASBye builds the BYE a phone sends as the UAS of an inbound call:
// Request-URI = the remote target (the Contact of the INVITE it received),
// Route = that INVITE's Record-Route set IN ORDER (RFC 3261 §12.1.1 — a
// UAS does not reverse it), From/To swapped relative to the INVITE because
// the phone is now the sender.
func phoneUASBye(t *testing.T, c *client, invite *sip.Request, toTag string) *sip.Request {
	t.Helper()
	target, ok := fsip.ContactURI(invite)
	if !ok {
		t.Fatal("the INVITE the phone received carried no Contact")
	}
	bye := sip.NewRequest(sip.BYE, target)

	from := &sip.FromHeader{Address: invite.To().Address, Params: sip.NewParams()}
	from.Params.Add("tag", toTag)
	bye.AppendHeader(from)
	to := &sip.ToHeader{Address: invite.From().Address, Params: sip.NewParams()}
	if tag, ok := invite.From().Params.Get("tag"); ok {
		to.Params.Add("tag", tag)
	}
	bye.AppendHeader(to)
	sip.CopyHeaders("Call-ID", invite, bye)
	bye.AppendHeader(&sip.CSeqHeader{SeqNo: invite.CSeq().SeqNo + 1, MethodName: sip.BYE})
	mf := sip.MaxForwardsHeader(70)
	bye.AppendHeader(&mf)
	bye.AppendHeader(&sip.ContactHeader{Address: c.contactURI(invite.To().Address.User)})
	for _, hh := range invite.GetHeaders("Record-Route") {
		rr, ok := hh.(*sip.RecordRouteHeader)
		if !ok {
			continue
		}
		bye.AppendHeader(&sip.RouteHeader{Address: rr.Address})
	}
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0",
		Transport: "UDP", Host: "127.0.0.1", Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	bye.PrependHeader(via)
	return bye
}

// TestUpstreamRegisterCooldownFailsOver proves the passive penalty (D6) on
// the REGISTER path with the one failure a UDP proxy can see at once: a
// transport error. fs-a is 192.0.2.1:5060, so the datagram cannot leave
// the socket; the REGISTER must be carried by fs-b, and fs-a must be
// cooling afterwards — the next user that hashes to fs-a must start its
// dial order at fs-b.
func TestUpstreamRegisterCooldownFailsOver(t *testing.T) {
	addrB := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	h, switches := startHarnessUpstreams(t, "", "30s", map[string]string{
		"fs-a": "192.0.2.1:5060",
		"fs-b": addrB,
	})
	fsB := switches["fs-b"]
	topo := h.srv.topo
	// Sorted pool: fs-a is index 0, the dead node.
	if topo.upstreamNames[0] != "fs-a" {
		t.Fatalf("pool %v: fs-a must sort first for this test", topo.upstreamNames)
	}
	dead := userForNode(t, topo, 0)
	other := userForNode(t, topo, 0, dead)

	phone := newUDPClient(t)
	// The unauthenticated REGISTER is enough: the challenge is what proves
	// which node served it, and the failover is what is under test.
	res := phone.do(t, phone.buildRegister(dead, "example.com", 600, ""), h.publicUDP)
	if res.StatusCode != 401 {
		t.Fatalf("REGISTER via failover: got %d, want the 401 from fs-b", res.StatusCode)
	}
	if got := len(fsB.waitFor(sip.REGISTER, 1, 3*time.Second)); got != 1 {
		t.Fatalf("fs-b saw %d REGISTERs, want 1", got)
	}
	if h.srv.upstreamCooldown.Available("fs-a") {
		t.Error("fs-a is still available after a transport error")
	}

	// The next user hashing to fs-a never even dials it: the cooled node is
	// out of the hash pool, so it sorts last, and a two-node pool hashes
	// entirely on the live node.
	order := h.srv.upstreamOrder(other)
	if len(order) != 2 || order[0] != "fs-b" || order[1] != "fs-a" {
		t.Fatalf("dial order for %s = %v, want [fs-b fs-a] while fs-a cools", other, order)
	}
	// And the registration really does land there: the phone is challenged
	// by fs-b, never by a dial to the dead node.
	res = phone.do(t, phone.buildRegister(other, "example.com", 600, ""), h.publicUDP)
	if res.StatusCode != 401 {
		t.Fatalf("REGISTER for %s: got %d, want 401 from fs-b", other, res.StatusCode)
	}
	if got := len(fsB.waitFor(sip.REGISTER, 2, 3*time.Second)); got != 2 {
		t.Errorf("fs-b saw %d REGISTERs, want 2", got)
	}
}

// TestUpstreamInviteFailsOverToLiveNode proves the same retry loop on the
// call path: an INVITE whose user hashes to the dead node is answered by
// the live one, and the dialog record names the node that actually
// answered — so the ACK and BYE that follow stick to it.
func TestUpstreamInviteFailsOverToLiveNode(t *testing.T) {
	addrB := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	h, switches := startHarnessUpstreams(t, "", "30s", map[string]string{
		"fs-a": "192.0.2.1:5060",
		"fs-b": addrB,
	})
	fsB := switches["fs-b"]
	topo := h.srv.topo
	if topo.upstreamNames[0] != "fs-a" {
		t.Fatalf("pool %v: fs-a must sort first for this test", topo.upstreamNames)
	}
	user := userForNode(t, topo, 0)

	phone := newUDPClient(t)
	invite := phone.buildInvite(user, "2002", "example.com", phoneOfferSDP(freePort(t)))
	res := phone.do(t, invite, h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE via failover: got %d, want 200 from fs-b", res.StatusCode)
	}
	if got := len(fsB.waitFor(sip.INVITE, 1, 3*time.Second)); got != 1 {
		t.Fatalf("fs-b saw %d INVITEs, want 1", got)
	}
	if h.srv.upstreamCooldown.Available("fs-a") {
		t.Error("fs-a is still available after a transport error")
	}

	// The dialog record names the node that answered, not the one the hash
	// chose — which is what makes the ACK and BYE below reach fs-b.
	rec := waitForCall(t, h, fsip.CallID(invite))
	if rec.privateRemote != addrB {
		t.Errorf("dialog PrivateRemote = %q, want the live node %q", rec.privateRemote, addrB)
	}

	sendAck(t, phone, invite, res, h.publicUDP)
	if got := len(fsB.waitFor(sip.ACK, 1, 3*time.Second)); got != 1 {
		t.Errorf("fs-b saw %d ACKs, want 1", got)
	}
	bye := buildBye(phone, invite, res)
	if byeRes := phone.do(t, bye, h.publicUDP); byeRes.StatusCode != 200 {
		t.Fatalf("BYE: got %d, want 200", byeRes.StatusCode)
	}
	if got := len(fsB.waitFor(sip.BYE, 1, 3*time.Second)); got != 1 {
		t.Errorf("fs-b saw %d BYEs, want 1", got)
	}
	waitForRelease(t, h)
}
