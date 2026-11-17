package edge

import (
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// Tests for the call-path credential check (issue #288; credentialcheck.go).
// Timing-based over real UDP loopback: re-run once before treating a flake
// as failure.

// registerAs registers user from c, proved by a credential for authUser.
func registerAs(t *testing.T, h *harness, c *client, user, authUser string) {
	t.Helper()
	if res := c.do(t, proofRegister(c, user, authUser, true), h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("REGISTER %s as %s: %d", user, authUser, res.StatusCode)
	}
}

// busyInvites makes the fake switch answer every INVITE 486, so a forwarded
// one leaves no dialog behind.
func busyInvites(h *harness) {
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 486, "Busy Here", nil))
		return true
	})
}

func inviteWithCredential(c *client, authHeader, authUser string) *sip.Request {
	req := c.buildInvite("1001", "2002", "example.com", phoneOfferSDP(4000))
	if authHeader != "" {
		req.AppendHeader(sip.NewHeader(authHeader, digest(authUser, "abc123nonce", "guess")))
	}
	return req
}

func credMismatches(h *harness) map[string]uint64 {
	return h.srv.metrics.Snapshot().CredentialMismatches
}

// Every method's refusal: 403 from the edge, nothing forwarded, counted.
func TestCredentialMismatchRefusedPerMethod(t *testing.T) {
	h, rec := startProofHarness(t, false)
	busyInvites(h)
	c := newUDPClient(t)
	registerAs(t, h, c, "1001", "1001")

	t.Run("INVITE", func(t *testing.T) {
		before := h.srv.metrics.Snapshot().InviteRejects["credential_mismatch"]
		res := c.do(t, inviteWithCredential(c, "Proxy-Authorization", "1002"), h.publicUDP)
		if res.StatusCode != 403 {
			t.Fatalf("got %d, want 403", res.StatusCode)
		}
		if got := h.fs.received(sip.INVITE); len(got) != 0 {
			t.Errorf("the switch saw %d INVITEs", len(got))
		}
		if got := credMismatches(h)["INVITE"]; got != 1 {
			t.Errorf("credential_mismatch{INVITE} = %d, want 1", got)
		}
		if got := h.srv.metrics.Snapshot().InviteRejects["credential_mismatch"]; got != before+1 {
			t.Errorf("invite_rejects{credential_mismatch} = %d, want %d", got, before+1)
		}
	})
	t.Run("MESSAGE", func(t *testing.T) {
		req := c.buildMessage("1001", "2002", "hi")
		req.AppendHeader(sip.NewHeader("Authorization", digest("1002", "abc123nonce", "guess")))
		if res := c.do(t, req, h.publicUDP); res.StatusCode != 403 {
			t.Fatalf("got %d, want 403", res.StatusCode)
		}
		if got := h.fs.received(sip.MESSAGE); len(got) != 0 {
			t.Errorf("the switch saw %d MESSAGEs", len(got))
		}
		if got := credMismatches(h)["MESSAGE"]; got != 1 {
			t.Errorf("credential_mismatch{MESSAGE} = %d, want 1", got)
		}
	})
	t.Run("SUBSCRIBE", func(t *testing.T) {
		req := c.buildSubscribe("1001", "dialog", 600)
		req.AppendHeader(sip.NewHeader("Proxy-Authorization", digest("1002", "abc123nonce", "guess")))
		if res := c.do(t, req, h.publicUDP); res.StatusCode != 403 {
			t.Fatalf("got %d, want 403", res.StatusCode)
		}
		if got := h.fs.received(sip.SUBSCRIBE); len(got) != 0 {
			t.Errorf("the switch saw %d SUBSCRIBEs", len(got))
		}
		if got := credMismatches(h)["SUBSCRIBE"]; got != 1 {
			t.Errorf("credential_mismatch{SUBSCRIBE} = %d, want 1", got)
		}
	})
	// An unparseable credential is refused too, and the refusal is logged
	// with the username and never the response.
	t.Run("no username", func(t *testing.T) {
		req := c.buildInvite("1001", "2002", "example.com", phoneOfferSDP(4000))
		req.AppendHeader(sip.NewHeader("Authorization", "Digest realm=\"example.com\", response=\"secretresp\""))
		if res := c.do(t, req, h.publicUDP); res.StatusCode != 403 {
			t.Fatalf("got %d, want 403", res.StatusCode)
		}
	})
	refusals, warns := 0, 0
	for _, r := range rec.snapshot() {
		if !strings.HasPrefix(r.msg, "credential refused") {
			continue
		}
		refusals++
		if r.level == slog.LevelWarn {
			warns++
		}
		for k, v := range r.attrs {
			if strings.Contains(v, "secretresp") || strings.Contains(v, "abc123nonce") || strings.Contains(v, "guess") {
				t.Errorf("log attribute %s leaks a credential field: %s", k, v)
			}
		}
		if r.attrs["method"] == "" || r.attrs["public_remote"] == "" || r.attrs["transport"] == "" {
			t.Errorf("log lacks method or source: %v", r.attrs)
		}
	}
	if refusals != 4 || warns != 1 {
		t.Errorf("%d refusal lines with %d WARN, want 4 with exactly 1 (one a minute)", refusals, warns)
	}
}

// A refused INVITE takes no session slot, invite_rate_limit token or media
// port: with a one-slot, one-per-minute budget a legitimate INVITE after
// several refusals still gets through.
func TestCredentialMismatchTakesNoResources(t *testing.T) {
	h, _ := startProofHarness(t, false)
	busyInvites(h)
	setShield(h, 1, "1/m")
	c := newUDPClient(t)
	registerAs(t, h, c, "1001", "1001")
	for i := 0; i < 3; i++ {
		if res := c.do(t, inviteWithCredential(c, "Proxy-Authorization", "1002"), h.publicUDP); res.StatusCode != 403 {
			t.Fatalf("attempt %d: got %d, want 403", i, res.StatusCode)
		}
	}
	if n := portsInUse(h); n != 0 {
		t.Errorf("ports in use = %d, want 0", n)
	}
	if g := h.srv.metrics.Snapshot().ActiveSessions; g != 0 {
		t.Errorf("sessions = %d, want 0", g)
	}
	rej := h.srv.metrics.Snapshot().InviteRejects
	if rej["session_cap"] != 0 || rej["invite_rate"] != 0 {
		t.Errorf("cap rejects: %v", rej)
	}
	// The one token of the budget is still there for the real call.
	if res := c.do(t, inviteWithCredential(c, "Proxy-Authorization", "1001"), h.publicUDP); res.StatusCode != 486 {
		t.Fatalf("legitimate INVITE: got %d, want the switch's 486", res.StatusCode)
	}
	if got := credMismatches(h)["INVITE"]; got != 3 {
		t.Errorf("credential_mismatch{INVITE} = %d, want 3", got)
	}
}

// A credential naming the source's own binding is forwarded unchanged, in
// either header; no credential at all is unchanged too.
func TestCredentialOwnBindingForwarded(t *testing.T) {
	h, _ := startProofHarness(t, false)
	busyInvites(h)
	c := newUDPClient(t)
	registerAs(t, h, c, "1001", "1001")
	for i, hdr := range []string{"Proxy-Authorization", "Authorization", ""} {
		res := c.do(t, inviteWithCredential(c, hdr, "1001"), h.publicUDP)
		if res.StatusCode != 486 {
			t.Fatalf("%q: got %d, want the switch's 486", hdr, res.StatusCode)
		}
		seen := h.fs.received(sip.INVITE)
		if len(seen) != i+1 {
			t.Fatalf("%q: the switch saw %d INVITEs, want %d", hdr, len(seen), i+1)
		}
		if hdr != "" {
			if got := seen[i].GetHeader(hdr); got == nil || got.Value() != digest("1001", "abc123nonce", "guess") {
				t.Errorf("%s at the switch = %v, want it unchanged", hdr, got)
			}
		}
	}
	// Case-insensitive, as credentialMatches is: "alice" registered, a
	// credential for "ALICE" is the same account.
	registerAs(t, h, c, "alice", "alice")
	if res := c.do(t, inviteWithCredential(c, "Proxy-Authorization", "ALICE"), h.publicUDP); res.StatusCode != 486 {
		t.Fatalf("credential ALICE for alice: got %d, want the switch's 486", res.StatusCode)
	}
	if n := credMismatches(h)["INVITE"]; n != 0 {
		t.Errorf("credential_mismatch{INVITE} = %d, want 0", n)
	}
}

// Two accounts registered from one socket may each authenticate; a third
// name may not.
func TestCredentialTwoBindingsOneSource(t *testing.T) {
	h, _ := startProofHarness(t, false)
	busyInvites(h)
	c := newUDPClient(t)
	registerAs(t, h, c, "1001", "1001")
	registerAs(t, h, c, "1002", "1002")
	for _, u := range []string{"1001", "1002"} {
		if res := c.do(t, inviteWithCredential(c, "Proxy-Authorization", u), h.publicUDP); res.StatusCode != 486 {
			t.Errorf("credential %s: got %d, want the switch's 486", u, res.StatusCode)
		}
	}
	if res := c.do(t, inviteWithCredential(c, "Proxy-Authorization", "1003"), h.publicUDP); res.StatusCode != 403 {
		t.Errorf("credential 1003: got %d, want 403", res.StatusCode)
	}
	// Two credentials in one request: every one must be proved.
	req := inviteWithCredential(c, "Proxy-Authorization", "1001")
	req.AppendHeader(sip.NewHeader("Authorization", digest("1003", "abc123nonce", "guess")))
	if res := c.do(t, req, h.publicUDP); res.StatusCode != 403 {
		t.Errorf("one proved, one not: got %d, want 403", res.StatusCode)
	}
}

// Under edge.allow_register_auth_mismatch the binding is proved by the
// digest username, not the To user; a refresh without a credential keeps it.
func TestCredentialAllowAuthMismatchComparesDigestUser(t *testing.T) {
	h, _ := startProofHarness(t, true)
	busyInvites(h)
	c := newUDPClient(t)
	registerAs(t, h, c, "default", "18888888880") // To user Y=default, digest X
	if res := c.do(t, inviteWithCredential(c, "Proxy-Authorization", "18888888880"), h.publicUDP); res.StatusCode != 486 {
		t.Errorf("credential X: got %d, want the switch's 486", res.StatusCode)
	}
	if res := c.do(t, inviteWithCredential(c, "Proxy-Authorization", "default"), h.publicUDP); res.StatusCode != 403 {
		t.Errorf("credential Y: got %d, want 403", res.StatusCode)
	}
	// A credential-less refresh of the same Call-ID keeps X.
	req := proofRegister(c, "default", "", true)
	if res := c.do(t, req, h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("refresh: %d", res.StatusCode)
	}
	if res := c.do(t, inviteWithCredential(c, "Proxy-Authorization", "18888888880"), h.publicUDP); res.StatusCode != 486 {
		t.Errorf("credential X after a refresh: got %d, want the switch's 486", res.StatusCode)
	}
}

// A carrier source that is not a registration is not checked.
func TestCredentialCarrierSourceNotChecked(t *testing.T) {
	h := startHarnessFull(t, false, false, harnessCarrierSources)
	busyInvites(h)
	c := newUDPClient(t)
	if res := c.do(t, inviteWithCredential(c, "Proxy-Authorization", "anyone"), h.publicUDP); res.StatusCode != 486 {
		t.Fatalf("got %d, want the switch's 486", res.StatusCode)
	}
	seen := h.fs.received(sip.INVITE)
	if len(seen) != 1 {
		t.Fatalf("the switch saw %d INVITEs", len(seen))
	}
	if got := seen[0].GetHeader("Proxy-Authorization"); got == nil || got.Value() != digest("anyone", "abc123nonce", "guess") {
		t.Errorf("Proxy-Authorization at the switch = %v, want it unchanged", got)
	}
	if n := credMismatches(h)["INVITE"]; n != 0 {
		t.Errorf("credential_mismatch{INVITE} = %d", n)
	}
}

// A mismatched credential sent from a registered victim's socket (all a
// forged datagram can do) is refused and touches none of the victim's state.
func TestCredentialForgedFromVictimSocketChangesNothing(t *testing.T) {
	h, _ := startProofHarness(t, false)
	busyInvites(h)
	victim := newUDPClient(t)
	registerAs(t, h, victim, "1001", "1001")
	before := h.srv.loc.ByAOR("1001@example.com")
	if len(before) != 1 {
		t.Fatalf("bindings = %d", len(before))
	}
	_, offBefore := h.srv.currentShield().Offenders(100)
	dropsBefore := h.srv.metrics.Snapshot().AdmissionDrops
	for i := 0; i < 60; i++ { // past the default admission_ban of 50
		if res := victim.do(t, inviteWithCredential(victim, "Proxy-Authorization", "9999"), h.publicUDP); res.StatusCode != 403 {
			t.Fatalf("attempt %d: got %d, want 403", i, res.StatusCode)
		}
	}
	after := h.srv.loc.ByAOR("1001@example.com")
	if len(after) != 1 || after[0] != before[0] {
		t.Errorf("binding changed: %+v -> %+v", before, after)
	}
	if _, n := h.srv.currentShield().Offenders(100); n != offBefore {
		t.Errorf("offender rows %d -> %d", offBefore, n)
	}
	if bannedLoopback(h) || h.srv.currentShield().Banned(netip.MustParseAddr("127.0.0.1")) {
		t.Error("the victim's IP was banned")
	}
	for r, n := range h.srv.metrics.Snapshot().AdmissionDrops {
		if n != dropsBefore[r] {
			t.Errorf("admission_drops{%s} moved %d -> %d", r, dropsBefore[r], n)
		}
	}
	if len(h.fs.received(sip.INVITE)) != 0 {
		t.Error("a refused INVITE reached the switch")
	}
	// The victim's own credential still works.
	if res := victim.do(t, inviteWithCredential(victim, "Proxy-Authorization", "1001"), h.publicUDP); res.StatusCode != 486 {
		t.Errorf("victim's own INVITE: got %d, want the switch's 486", res.StatusCode)
	}
}

// Location: HasDigestUser is an exact match, and a refresh without a
// credential keeps the stored username while one with a credential replaces it.
func TestLocationDigestUser(t *testing.T) {
	l := NewLocation()
	src := netip.MustParseAddrPort("198.51.100.1:5060")
	put := func(digestUser string) {
		t.Helper()
		if _, err := l.Put(Binding{AOR: "a@x", User: "a", Transport: "udp", Source: src, CallID: "c1",
			ExpiresAt: time.Now().Add(time.Minute), DigestUser: digestUser}); err != nil {
			t.Fatal(err)
		}
	}
	put("Proofed")
	if !l.HasDigestUser("UDP", src, "proofed") {
		t.Error("case-insensitive match failed")
	}
	if l.HasDigestUser("udp", src, "") || l.HasDigestUser("tcp", src, "proofed") ||
		l.HasDigestUser("udp", netip.MustParseAddrPort("198.51.100.1:5061"), "proofed") || l.HasDigestUser("udp", src, "a") {
		t.Error("a non-matching query matched")
	}
	put("") // refresh with no proving credential
	if !l.HasDigestUser("udp", src, "proofed") {
		t.Error("a refresh without a credential lost the proved username")
	}
	put("other")
	if l.HasDigestUser("udp", src, "proofed") || !l.HasDigestUser("udp", src, "other") {
		t.Error("a refresh with a credential did not replace the username")
	}
}

// The WARN is limited to one a minute and carries the count it stands for.
func TestCredWarnerOncePerMinute(t *testing.T) {
	var w credWarner
	if ok, since := w.allow(); !ok || since != 0 {
		t.Fatalf("first: %v %d", ok, since)
	}
	for i := 0; i < 3; i++ {
		if ok, _ := w.allow(); ok {
			t.Fatal("second WARN inside a minute")
		}
	}
	w.mu.Lock()
	w.last = time.Now().Add(-2 * credWarnEvery)
	w.mu.Unlock()
	if ok, since := w.allow(); !ok || since != 3 {
		t.Fatalf("after the window: %v %d, want true 3", ok, since)
	}
}
