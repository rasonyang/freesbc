package edge

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/shield"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// Tests for the proof a 2xx to a public REGISTER must carry before FreeSBC
// records a binding or clears strikes (issue #303; recordBinding and
// registerOutcome in register.go and regguard.go). Timing-based over real
// UDP loopback: re-run once before treating a flake as failure.

// startProofHarness is startHarnessStrict with the log kept, a registrar
// that never challenges (so a credential-less REGISTER draws a 200, as with
// accept-blind-reg) and, when allowMismatch is set,
// edge.allow_register_auth_mismatch.
func startProofHarness(t *testing.T, allowMismatch bool) (*harness, *logRecorder) {
	t.Helper()
	pubUDP, priv, up := freePort(t), freePort(t), freePort(t)
	mediaBase := nextMediaBase(t)
	yaml := harnessYAML(t, []string{fmt.Sprintf("127.0.0.1:%d", up)}, pubUDP, 0, 0, mediaBase, "")
	if allowMismatch {
		yaml = strings.Replace(yaml, "shield:", "  allow_register_auth_mismatch: true\nshield:", 1)
	}
	rec := newLogRecorder()
	h := newHarnessLog(t, yaml, priv, rec)
	h.upstream = fmt.Sprintf("127.0.0.1:%d", up)
	h.fs = startFakeSwitch(t, h.upstream)
	h.fs.mu.Lock()
	h.fs.challenge = false
	h.fs.mu.Unlock()
	h.run()
	return h, rec
}

// proofRegister builds a REGISTER to the AoR user@example.com; authUser, when
// non-empty, adds a digest credential for that username.
func proofRegister(c *client, user, authUser string, contact bool) *sip.Request {
	auth := ""
	if authUser != "" {
		auth = digest(authUser, "abc123nonce", "right")
	}
	req := c.buildRegister(user, "example.com", 3600, auth)
	if auth == "" {
		req.RemoveHeader("Authorization") // buildRegister adds a placeholder
	}
	if !contact {
		fsip.RemoveHeaders(req, "Contact")
	}
	return req
}

func bindingCount(h *harness) int { return h.srv.loc.Count() }

// expectInviteDropped sends an INVITE from c and checks the edge stays
// silent and counts invite_not_admitted.
func expectInviteDropped(t *testing.T, h *harness, c *client) {
	t.Helper()
	before := admissionDrops(h, dropInviteNotAdmitted)
	expectSilence(t, c, c.buildInvite("1001", "2002", "example.com", phoneOfferSDP(4000)), h.publicUDP)
	// The client stack retransmits the unanswered INVITE, so at least one.
	if got := admissionDrops(h, dropInviteNotAdmitted); got <= before {
		t.Errorf("invite_not_admitted = %d, want it to move past %d", got, before)
	}
	if got := h.fs.received(sip.INVITE); len(got) != 0 {
		t.Errorf("the switch saw %d INVITEs from an unproven source", len(got))
	}
}

func proofRejects(h *harness) map[string]uint64 {
	return h.srv.metrics.Snapshot().RegisterBindingRejects
}

// A 200 to a REGISTER with no Contact and Expires: 3600 (a query) records
// nothing, with or without a credential, and the source's INVITE is dropped.
func TestRegisterProofNoContactCreatesNoBinding(t *testing.T) {
	for _, authUser := range []string{"", "1001"} {
		t.Run("auth="+authUser, func(t *testing.T) {
			h, rec := startProofHarness(t, false)
			c := newUDPClient(t)
			if res := c.do(t, proofRegister(c, "1001", authUser, false), h.publicUDP); res.StatusCode != 200 {
				t.Fatalf("REGISTER: %d, want the switch's 200 relayed", res.StatusCode)
			}
			if n := bindingCount(h); n != 0 {
				t.Fatalf("bindings = %d, want 0", n)
			}
			if got := proofRejects(h)["no_contact"]; got != 1 {
				t.Errorf("no_contact = %d, want 1 (%v)", got, proofRejects(h))
			}
			assertProofWarn(t, rec, "no_contact", "1001@example.com", "")
			expectInviteDropped(t, h, c)
		})
	}
}

// A credential-less 200 for a source with no binding creates none.
func TestRegisterProofNoCredentialCreatesNoBinding(t *testing.T) {
	h, rec := startProofHarness(t, false)
	c := newUDPClient(t)
	if res := c.do(t, proofRegister(c, "1001", "", true), h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d, want the switch's 200 relayed", res.StatusCode)
	}
	if n := bindingCount(h); n != 0 {
		t.Fatalf("bindings = %d, want 0", n)
	}
	if got := proofRejects(h)["no_auth"]; got != 1 {
		t.Errorf("no_auth = %d, want 1 (%v)", got, proofRejects(h))
	}
	assertProofWarn(t, rec, "no_auth", "1001@example.com", "")
	expectInviteDropped(t, h, c)
}

// To: default with username=18888888880 binds nothing by default, and binds
// with edge.allow_register_auth_mismatch: the config gate.
func TestRegisterProofAuthAORMismatchGate(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		h, rec := startProofHarness(t, false)
		c := newUDPClient(t)
		if res := c.do(t, proofRegister(c, "default", "18888888880", true), h.publicUDP); res.StatusCode != 200 {
			t.Fatalf("REGISTER: %d, want the switch's 200 relayed", res.StatusCode)
		}
		if n := bindingCount(h); n != 0 {
			t.Fatalf("bindings = %d, want 0", n)
		}
		if got := proofRejects(h)["auth_aor_mismatch"]; got != 1 {
			t.Errorf("auth_aor_mismatch = %d, want 1 (%v)", got, proofRejects(h))
		}
		assertProofWarn(t, rec, "auth_aor_mismatch", "default@example.com", "18888888880")
		expectInviteDropped(t, h, c)
	})
	t.Run("allowed", func(t *testing.T) {
		h, _ := startProofHarness(t, true)
		c := newUDPClient(t)
		if res := c.do(t, proofRegister(c, "default", "18888888880", true), h.publicUDP); res.StatusCode != 200 {
			t.Fatalf("REGISTER: %d", res.StatusCode)
		}
		if n := bindingCount(h); n != 1 {
			t.Fatalf("bindings = %d, want 1 with the key on", n)
		}
		if got := proofRejects(h)["auth_aor_mismatch"]; got != 0 {
			t.Errorf("auth_aor_mismatch = %d, want 0 with the key on", got)
		}
		// The key does not waive the other rules.
		c2 := newUDPClient(t)
		if res := c2.do(t, proofRegister(c2, "other", "", true), h.publicUDP); res.StatusCode != 200 {
			t.Fatalf("REGISTER: %d", res.StatusCode)
		}
		if res := c2.do(t, proofRegister(c2, "third", "18888888880", false), h.publicUDP); res.StatusCode != 200 {
			t.Fatalf("REGISTER: %d", res.StatusCode)
		}
		if n := bindingCount(h); n != 1 {
			t.Fatalf("bindings = %d, want still 1 (no credential, no contact)", n)
		}
	})
}

// The username is compared case-insensitively.
func TestRegisterProofUsernameCaseInsensitive(t *testing.T) {
	h, _ := startProofHarness(t, false)
	c := newUDPClient(t)
	if res := c.do(t, proofRegister(c, "alice", "ALICE", true), h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	if n := bindingCount(h); n != 1 {
		t.Fatalf("bindings = %d, want 1", n)
	}
}

// A REGISTER with a Contact and a matching credential creates a binding; a
// credential-less refresh of it (same AoR, Call-ID and source) extends it.
func TestRegisterProofMatchingCreatesAndRefreshes(t *testing.T) {
	h, _ := startProofHarness(t, false)
	c := newUDPClient(t)
	if res := c.do(t, proofRegister(c, "1001", "1001", true), h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	bs := h.srv.loc.ByAOR("1001@example.com")
	if len(bs) != 1 {
		t.Fatalf("bindings = %d, want 1", len(bs))
	}
	first := bs[0].ExpiresAt
	time.Sleep(20 * time.Millisecond)
	if res := c.do(t, proofRegister(c, "1001", "", true), h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("refresh: %d", res.StatusCode)
	}
	bs = h.srv.loc.ByAOR("1001@example.com")
	if len(bs) != 1 || !bs[0].ExpiresAt.After(first) {
		t.Fatalf("credential-less refresh did not extend the binding: %+v (was %v)", bs, first)
	}
	if got := proofRejects(h)["no_auth"]; got != 0 {
		t.Errorf("no_auth = %d for a refresh, want 0", got)
	}
	// And the registered source is admitted.
	if res := c.do(t, c.buildInvite("1001", "2002", "example.com", phoneOfferSDP(4000)), h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("INVITE from the proven source: %d", res.StatusCode)
	}
}

// A refresh from another source IP does not count as 1b: with no credential
// it binds nothing new.
func TestRegisterProofRefreshNeedsSameSource(t *testing.T) {
	h, _ := startProofHarness(t, false)
	c := newUDPClient(t)
	if res := c.do(t, proofRegister(c, "1001", "1001", true), h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	if n := bindingCount(h); n != 1 {
		t.Fatalf("bindings = %d, want 1", n)
	}
	other := newUDPClient(t)
	other.local = "127.0.0.1:" + strings.Split(other.local, ":")[1]
	// Same IP in this suite, so only a different Call-ID shows the rule.
	req := proofRegister(other, "1001", "", true)
	req.RemoveHeader("Call-ID")
	cid := sip.CallIDHeader("another-call-id")
	req.AppendHeader(&cid)
	if res := other.do(t, req, h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	if n := bindingCount(h); n != 1 {
		t.Fatalf("bindings = %d, want 1 (a new Call-ID without a credential binds nothing)", n)
	}
}

func strikeCount(h *harness) int {
	_, total := h.srv.currentShield().Offenders(10)
	return total
}

// seedStrikes puts one register and one admission strike (and an AoR strike)
// on the loopback source.
func seedStrikes(t *testing.T, h *harness, aor string) {
	t.Helper()
	sh := h.srv.currentShield()
	src := netip.MustParseAddr("127.0.0.1")
	sh.Strike(src, shield.StrikeRegister)
	sh.Strike(src, shield.StrikeAdmission)
	sh.StrikeAOR(aor)
	if got := strikeCount(h); got < 3 {
		t.Fatalf("seeded strikes = %d, want >= 3", got)
	}
}

// A 2xx that proves nothing clears nothing; a credentialed 2xx for the AoR
// clears the source's strikes.
func TestRegisterProofStrikeClearing(t *testing.T) {
	h, _ := startProofHarness(t, false)
	c := newUDPClient(t)
	seedStrikes(t, h, "1001@example.com")
	before := strikeCount(h)

	// No credential.
	if res := c.do(t, proofRegister(c, "1001", "", true), h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	// Mismatched credential.
	if res := c.do(t, proofRegister(c, "1001", "9999", true), h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	if got := strikeCount(h); got != before {
		t.Fatalf("strikes = %d after unproven 2xx, want %d", got, before)
	}

	// Matching credential, even with no Contact is not enough to bind but
	// the credential is what clears.
	if res := c.do(t, proofRegister(c, "1001", "1001", true), h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	if got := strikeCount(h); got != 0 {
		t.Fatalf("strikes = %d after a credentialed 2xx, want 0", got)
	}
}

// A credential-less refresh of a live binding refreshes it but clears
// nothing.
func TestRegisterProofRefreshClearsNothing(t *testing.T) {
	h, _ := startProofHarness(t, false)
	c := newUDPClient(t)
	if res := c.do(t, proofRegister(c, "1001", "1001", true), h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	seedStrikes(t, h, "1001@example.com")
	before := strikeCount(h)
	if res := c.do(t, proofRegister(c, "1001", "", true), h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("refresh: %d", res.StatusCode)
	}
	if got := strikeCount(h); got != before {
		t.Fatalf("strikes = %d after a credential-less refresh, want %d", got, before)
	}
}

// Un-REGISTER and wildcard un-REGISTER keep working without a credential
// being re-proved.
func TestRegisterProofUnregisterUnchanged(t *testing.T) {
	h, _ := startProofHarness(t, false)
	c := newUDPClient(t)
	if res := c.do(t, proofRegister(c, "1001", "1001", true), h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	if n := bindingCount(h); n != 1 {
		t.Fatalf("bindings = %d, want 1", n)
	}
	req := c.buildRegister("1001", "example.com", 0, "")
	if res := c.do(t, req, h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("un-REGISTER: %d", res.StatusCode)
	}
	if n := bindingCount(h); n != 0 {
		t.Fatalf("bindings = %d after un-REGISTER, want 0", n)
	}
	if got := proofRejects(h); got["no_auth"]+got["no_contact"]+got["auth_aor_mismatch"] != 0 {
		t.Errorf("an un-REGISTER was counted as a rejected binding: %v", got)
	}
}

// The metric is exported from zero with exactly the fixed reasons.
func TestRegisterProofMetricExportedFromZero(t *testing.T) {
	h, _ := startProofHarness(t, false)
	got := proofRejects(h)
	if len(got) != 3 {
		t.Fatalf("reasons = %v, want exactly no_contact, no_auth, auth_aor_mismatch", got)
	}
	for _, r := range []string{"no_contact", "no_auth", "auth_aor_mismatch"} {
		if v, ok := got[r]; !ok || v != 0 {
			t.Errorf("reason %s = %v %v, want present at 0", r, v, ok)
		}
	}
}

// assertProofWarn checks the one Warn a rejection logs: aor, source, reason,
// the auth username in the mismatch case, and no secret.
func assertProofWarn(t *testing.T, rec *logRecorder, reason, aor, authUser string) {
	t.Helper()
	var found []recordedLog
	for _, r := range rec.snapshot() {
		if r.msg == "registration binding not recorded" {
			found = append(found, r)
		}
	}
	if reason == "no_contact" {
		// Debug, not Warn: a query never asked for a binding.
		if len(found) != 1 || found[0].level.String() != "DEBUG" || found[0].attrs["reason"] != reason {
			t.Fatalf("no_contact log = %v, want one DEBUG line", found)
		}
		return
	}
	if len(found) != 1 {
		t.Fatalf("%d \"registration binding not recorded\" lines, want 1", len(found))
	}
	r := found[0]
	if r.level.String() != "WARN" || r.attrs["reason"] != reason || r.attrs["aor"] != aor {
		t.Errorf("log = %v %v", r.level, r.attrs)
	}
	if r.attrs["public_remote"] == "" || r.attrs["transport"] == "" {
		t.Errorf("log lacks the source: %v", r.attrs)
	}
	if r.attrs["auth_user"] != authUser {
		t.Errorf("auth_user = %q, want %q", r.attrs["auth_user"], authUser)
	}
	for k, v := range r.attrs {
		if strings.Contains(v, "abc123nonce") || strings.Contains(v, "right") && k != "reason" {
			t.Errorf("log attr %s leaks credential material: %q", k, v)
		}
	}
}

// A Contact-less REGISTER is a query: a 200 to one with no Expires and the
// same Call-ID from the same source leaves a live binding alone.
func TestRegisterProofQueryDoesNotRemoveBinding(t *testing.T) {
	h, _ := startProofHarness(t, false)
	c := newUDPClient(t)
	if res := c.do(t, proofRegister(c, "1001", "1001", true), h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	for _, withAuth := range []string{"1001", ""} {
		q := proofRegister(c, "1001", withAuth, false)
		q.RemoveHeader("Expires")
		if res := c.do(t, q, h.publicUDP); res.StatusCode != 200 {
			t.Fatalf("query: %d", res.StatusCode)
		}
		if n := bindingCount(h); n != 1 {
			t.Fatalf("bindings = %d after a query (auth=%q), want the live one kept", n, withAuth)
		}
	}
	z := proofRegister(c, "1001", "1001", false)
	z.RemoveHeader("Expires")
	z.AppendHeader(sip.NewHeader("Expires", "0"))
	if res := c.do(t, z, h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("query with Expires 0: %d", res.StatusCode)
	}
	if n := bindingCount(h); n != 1 {
		t.Fatalf("bindings = %d after a Contact-less Expires: 0, want 1", n)
	}
}
