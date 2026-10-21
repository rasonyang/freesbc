package edge

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
	"github.com/freesbc/freesbc/internal/shield"
)

// Tests for the admission-drop ban (shield.admission_ban, issue #180).
// Timing-based over real UDP loopback: re-run once before treating a flake
// as failure.

func setAdmissionBan(h *harness, v string) {
	next := *h.store.Current()
	next.Shield.AdmissionBan = v
	h.store.Replace(&next)
}

// scanOnce sends one INVITE from a fresh UDP socket (a new source port per
// request, as the scanner in the issue does) and does not wait for an
// answer: admission drops it silently.
func scanOnce(t *testing.T, h *harness) {
	t.Helper()
	conn := auditUDP(t)
	raw := &client{transport: "udp", local: conn.LocalAddr().String()}
	invite := raw.buildInvite("1001", "2002", "example.com", phoneOfferSDP(4000))
	pub, err := net.ResolveUDPAddr("udp", h.publicUDP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteToUDP([]byte(invite.String()), pub); err != nil {
		t.Fatal(err)
	}
}

// bannedLoopbackUDP reports whether UDP from the test source IP is banned
// (by any ban scope that covers UDP).
func bannedLoopbackUDP(h *harness) bool {
	return h.srv.currentShield().BannedFrom(netip.AddrPortFrom(guardSrc, 5999), "udp")
}

func waitDrops(t *testing.T, h *harness, want uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for admissionDrops(h, dropInviteNotAdmitted) < want {
		if time.Now().After(deadline) {
			t.Fatalf("invite_not_admitted drops = %d, want %d", admissionDrops(h, dropInviteNotAdmitted), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
}

// A source that keeps sending INVITEs admission drops, each from a new
// port, is banned by IP once it passes shield.admission_ban; below the
// threshold it is not.
func TestAdmissionBanLowAndSlowScanner(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	setAdmissionBan(h, "3/5m")
	for i := 0; i < 3; i++ {
		scanOnce(t, h)
	}
	waitDrops(t, h, 3)
	if bannedLoopbackUDP(h) {
		t.Fatal("banned at the threshold; want only past it")
	}
	scanOnce(t, h)
	waitDrops(t, h, 4)
	if !bannedLoopbackUDP(h) {
		t.Fatal("the 4th dropped INVITE did not ban the source IP")
	}
	page, _, _ := h.srv.Bans(10, 0)
	if len(page) != 1 || page[0].Reason != shield.BanReasonAdmission || page[0].Kind != shield.BanKindUDPIP {
		t.Errorf("bans = %+v", page)
	}
	top, total := h.srv.currentShield().Offenders(10)
	if total != 1 || top[0].Reason != shield.StrikeAdmissionUDP || top[0].Source != "127.0.0.1" {
		t.Errorf("offenders = %+v (total %d)", top, total)
	}
	// Banned: the read filter drops it, so admission no longer sees it, and
	// the drop is counted as a shield "banned" drop (issue #249).
	sh := h.srv.currentShield()
	bannedDrops := func() int64 { return sh.Stats().DropsByReason["banned"] }
	before := bannedDrops()
	strikes := top[0].Strikes
	scanOnce(t, h)
	deadline := time.Now().Add(5 * time.Second)
	for bannedDrops() < before+1 {
		if time.Now().After(deadline) {
			t.Fatalf("banned drops = %d, want %d: the read filter did not count the banned read", bannedDrops(), before+1)
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if n := bannedDrops(); n != before+1 {
		t.Errorf("banned drops = %d, want exactly %d for one banned read", n, before+1)
	}
	if n := admissionDrops(h, dropInviteNotAdmitted); n != 4 {
		t.Errorf("drops after the ban = %d, want 4 (read filter drops first)", n)
	}
	if top, _ := sh.Offenders(10); len(top) != 1 || top[0].Strikes != strikes {
		t.Errorf("offenders after the ban = %+v, want admission strikes unchanged at %d", top, strikes)
	}
}

// "off" never bans, however many requests are dropped.
func TestAdmissionBanOff(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	setAdmissionBan(h, "off")
	for i := 0; i < 6; i++ {
		scanOnce(t, h)
	}
	waitDrops(t, h, 6)
	if bannedLoopbackUDP(h) {
		t.Fatal("admission_ban off banned a source")
	}
}

// An IP holding a live registration is never struck, even when another
// socket on it (a phone whose NAT mapping moved) is dropped.
func TestAdmissionBanSparesRegisteredIP(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	setAdmissionBan(h, "2/5m")
	phone := newUDPClient(t)
	auditRegisterPhone(t, h, phone, "1001")
	for i := 0; i < 5; i++ {
		scanOnce(t, h)
	}
	waitDrops(t, h, 5)
	if bannedLoopbackUDP(h) {
		t.Fatal("an IP with a live registration was banned by admission drops")
	}
	if _, total := h.srv.currentShield().Offenders(10); total != 0 {
		t.Errorf("offenders = %d, want none for a registered IP", total)
	}
}

// A carrier source is never struck.
func TestAdmissionBanSparesCarrierSource(t *testing.T) {
	h := startHarnessFull(t, false, false, "127.0.0.0/8")
	setAdmissionBan(h, "1/5m")
	for i := 0; i < 5; i++ {
		h.srv.admissionStrike(guardSrc, "udp")
	}
	if bannedLoopbackUDP(h) {
		t.Fatal("a carrier source was banned by admission strikes")
	}
	if _, total := h.srv.currentShield().Offenders(10); total != 0 {
		t.Errorf("offenders = %d, want none for a carrier source", total)
	}
}

// Location.HasIP follows bindings across refresh, move and removal.
func TestLocationHasIP(t *testing.T) {
	l := NewLocation()
	ip := netip.MustParseAddr("198.51.100.7")
	if l.HasIP(ip) {
		t.Fatal("empty table has an IP")
	}
	b := Binding{AOR: "a@x", User: "a", Transport: "udp", CallID: "c1",
		Source: netip.AddrPortFrom(ip, 5000), ExpiresAt: time.Now().Add(time.Minute)}
	if _, err := l.Put(b); err != nil {
		t.Fatal(err)
	}
	b.Source = netip.AddrPortFrom(ip, 5001) // refresh from a new port
	if _, err := l.Put(b); err != nil {
		t.Fatal(err)
	}
	if !l.HasIP(ip) {
		t.Fatal("binding's IP not found after refresh")
	}
	l.Remove("a@x", "c1")
	if l.HasIP(ip) {
		t.Fatal("IP still indexed after the binding was removed")
	}
}

// Dialog-less BYE requests from an unregistered, non-carrier source, each
// from a new port, are answered 481 and also strike the source: past
// shield.admission_ban its IP is banned on UDP only, and later datagrams
// are dropped before any answer.
func TestAdmissionBanDialoglessBye(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	setAdmissionBan(h, "3/5m")
	for i := 0; i < 4; i++ {
		stranger := newUDPClient(t)
		invite, res := ghostDialog(stranger)
		req := inDialogRequest(stranger, sip.BYE, 2, invite, res)
		if got := stranger.do(t, req, h.publicUDP); got.StatusCode != 481 {
			t.Fatalf("request %d: got %d, want 481", i+1, got.StatusCode)
		}
		if i < 3 && bannedLoopbackUDP(h) {
			t.Fatalf("banned after %d requests; want only past 3", i+1)
		}
	}
	waitDialoglessDrops(t, h, 4)
	if !bannedLoopbackUDP(h) {
		t.Fatal("the 4th dialog-less BYE did not ban the source IP on UDP")
	}
	if h.srv.currentShield().BannedFrom(netip.AddrPortFrom(guardSrc, 5999), "tcp") {
		t.Error("UDP strikes produced an all-transport ban")
	}
	page, _, _ := h.srv.Bans(10, 0)
	if len(page) != 1 || page[0].Reason != shield.BanReasonAdmission || page[0].Kind != shield.BanKindUDPIP {
		t.Errorf("bans = %+v", page)
	}
	// Banned: the next datagram is dropped with no response.
	late := newUDPClient(t)
	invite, res := ghostDialog(late)
	req := inDialogRequest(late, sip.BYE, 2, invite, res)
	conn := auditUDP(t)
	pub, err := net.ResolveUDPAddr("udp", h.publicUDP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteToUDP([]byte(req.String()), pub); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 4096)
	if n, _, err := conn.ReadFromUDP(buf); err == nil {
		t.Fatalf("banned source got a response: %q", buf[:n])
	}
	if n := admissionDrops(h, dropDialogless); n != 4 {
		t.Errorf("dialogless drops = %d, want 4 (read filter drops first)", n)
	}
}

func waitDialoglessDrops(t *testing.T, h *harness, want uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for admissionDrops(h, dropDialogless) < want {
		if time.Now().After(deadline) {
			t.Fatalf("dialogless drops = %d, want %d", admissionDrops(h, dropDialogless), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
}
