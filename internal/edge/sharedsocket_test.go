package edge

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/config"
	"github.com/freesbc/freesbc/internal/media"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// Tests for the single-IP layout (issue #320): private.ip equals public.bind,
// so one UDP socket serves the switch and the internet, and the read filter
// tells them apart by source IP alone.
//
// The harness cannot configure that layout literally, because validation
// wants the shared address to be private and the suite lives on loopback.
// startHarnessShared instead points the private socket at the public udp
// listener with WithPrivateAddr, which is the condition Server.shared is
// derived from, and puts the fake switch on 127.0.0.2 so its datagrams have a
// source IP of their own. public.ip is 203.0.113.7, as on a real 1:1 NAT, so
// the advertised addresses of the two sides differ on the same port.
//
// 127.0.0.2 and 127.0.0.3 are loopback aliases on Linux; macOS has only
// 127.0.0.1 until `sudo ifconfig lo0 alias 127.0.0.2 up`. Without an alias
// these tests skip, as TestAuditMED006LooseLatchFirstPacketHijack does.
// Timing-based over real UDP loopback: re-run once before treating a flake as
// failure.

// requireLoopbackAlias skips the test unless ip can be bound.
func requireLoopbackAlias(t *testing.T, ip string) {
	t.Helper()
	c, err := net.ListenPacket("udp", ip+":0")
	if err != nil {
		t.Skipf("%s is not a local address (macOS: sudo ifconfig lo0 alias %s up): %v", ip, ip, err)
	}
	_ = c.Close()
}

const sharedSwitchIP = "127.0.0.2"

// startHarnessShared builds a harness whose private socket is the public udp
// listener, with the fake switch at 127.0.0.2. carrierSources is the
// edge.carrier_sources body ("" for none, so admission is live for the test
// clients). extra are further edge.listen entries.
func startHarnessShared(t *testing.T, carrierSources string, extra ...string) *harness {
	t.Helper()
	requireLoopbackAlias(t, sharedSwitchIP)
	pubUDP := freePort(t)
	up := freePort(t)
	mediaBase := nextMediaBase(t)
	yaml := harnessYAML(t, []string{fmt.Sprintf("%s:%d", sharedSwitchIP, up)}, pubUDP, 0, 0, mediaBase, carrierSources, extra...)
	const old = "public: {ip: 127.0.0.1}"
	if !strings.Contains(yaml, old) {
		t.Fatal("harness yaml changed")
	}
	yaml = strings.Replace(yaml, old, "public: {ip: 203.0.113.7, bind: 127.0.0.1}", 1)
	h := newHarness(t, yaml, pubUDP)
	if !h.srv.shared {
		t.Fatal("the private socket is the public listener but the server is not in shared mode")
	}
	h.upstream = fmt.Sprintf("%s:%d", sharedSwitchIP, up)
	h.fs = startFakeSwitch(t, h.upstream)
	h.run()
	return h
}

// listenRTPOn binds a UDP socket on ip:port (port 0 for any).
func listenRTPOn(t *testing.T, ip string, port int) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(ip), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// rawOptions is an OPTIONS the way a scanner or a switch keep-alive writes it.
func sharedOptions(target, from string, port int) []byte {
	return []byte(fmt.Sprintf("OPTIONS sip:%s SIP/2.0\r\n"+
		"Via: SIP/2.0/UDP %s:%d;branch=z9hG4bK%d\r\n"+
		"From: <sip:probe@example.com>;tag=abc\r\nTo: <sip:%s>\r\n"+
		"Call-ID: probe-%d\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
		target, from, port, time.Now().UnixNano(), target, time.Now().UnixNano()))
}

func readDatagram(c *net.UDPConn, wait time.Duration) (string, bool) {
	buf := make([]byte, 4096)
	_ = c.SetReadDeadline(time.Now().Add(wait))
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		return "", false
	}
	return string(buf[:n]), true
}

func TestSharedSocketListenersDescribeOneSocket(t *testing.T) {
	h := startHarnessShared(t, harnessCarrierSources)
	ls := h.srv.Listeners()
	if len(ls) != 1 || !strings.HasPrefix(ls[0], "udp://"+h.publicUDP) || !strings.Contains(ls[0], "public and private") {
		t.Errorf("Listeners = %v, want one udp entry naming both roles", ls)
	}
	infos := h.srv.ListenerInfos()
	if len(infos) != 1 || !infos[0].Shared || infos[0].Private || infos[0].Bind != h.publicUDP {
		t.Errorf("ListenerInfos = %+v, want one Shared, non-Private entry", infos)
	}
	if want := fmt.Sprintf("203.0.113.7:%d", portOf(h.publicUDP)); infos[0].Advertised != want {
		t.Errorf("advertised = %q, want %q", infos[0].Advertised, want)
	}
	// Separate addresses keep two entries and never claim sharing.
	sep := startHarness(t, false)
	if sep.srv.shared {
		t.Error("a separate private socket was taken for a shared one")
	}
	if got := sep.srv.ListenerInfos(); len(got) != 2 || got[0].Shared || got[1].Shared || !got[1].Private {
		t.Errorf("separate ListenerInfos = %+v", got)
	}
}

// The classification itself: a switch source on the shared socket takes the
// private path (an OPTIONS naming the private address is answered 200), a
// non-switch source takes the public path (the same OPTIONS is admission
// dropped, silently, and counted).
func TestSharedSocketClassifiesBySourceIP(t *testing.T) {
	h := startHarnessShared(t, "")
	pub, _ := net.ResolveUDPAddr("udp", h.publicUDP)
	privateURI := h.publicUDP // the private side advertises 127.0.0.1:port

	sw := listenRTPOn(t, sharedSwitchIP, 0)
	swPort := sw.LocalAddr().(*net.UDPAddr).Port
	if _, err := sw.WriteToUDP(sharedOptions(privateURI, sharedSwitchIP, swPort), pub); err != nil {
		t.Fatal(err)
	}
	got, ok := readDatagram(sw, 3*time.Second)
	if !ok || !strings.HasPrefix(got, "SIP/2.0 200") {
		t.Fatalf("OPTIONS from the switch IP: got %q (ok=%v), want 200 from the private path", got, ok)
	}

	other := auditUDP(t)
	if _, err := other.WriteToUDP(sharedOptions(privateURI, "127.0.0.1", auditUDPPort(other)), pub); err != nil {
		t.Fatal(err)
	}
	if got, ok := readDatagram(other, 700*time.Millisecond); ok {
		t.Fatalf("OPTIONS from a non-switch source was answered: %q", got)
	}
	deadline := time.Now().Add(3 * time.Second)
	for admissionDrops(h, dropOptions) < 1 {
		if time.Now().After(deadline) {
			t.Fatal("the non-switch OPTIONS was not counted as an admission drop: it did not take the public path")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A public out-of-dialog INVITE from an unknown source gets the usual silent
// drop and never reaches the switch; so does one sent from the switch's UDP
// port number at a non-switch IP.
func TestSharedSocketUnknownSourceInviteDropped(t *testing.T) {
	h := startHarnessShared(t, "")
	pub, _ := net.ResolveUDPAddr("udp", h.publicUDP)
	conn := auditUDP(t)
	raw := &client{transport: "udp", local: conn.LocalAddr().String()}
	invite := raw.buildInvite("1001", "2002", "example.com", phoneOfferSDP(4000))
	if _, err := conn.WriteToUDP([]byte(invite.String()), pub); err != nil {
		t.Fatal(err)
	}
	if got, ok := readDatagram(conn, 800*time.Millisecond); ok {
		t.Fatalf("an unadmitted INVITE was answered: %q", got)
	}
	waitDrops(t, h, 1)
	if got := h.fs.received(sip.INVITE); len(got) != 0 {
		t.Errorf("the switch saw %d INVITEs from an unadmitted source", len(got))
	}
}

// The readFilter decision, directly, on both ways of recognising the
// private socket: the *net.UDPAddr fast path and the string fallback (any
// other net.Addr). A non-switch source is never stamped on either; this
// fails if the fallback branch trusts the socket alone.
type stringAddr struct{ network, s string }

func (a stringAddr) Network() string { return a.network }
func (a stringAddr) String() string  { return a.s }

func TestSharedSocketReadFilterNeverStampsNonSwitch(t *testing.T) {
	h := startHarnessShared(t, harnessCarrierSources)
	filter := h.srv.readFilter()
	local := h.publicUDP
	wire := sharedOptions(local, "x", 5999)
	cases := []struct {
		name       string
		local, rem net.Addr
		stamped    bool
	}{
		{"fast path, switch", mustUDP(local), mustUDP(sharedSwitchIP + ":5080"), true},
		{"fast path, other IP", mustUDP(local), mustUDP("127.0.0.1:5080"), false},
		{"fast path, other IP on the switch port", mustUDP(local), mustUDP("127.0.0.9:5080"), false},
		{"fallback, switch", stringAddr{"udp", local}, stringAddr{"udp", sharedSwitchIP + ":5080"}, true},
		{"fallback, other IP", stringAddr{"udp", local}, stringAddr{"udp", "127.0.0.1:5080"}, false},
		{"fallback local, parsed other IP", stringAddr{"udp", local}, mustUDP("127.0.0.1:5080"), false},
		{"fallback local, unparsable source", stringAddr{"udp", local}, stringAddr{"udp", "garbage"}, false},
		{"tcp to the same address, switch IP", stringAddr{"tcp", local}, stringAddr{"tcp", sharedSwitchIP + ":5080"}, false},
	}
	for _, c := range cases {
		tr := "udp"
		if c.local.Network() == "tcp" {
			tr = "tcp"
		}
		out, err := filter(sip.TransportReadProps{Transport: tr, LocalAddr: c.local, RemoteAddr: c.rem}, wire)
		if err != nil {
			t.Fatalf("%s: filter error %v", c.name, err)
		}
		if got := strings.Contains(string(out), arrivalHeader); got != c.stamped {
			t.Errorf("%s: stamped = %v, want %v", c.name, got, c.stamped)
		}
		if len(out) == 0 {
			t.Errorf("%s: the read was dropped; a non-switch source is a public read, not a drop", c.name)
		}
	}
	// With a separate private socket the same non-switch source is dropped.
	sep := startHarness(t, false)
	out, _ := sep.srv.readFilter()(sip.TransportReadProps{Transport: "udp",
		LocalAddr: mustUDP(sep.privateSIP), RemoteAddr: mustUDP("127.0.0.9:5080")}, wire)
	if len(out) != 0 {
		t.Error("a non-switch source on a separate private socket was not dropped")
	}
}

func mustUDP(s string) *net.UDPAddr {
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		panic(err)
	}
	return a
}

// A phone calls the switch; ACK, a re-INVITE, BYE; RTP both ways on both
// planes; the private leg is strict, so a source that is not the switch
// cannot latch it.
func TestSharedSocketClientCallBothPlanes(t *testing.T) {
	h := startHarnessShared(t, harnessCarrierSources)
	phone := newUDPClient(t)
	phoneRTP := listenRTPOn(t, "127.0.0.1", 0)
	fsRTP := listenRTPOn(t, sharedSwitchIP, h.fs.rtpPort)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, nil, nil))

	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(phoneRTP.LocalAddr().(*net.UDPAddr).Port))
	res := phone.do(t, invite, h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: %d", res.StatusCode)
	}
	invites := h.fs.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(invites) != 1 {
		t.Fatalf("the switch saw %d INVITEs", len(invites))
	}
	upstream, err := parseLabSDP(invites[0].Body())
	if err != nil {
		t.Fatal(err)
	}
	answer, err := parseLabSDP(res.Body())
	if err != nil {
		t.Fatal(err)
	}
	// Topology hiding still holds with one socket: the switch is offered the
	// private address and told FreeSBC's private Contact, the phone the
	// public address.
	if got := upstream.Audio.Address.String(); got != "127.0.0.1" {
		t.Errorf("offer to the switch c= = %s", got)
	}
	if got := answer.Audio.Address.String(); got != "203.0.113.7" {
		t.Errorf("answer to the phone c= = %s, want public.ip", got)
	}
	if c, ok := fsip.ContactURI(invites[0]); !ok || c.Host != h.srv.topo.private.advIP.String() {
		t.Errorf("Contact the switch saw = %v", c)
	}
	// The phone's Record-Route is FreeSBC's public entry alone (public.ip),
	// never the private address on the same port.
	rrs := res.GetHeaders("Record-Route")
	if len(rrs) != 1 {
		t.Errorf("%d Record-Routes to the phone, want 1", len(rrs))
	}
	for _, rh := range rrs {
		if rr := rh.(*sip.RecordRouteHeader); rr.Address.Host != "203.0.113.7" || rr.Address.Port != portOf(h.publicUDP) {
			t.Errorf("Record-Route %s is not the public entry", rr.Address.String())
		}
	}

	sbcPublic := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: answer.Audio.Port}
	sbcPrivate := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: upstream.Audio.Port}

	// A source that is not the switch cannot latch the private leg: strict
	// latching accepts only the SDP address.
	attacker := listenRTPOn(t, "127.0.0.1", 0)
	for i := 0; i < 5; i++ {
		if _, err := attacker.WriteToUDP(rtpPacket(0, uint16(900+i), 160), sbcPrivate); err != nil {
			t.Fatal(err)
		}
	}
	if got, ok := readDatagram(phoneRTP, 400*time.Millisecond); ok {
		t.Fatalf("media from a non-switch source latched the private leg and reached the phone: %d bytes", len(got))
	}

	if !relayReaches(t, phoneRTP, sbcPublic, fsRTP, rtpPacket(0, 100, 160)) {
		t.Fatal("phone to switch audio never arrived")
	}
	if !relayReaches(t, fsRTP, sbcPrivate, phoneRTP, rtpPacket(0, 200, 160)) {
		t.Fatal("switch to phone audio never arrived")
	}

	sendAck(t, phone, invite, res, h.publicUDP)
	if acks := h.fs.waitFor(sip.ACK, 1, 3*time.Second); len(acks) != 1 {
		t.Errorf("the switch saw %d ACKs", len(acks))
	}

	// re-INVITE keeps the anchor.
	re := sip.NewRequest(sip.INVITE, invite.Recipient)
	sip.CopyHeaders("From", invite, re)
	sip.CopyHeaders("Call-ID", invite, re)
	re.AppendHeader(sip.HeaderClone(res.To()))
	re.AppendHeader(&sip.CSeqHeader{SeqNo: invite.CSeq().SeqNo + 1, MethodName: sip.INVITE})
	mf := sip.MaxForwardsHeader(70)
	re.AppendHeader(&mf)
	re.AppendHeader(&sip.ContactHeader{Address: phone.contactURI("1001")})
	re.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	via := &sip.ViaHeader{ProtocolName: "SIP", ProtocolVersion: "2.0", Transport: "UDP", Host: "127.0.0.1", Params: sip.NewParams()}
	via.Params.Add("branch", sip.GenerateBranchN(16))
	via.Params.Add("rport", "")
	re.PrependHeader(via)
	copyRouteFromRecordRoute(res, re)
	re.SetBody([]byte(strings.Replace(phoneOfferSDP(phoneRTP.LocalAddr().(*net.UDPAddr).Port), "a=sendrecv", "a=sendonly", 1)))
	reRes := phone.do(t, re, h.publicUDP)
	if reRes.StatusCode != 200 {
		t.Fatalf("re-INVITE: %d", reRes.StatusCode)
	}
	reAnswer, err := parseLabSDP(reRes.Body())
	if err != nil {
		t.Fatal(err)
	}
	if reAnswer.Audio.Port != answer.Audio.Port {
		t.Errorf("public media port moved on re-INVITE: %d to %d", answer.Audio.Port, reAnswer.Audio.Port)
	}

	if r := phone.do(t, buildBye(phone, invite, res), h.publicUDP); r.StatusCode != 200 {
		t.Errorf("BYE: %d", r.StatusCode)
	}
	if byes := h.fs.waitFor(sip.BYE, 1, 3*time.Second); len(byes) != 1 {
		t.Errorf("the switch saw %d BYEs", len(byes))
	}
	waitForRelease(t, h)
}

// The switch calls a registered phone: the call is delivered, media crosses
// both planes, the switch's BYE reaches the phone.
func TestSharedSocketSwitchCallsClient(t *testing.T) {
	h := startHarnessShared(t, harnessCarrierSources)
	phone := newUDPClient(t)
	ruri := auditRegisterPhone(t, h, phone, "1001")
	phoneRTP := listenRTPOn(t, "127.0.0.1", 0)
	phonePort := phoneRTP.LocalAddr().(*net.UDPAddr).Port
	fsRTP := listenRTPOn(t, sharedSwitchIP, h.fs.rtpPort)
	phone.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
		if req.Method != sip.INVITE {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
			return
		}
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(phoneOfferSDP(phonePort)))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: phone.contactURI("1001")})
		res.To().Params.Add("tag", sip.GenerateTagN(12))
		_ = tx.Respond(res)
	})

	res := h.fs.call(t, ruri, h.privateSIP, h.fs.answerSDP(&sip.Request{}))
	if res.StatusCode != 200 {
		t.Fatalf("switch INVITE: %d", res.StatusCode)
	}
	var offer *sip.Request
	select {
	case offer = <-phone.inbound:
	case <-time.After(5 * time.Second):
		t.Fatal("the phone never received the INVITE")
	}
	phoneSide, err := parseLabSDP(offer.Body())
	if err != nil {
		t.Fatal(err)
	}
	switchSide, err := parseLabSDP(res.Body())
	if err != nil {
		t.Fatal(err)
	}
	if phoneSide.Audio.Address.String() != "203.0.113.7" {
		t.Errorf("phone offered c= %s, want public.ip", phoneSide.Audio.Address)
	}
	sbcPublic := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: phoneSide.Audio.Port}
	sbcPrivate := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: switchSide.Audio.Port}
	if !relayReaches(t, phoneRTP, sbcPublic, fsRTP, rtpPacket(0, 1, 160)) {
		t.Fatal("phone to switch audio never arrived")
	}
	if !relayReaches(t, fsRTP, sbcPrivate, phoneRTP, rtpPacket(0, 2, 160)) {
		t.Fatal("switch to phone audio never arrived")
	}
	drain(phone.inbound)
	if r := h.fs.uacBye(t, res); r.StatusCode != 200 {
		t.Fatalf("switch BYE: %d", r.StatusCode)
	}
	select {
	case got := <-phone.inbound:
		if got.Method != sip.BYE {
			t.Fatalf("the phone received %s, want BYE", got.Method)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the phone never received the BYE")
	}
	waitForRelease(t, h)
}

// CANCEL from the phone reaches the switch over the shared socket.
func TestSharedSocketCancel(t *testing.T) {
	h := startHarnessShared(t, harnessCarrierSources)
	phone := newUDPClient(t)
	ringing := make(chan struct{})
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 180, "Ringing", nil))
		close(ringing)
		return true
	})
	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30097))
	invite.SetTransport("UDP")
	invite.SetDestination(h.publicUDP)
	cancelReq := buildCancelFor(invite)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ctx, cancel := timeoutCtx(15 * time.Second)
		defer cancel()
		tx, err := phone.cli.TransactionRequest(ctx, invite)
		if err != nil {
			return
		}
		defer tx.Terminate()
		for {
			select {
			case res, ok := <-tx.Responses():
				if !ok || res.StatusCode >= 200 {
					return
				}
			case <-tx.Done():
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	select {
	case <-ringing:
	case <-time.After(5 * time.Second):
		t.Fatal("the switch never rang")
	}
	if res := phone.do(t, cancelReq, h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("CANCEL: %d", res.StatusCode)
	}
	if got := h.fs.waitFor(sip.CANCEL, 1, 5*time.Second); len(got) != 1 {
		t.Errorf("the switch saw %d CANCELs", len(got))
	}
	<-done
	waitForRelease(t, h)
}

// A scanner is banned by its own IP; the switch keeps working, on a live
// call too, and is never struck itself.
func TestSharedSocketScannerBanSparesSwitch(t *testing.T) {
	requireLoopbackAlias(t, "127.0.0.3")
	h := startHarnessShared(t, harnessCarrierSources)
	setAdmissionBan(h, "3/5m")
	phone := newUDPClient(t)
	tags := make(chan string, 1)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, tags, nil))
	invite, res, _ := auditPhoneCall(t, h, phone)
	waitForDialog(t, h, fsip.CallID(invite))
	tag := <-tags

	scanner := listenRTPOn(t, "127.0.0.3", 0)
	scanRaw := &client{transport: "udp", local: scanner.LocalAddr().String()}
	pub, _ := net.ResolveUDPAddr("udp", h.publicUDP)
	for i := 0; i < 6; i++ {
		// A fresh Call-ID each time; the source is unregistered and no carrier.
		inv := scanRaw.buildInvite("1001", "2002", "example.com", phoneOfferSDP(4000))
		if _, err := scanner.WriteToUDP([]byte(inv.String()), pub); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	sh := h.srv.currentShield()
	scannerAddr := netip.MustParseAddrPort("127.0.0.3:5999")
	deadline := time.Now().Add(5 * time.Second)
	for !sh.BannedFrom(scannerAddr, "udp") {
		if time.Now().After(deadline) {
			t.Fatal("the scanner was not banned by its own IP")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if sh.BannedFrom(netip.MustParseAddrPort(sharedSwitchIP+":5999"), "udp") || sh.BannedFrom(netip.MustParseAddrPort("127.0.0.1:5999"), "udp") {
		t.Fatal("the ban reached the switch or the phone")
	}
	for _, o := range func() []string {
		top, _ := sh.Offenders(10)
		var s []string
		for _, o := range top {
			s = append(s, o.Source)
		}
		return s
	}() {
		if o == sharedSwitchIP {
			t.Errorf("the switch IP is in the offender table")
		}
	}

	// The live call still takes the switch's in-dialog request.
	invites := h.fs.waitFor(sip.INVITE, 1, 3*time.Second)
	drain(phone.inbound)
	if r := h.fs.inDialog(t, sip.BYE, invites[0], tag); r.StatusCode != 200 {
		t.Fatalf("switch BYE after the ban: %d", r.StatusCode)
	}
	select {
	case got := <-phone.inbound:
		if got.Method != sip.BYE {
			t.Fatalf("the phone received %s", got.Method)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the phone never received the switch's BYE")
	}
	_ = res
	waitForRelease(t, h)
}

// A tcp listener on the shared address stays public, even for a source IP
// that is the switch's: the INVITE is admission dropped, not routed as the
// switch's.
func TestSharedSocketTCPStaysPublic(t *testing.T) {
	requireLoopbackAlias(t, sharedSwitchIP)
	tcpPort := freePort(t)
	h := startHarnessShared(t, "", fmt.Sprintf("tcp: %d", tcpPort))
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(sharedSwitchIP)}, Timeout: 3 * time.Second}
	conn, err := d.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tcpPort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw := &client{transport: "tcp", local: conn.LocalAddr().String()}
	invite := raw.buildInvite("1001", "2002", "example.com", phoneOfferSDP(4000))
	if _, err := conn.Write([]byte(invite.String())); err != nil {
		t.Fatal(err)
	}
	waitDrops(t, h, 1)
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if line, err := bufio.NewReader(conn).ReadString('\n'); err == nil {
		t.Errorf("the stream answered a public INVITE: %q", line)
	}
	if got := h.fs.received(sip.INVITE); len(got) != 0 {
		t.Errorf("the switch saw %d INVITEs", len(got))
	}
}

// sessionLimit counts half the range when both planes draw from it, the port
// statistics count the range once, and the allocator really fits that many
// calls with no spurious failure below the limit.
func TestSharedSocketSessionLimitAndPorts(t *testing.T) {
	h := startHarnessShared(t, harnessCarrierSources)
	pairs := h.store.Current().RTP.Pairs()
	if got := h.srv.sessionLimit(h.store.Current()); got != pairs/2 {
		t.Errorf("shared sessionLimit = %d, want %d (half of %d pairs)", got, pairs/2, pairs)
	}
	if _, total := h.srv.PortStats(); total != pairs {
		t.Errorf("shared port total = %d, want the range's %d pairs", total, pairs)
	}
	sep := startHarness(t, false)
	spairs := sep.store.Current().RTP.Pairs()
	if got := sep.srv.sessionLimit(sep.store.Current()); got != spairs {
		t.Errorf("separate sessionLimit = %d, want %d", got, spairs)
	}
	if _, total := sep.srv.PortStats(); total != 2*spairs {
		t.Errorf("separate port total = %d, want %d", total, 2*spairs)
	}

	// pairs/2 calls fit, the next does not. Each pool tries a bind and moves
	// on past a port the other pool holds.
	var sessions []*media.Session
	t.Cleanup(func() {
		for _, s := range sessions {
			_ = s.Close()
		}
	})
	for i := 0; i < pairs/2; i++ {
		s, err := media.AllocateAcross(h.srv.pubPool, h.srv.privPool, media.SessionConfig{})
		if err != nil {
			t.Fatalf("call %d of %d failed: %v", i+1, pairs/2, err)
		}
		sessions = append(sessions, s)
	}
	if _, err := media.AllocateAcross(h.srv.pubPool, h.srv.privPool, media.SessionConfig{}); !errors.Is(err, media.ErrPortsExhausted) {
		t.Errorf("call %d: err = %v, want ErrPortsExhausted", pairs/2+1, err)
	}
}

// Config says shared only for an equal pair of addresses; the harness's
// separate-address config keeps it false.
func TestSharedSocketConfigFlagFalseForSeparateAddresses(t *testing.T) {
	h := startHarness(t, false)
	if h.store.Current().SharedSocket() {
		t.Error("a separate-address config reports a shared socket")
	}
}

// Issue #328: in the single-IP layout the shared socket is
// private.ip:<edge.listen.udp>, derived by New from the config alone. No
// WithPrivateAddr here (the harness uses it as a seam), so a Server that took
// the 5060 constant instead of Config.PrivateAddr fails this. New binds
// nothing, so the private address need not be local.
func TestSharedSocketPortFollowsListenUDPInNew(t *testing.T) {
	const src = `
public: {ip: 203.0.113.7, bind: 10.77.0.2}
private: {ip: 10.77.0.2}
rtp: "10000-19999"
edge:
  switch: ["10.77.0.3:5080"]
  listen: {udp: 16060}
`
	cfg, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(config.NewStore(cfg), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddrPort("10.77.0.2:16060"); srv.privAddr != want {
		t.Errorf("privAddr = %v, want %v", srv.privAddr, want)
	}
	if !srv.shared {
		t.Fatal("the shared socket was not recognised")
	}
	pub, ok := srv.topo.publicSide("udp")
	if !ok || pub.advIP.String() != "203.0.113.7" || pub.advPort != 16060 {
		t.Errorf("public side = %+v, want 203.0.113.7:16060", pub)
	}
	if p := srv.topo.private; p.advIP.String() != "10.77.0.2" || p.advPort != 16060 {
		t.Errorf("private side = %v:%d, want 10.77.0.2:16060", p.advIP, p.advPort)
	}
	self := func(host string, port int) bool { return srv.topo.isSelf(sip.Uri{Host: host, Port: port}) }
	if !self("10.77.0.2", 16060) || !self("203.0.113.7", 16060) {
		t.Error("isSelf misses a FreeSBC address on the moved port")
	}
	if self("10.77.0.2", 5060) || self("203.0.113.7", 5060) {
		t.Error("isSelf still matches port 5060")
	}
	if got := srv.Listeners(); len(got) != 1 || !strings.Contains(got[0], "10.77.0.2:16060") {
		t.Errorf("Listeners = %v", got)
	}
}
