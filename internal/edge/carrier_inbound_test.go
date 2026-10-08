package edge

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// This file tests the inbound carrier path (carrier → switch): admission
// of a carrier source, delivery to the switch's CARRIER port with
// X-FreeSBC-Carrier, the X-FreeSBC-* strip, and the classification of what
// the switch itself originates on the private socket.
//
// The rig is the shared harness plus edge.carriers (literal addresses on
// 127.0.0.1) and edge.switch_carrier_port pointing at a second fake
// switch: h.fs is the switch's client port, rig.cs its carrier port.

type carrierRig struct {
	*harness
	cs *fakeSwitch // the switch's carrier port
}

// startCarrierRig starts the proxy with edge.carriers = carriers (a YAML
// flow-map body) and edge.carrier_sources = carrierSources. tweak runs on
// the built server before it starts (the DNS seams).
func startCarrierRig(t *testing.T, carriers, carrierSources string, tweak func(*Server)) *carrierRig {
	t.Helper()
	pubUDP, priv, up, cp := freePort(t), freePort(t), freePort(t), freePort(t)
	mediaBase := nextMediaBase(t)
	yaml := harnessYAML(t, []string{fmt.Sprintf("127.0.0.1:%d", up)}, pubUDP, 0, 0, mediaBase, carrierSources)
	yaml = strings.Replace(yaml, "edge:\n",
		fmt.Sprintf("edge:\n  switch_carrier_port: %d\n  carriers: {%s}\n", cp, carriers), 1)
	h := newHarness(t, yaml, priv)
	h.upstream = fmt.Sprintf("127.0.0.1:%d", up)
	h.fs = startFakeSwitch(t, h.upstream)
	cs := startFakeSwitch(t, fmt.Sprintf("127.0.0.1:%d", cp))
	h.upstreams["carrier-port"] = cs // stopped with the harness
	if tweak != nil {
		tweak(h.srv)
	}
	h.run()
	return &carrierRig{harness: h, cs: cs}
}

// carrierHeaders returns the values of the X-FreeSBC-Carrier headers req
// carries.
func carrierHeaders(req *sip.Request) []string {
	var out []string
	for _, h := range req.GetHeaders("X-FreeSBC-Carrier") {
		out = append(out, h.Value())
	}
	return out
}

// answerWithEcho makes a fake switch answer every INVITE 200 with an
// X-FreeSBC-Echo header, as a switch that echoes what it was sent would.
func answerWithEcho(f *fakeSwitch) {
	f.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(f.answerSDP(req)))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "fs", Host: "127.0.0.1", Port: portOf(f.addr)}})
		res.AppendHeader(sip.NewHeader("X-FreeSBC-Echo", "1"))
		res.AppendHeader(sip.NewHeader("X-FreeSBC-Carrier", "echoed"))
		_ = tx.Respond(res)
		return true
	})
}

// An INVITE from a carrier's address is delivered to the switch's carrier
// port, not its client port, with X-FreeSBC-Carrier, the Request-URI
// untouched and its media anchored; the call completes and BYE works.
func TestCarrierInviteDeliveredToCarrierPort(t *testing.T) {
	phone := newUDPClient(t) // stands in for the carrier's gateway
	rig := startCarrierRig(t, fmt.Sprintf("alpha: 127.0.0.1:%d, far: 198.51.100.7:5060", portOf(phone.local)), "", nil)
	answerWithEcho(rig.cs)

	rtp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer rtp.Close()
	phonePort := rtp.LocalAddr().(*net.UDPAddr).Port

	invite := phone.buildInvite("+442071234567", "+15551230000", "example.com", phoneOfferSDP(phonePort))
	res := phone.do(t, invite, rig.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("carrier INVITE: got %d, want 200", res.StatusCode)
	}
	if names := internalHeaderNames(res); len(names) != 0 {
		t.Errorf("the carrier saw internal headers %v on the response", names)
	}
	// Nothing private goes back to the carrier: its route set is FreeSBC's
	// public Record-Route alone, and no header or body names the private
	// socket or a switch port.
	rrs := res.GetHeaders("Record-Route")
	if len(rrs) != 1 || rrs[0].(*sip.RecordRouteHeader).Address.Port != portOf(rig.publicUDP) {
		t.Errorf("response Record-Route = %v, want only FreeSBC's public entry", rrs)
	}
	if a := portLeak(res.String(), rig.privateSIP, rig.fs.addr, rig.cs.addr); a != "" {
		t.Errorf("%s leaked in the response to the carrier:\n%s", a, res.String())
	}

	if got := rig.fs.received(sip.INVITE); len(got) != 0 {
		t.Fatalf("the switch's CLIENT port saw %d carrier INVITEs, want 0", len(got))
	}
	got := rig.cs.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(got) != 1 {
		t.Fatalf("the switch's carrier port saw %d INVITEs, want 1", len(got))
	}
	req := got[0]
	if hs := carrierHeaders(req); len(hs) != 1 || hs[0] != "alpha" {
		t.Errorf("X-FreeSBC-Carrier = %v, want [alpha]", hs)
	}
	if req.Recipient.User != "+15551230000" || req.Recipient.Host != "example.com" {
		t.Errorf("Request-URI = %s, want it unchanged", req.Recipient.String())
	}
	// Media anchored: the switch is offered an SBC port, never the carrier's.
	offer, err := parseLabSDP(req.Body())
	if err != nil {
		t.Fatalf("offer to the switch: %v", err)
	}
	if r := rig.store.Current().RTP; offer.Audio.Port == phonePort || offer.Audio.Port < int(r.Min) || offer.Audio.Port > int(r.Max) {
		t.Errorf("offer to the switch advertises port %d, want an SBC port in %d-%d", offer.Audio.Port, r.Min, r.Max)
	}

	sendAck(t, phone, invite, res, rig.publicUDP)
	if acks := rig.cs.waitFor(sip.ACK, 1, 3*time.Second); len(acks) != 1 || len(carrierHeaders(acks[0])) != 1 {
		t.Errorf("ACK did not reach the carrier port with the carrier header: %v", acks)
	}

	d := waitForDialog(t, rig.harness, invite.CallID().Value())
	if d.carrierName() != "alpha" {
		t.Errorf("dialog carrier = %q, want alpha", d.carrierName())
	}
	calls := rig.srv.Calls()
	if len(calls) != 1 || calls[0].From != "carrier:alpha" || calls[0].To != "switch:"+rig.cs.addr {
		t.Errorf("call record = %+v, want carrier:alpha → switch:%s", calls, rig.cs.addr)
	}
	if n := rig.srv.metrics.Snapshot().CarrierRequests["alpha/inbound/INVITE"]; n != 1 {
		t.Errorf("carrier INVITE metric = %d, want 1", n)
	}

	if r := phone.do(t, buildBye(phone, invite, res), rig.publicUDP); r.StatusCode != 200 {
		t.Fatalf("BYE: %d", r.StatusCode)
	}
	byes := rig.cs.waitFor(sip.BYE, 1, 3*time.Second)
	if len(byes) != 1 || len(carrierHeaders(byes[0])) != 1 {
		t.Errorf("BYE did not reach the carrier port with the carrier header: %v", byes)
	}
	if len(rig.fs.received(sip.BYE)) != 0 {
		t.Error("the BYE went to the switch's client port")
	}
	waitForRelease(t, rig.harness)
}

// Every X-FreeSBC-* header a public sender writes is removed before
// anything else, on the carrier path and on the client path alike; the only
// one the switch sees is the one FreeSBC itself adds.
func TestCarrierForgedInternalHeadersStripped(t *testing.T) {
	phone := newUDPClient(t)
	rig := startCarrierRig(t, fmt.Sprintf("alpha: 127.0.0.1:%d", portOf(phone.local)), "", nil)
	forge := func(req *sip.Request) {
		req.AppendHeader(sip.NewHeader("X-FreeSBC-Carrier", "spoofed"))
		req.AppendHeader(sip.NewHeader("x-freesbc-extra", "1"))
		req.AppendHeader(sip.NewHeader("X-FreeSBC-Arrival", "forged;private"))
	}

	// Carrier path.
	invite := phone.buildInvite("+442071234567", "+15551230000", "example.com", phoneOfferSDP(4000))
	forge(invite)
	if res := phone.do(t, invite, rig.publicUDP); res.StatusCode != 200 {
		t.Fatalf("carrier INVITE: got %d", res.StatusCode)
	}
	got := rig.cs.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(got) != 1 {
		t.Fatalf("carrier port saw %d INVITEs", len(got))
	}
	if names := internalHeaderNames(got[0]); len(names) != 1 || !strings.EqualFold(names[0], "X-FreeSBC-Carrier") {
		t.Errorf("internal headers at the switch = %v, want only X-FreeSBC-Carrier", names)
	}
	if hs := carrierHeaders(got[0]); len(hs) != 1 || hs[0] != "alpha" {
		t.Errorf("X-FreeSBC-Carrier = %v, want [alpha], not the forged value", hs)
	}

	// Client path: a registered client on the same IP, with forged headers.
	client := newUDPClient(t)
	auditRegisterPhone(t, rig.harness, client, "1001")
	ci := client.buildInvite("1001", "2002", "example.com", phoneOfferSDP(4002))
	forge(ci)
	if res := client.do(t, ci, rig.publicUDP); res.StatusCode != 200 {
		t.Fatalf("client INVITE: got %d", res.StatusCode)
	}
	cg := rig.fs.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(cg) != 1 {
		t.Fatalf("client port saw %d INVITEs, want 1", len(cg))
	}
	if names := internalHeaderNames(cg[0]); len(names) != 0 {
		t.Errorf("forged headers reached the switch's client port: %v", names)
	}
	if n := len(rig.cs.received(sip.INVITE)); n != 1 {
		t.Errorf("carrier port saw %d INVITEs, want only the carrier's", n)
	}
}

// A switch that echoes X-FreeSBC-* on a response does not get it relayed
// to the public side (hardening).
func TestCarrierEchoedHeaderNotRelayedToPublic(t *testing.T) {
	client := newUDPClient(t)
	rig := startCarrierRig(t, "far: 198.51.100.7:5060", "", nil)
	auditRegisterPhone(t, rig.harness, client, "1001")
	answerWithEcho(rig.fs)
	res := client.do(t, client.buildInvite("1001", "2002", "example.com", phoneOfferSDP(4004)), rig.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: got %d", res.StatusCode)
	}
	if names := internalHeaderNames(res); len(names) != 0 {
		t.Errorf("echoed internal headers reached the public client: %v", names)
	}
}

// A carrier_sources address that matches no edge.carriers entry is
// delivered with X-FreeSBC-Carrier: unknown.
func TestCarrierSourceWithoutEntryIsUnknown(t *testing.T) {
	phone := newUDPClient(t)
	rig := startCarrierRig(t, "far: 198.51.100.7:5060", "127.0.0.1", nil)
	if res := phone.do(t, phone.buildInvite("+4420", "+1555", "example.com", phoneOfferSDP(4000)), rig.publicUDP); res.StatusCode != 200 {
		t.Fatalf("INVITE: got %d", res.StatusCode)
	}
	got := rig.cs.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(got) != 1 {
		t.Fatalf("carrier port saw %d INVITEs, want 1", len(got))
	}
	if hs := carrierHeaders(got[0]); len(hs) != 1 || hs[0] != "unknown" {
		t.Errorf("X-FreeSBC-Carrier = %v, want [unknown]", hs)
	}
}

// The carrier is named by exact IP:port first, then by IP alone (first by
// sorted name).
func TestCarrierNamingExactThenIP(t *testing.T) {
	exact := newUDPClient(t)
	other := newUDPClient(t)
	rig := startCarrierRig(t, fmt.Sprintf("alpha: 127.0.0.1:%d, beta: 127.0.0.1:%d", freePort(t), portOf(exact.local)), "", nil)
	for _, c := range []struct {
		client *client
		want   string
	}{{exact, "beta"}, {other, "alpha"}} {
		inv := c.client.buildInvite("+4420", "+1555", "example.com", phoneOfferSDP(4000))
		// Pin the source socket: the test client otherwise picks its own.
		inv.Laddr = sip.Addr{IP: net.IPv4(127, 0, 0, 1), Port: portOf(c.client.local)}
		if res := c.client.do(t, inv, rig.publicUDP); res.StatusCode != 200 {
			t.Fatalf("INVITE: got %d", res.StatusCode)
		}
		reqs := rig.cs.received(sip.INVITE)
		last := reqs[len(reqs)-1]
		if hs := carrierHeaders(last); len(hs) != 1 || hs[0] != c.want {
			t.Errorf("source %s named %v, want %s", c.client.local, hs, c.want)
		}
	}
}

// A registered client wins over a carrier source at the same transport
// address: its call goes to the switch's client port, with no carrier
// header, never the unauthenticated carrier port.
func TestCarrierRegisteredClientStaysOnClientPort(t *testing.T) {
	phone := newUDPClient(t)
	rig := startCarrierRig(t, fmt.Sprintf("alpha: 127.0.0.1:%d", portOf(phone.local)), "", nil)
	auditRegisterPhone(t, rig.harness, phone, "1001")
	if res := phone.do(t, phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(4000)), rig.publicUDP); res.StatusCode != 200 {
		t.Fatalf("INVITE: got %d", res.StatusCode)
	}
	got := rig.fs.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(got) != 1 {
		t.Fatalf("client port saw %d INVITEs, want 1", len(got))
	}
	if len(carrierHeaders(got[0])) != 0 {
		t.Error("a registered client's INVITE carried X-FreeSBC-Carrier")
	}
	if n := len(rig.cs.received(sip.INVITE)); n != 0 {
		t.Errorf("carrier port saw %d INVITEs from a registered client, want 0", n)
	}
}

// Neither registered nor a carrier source: silence, and nothing reaches
// either switch port.
func TestCarrierUnregisteredNonCarrierDropped(t *testing.T) {
	phone := newUDPClient(t)
	rig := startCarrierRig(t, "far: 198.51.100.7:5060", "", nil)
	expectSilence(t, phone, phone.buildInvite("+4420", "+1555", "example.com", phoneOfferSDP(4000)), rig.publicUDP)
	// At least one: expectSilence's transaction retransmits the INVITE.
	if n := admissionDrops(rig.harness, dropInviteNotAdmitted); n < 1 {
		t.Errorf("invite_not_admitted drops = %d, want at least 1", n)
	}
	if len(rig.fs.received(sip.INVITE))+len(rig.cs.received(sip.INVITE)) != 0 {
		t.Error("a dropped INVITE reached a switch")
	}
}

// A carrier's in-dialog request that names no dialog on record still goes
// to the carrier port, with the header.
func TestCarrierInDialogFallbackGoesToCarrierPort(t *testing.T) {
	phone := newUDPClient(t)
	rig := startCarrierRig(t, fmt.Sprintf("alpha: 127.0.0.1:%d", portOf(phone.local)), "", nil)
	invite := phone.buildInvite("+4420", "+1555", "example.com", phoneOfferSDP(4000))
	ghost := sip.NewResponseFromRequest(invite, 200, "OK", nil)
	ghost.To().Params.Add("tag", "ghost-tag")
	bye := buildBye(phone, invite, ghost)
	bye.SetTransport("UDP")
	if res := phone.do(t, bye, rig.publicUDP); res.StatusCode != 200 {
		t.Fatalf("BYE: got %d", res.StatusCode)
	}
	got := rig.cs.waitFor(sip.BYE, 1, 3*time.Second)
	if len(got) != 1 || len(carrierHeaders(got[0])) != 1 {
		t.Fatalf("carrier port BYEs = %v, want one with X-FreeSBC-Carrier", got)
	}
	if len(rig.fs.received(sip.BYE)) != 0 {
		t.Error("the fallback BYE went to the switch's client port")
	}
}

// A DNS-name carrier becomes a source once the background refresh has
// resolved it: SRV, then A.
func TestCarrierDNSResolvedSourceAdmitted(t *testing.T) {
	phone := newUDPClient(t)
	port := uint16(portOf(phone.local))
	stub := &dnsStub{
		srv: map[string][]*net.SRV{"sip.carrier.example": {{Target: "gw.carrier.example.", Port: port, Priority: 1}}},
		ips: map[string][]string{"gw.carrier.example": {"127.0.0.1"}},
	}
	rig := startCarrierRig(t, "dns: sip.carrier.example", "", func(s *Server) {
		s.carriers.lookupSRV, s.carriers.lookupIP = stub.lookupSRV, stub.lookupIP
	})
	deadline := time.Now().Add(3 * time.Second)
	for {
		if name, ok := rig.srv.carriers.snapshot().carrierFor(ap(phone.local), "udp"); ok && name == "dns" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the carrier was never resolved")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if res := phone.do(t, phone.buildInvite("+4420", "+1555", "example.com", phoneOfferSDP(4000)), rig.publicUDP); res.StatusCode != 200 {
		t.Fatalf("INVITE from a resolved carrier: got %d", res.StatusCode)
	}
	got := rig.cs.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(got) != 1 {
		t.Fatalf("carrier port saw %d INVITEs", len(got))
	}
	if hs := carrierHeaders(got[0]); len(hs) != 1 || hs[0] != "dns" {
		t.Errorf("X-FreeSBC-Carrier = %v, want [dns]", hs)
	}
}

// switchRequest sends an out-of-dialog request from the fake switch to the
// proxy's private socket and returns the final response.
func switchRequest(t *testing.T, f *fakeSwitch, method sip.RequestMethod, ruri sip.Uri, dest string) *sip.Response {
	t.Helper()
	req := f.callRequest(ruri, dest, "")
	req.Method = method
	req.CSeq().MethodName = method
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := f.cli.TransactionRequest(ctx, req)
	if err != nil {
		t.Fatalf("fake switch %s: %v", method, err)
	}
	defer tx.Terminate()
	for {
		select {
		case res := <-tx.Responses():
			if res.StatusCode >= 200 {
				return res
			}
		case <-tx.Done():
			t.Fatalf("fake switch %s: %v", method, tx.Err())
		case <-ctx.Done():
			t.Fatalf("fake switch %s timed out", method)
		}
	}
}

// What the switch originates is classified by Request-URI alone: a carrier
// entry → carrier path (a carrier with no resolved address is 503;
// carrier_outbound_test.go has the proxying), a client token → client path,
// FreeSBC itself → OPTIONS answered, anything else → 404; a method a
// carrier does not accept → 405.
func TestCarrierPrivateClassification(t *testing.T) {
	rig := startCarrierRig(t, "alpha: 127.0.0.1:5090, dns: Carrier.Example.com:5070, nores: nores.example.com:5071", "", func(s *Server) {
		s.carriers.lookupSRV = (&dnsStub{}).lookupSRV
		s.carriers.lookupIP = (&dnsStub{ips: map[string][]string{"carrier.example.com": {"198.51.100.9"}}}).lookupIP
	})
	deadline := time.Now().Add(3 * time.Second)
	for len(rig.srv.carriers.snapshot().addrs["dns"]) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the dns carrier was never resolved")
		}
		time.Sleep(10 * time.Millisecond)
	}
	fs, priv := rig.fs, rig.privateSIP
	privPort := portOf(priv)
	bogus := sip.NewParams()
	bogus.Add("fsbc", "bogus-token")

	for _, c := range []struct {
		name   string
		method sip.RequestMethod
		ruri   sip.Uri
		want   int
	}{
		{"INVITE to an unresolved carrier", sip.INVITE, sip.Uri{User: "+1555", Host: "nores.example.com", Port: 5071}, 503},
		{"INVITE, host case and trailing dot", sip.INVITE, sip.Uri{User: "+1555", Host: "NORES.example.COM.", Port: 5071}, 503},
		{"INVITE, wrong port", sip.INVITE, sip.Uri{User: "+1555", Host: "carrier.example.com"}, 404},
		{"INVITE to a stranger", sip.INVITE, sip.Uri{User: "+1555", Host: "203.0.113.50"}, 404},
		{"INVITE to an expired token", sip.INVITE, sip.Uri{User: "1001", Host: "127.0.0.1", Port: 1234, UriParams: bogus}, 404},
		{"REGISTER to an unresolved carrier", sip.REGISTER, sip.Uri{Host: "nores.example.com", Port: 5071}, 503},
		{"REGISTER to a stranger", sip.REGISTER, sip.Uri{Host: "203.0.113.50"}, 404},
		{"OPTIONS to an unresolved carrier", sip.OPTIONS, sip.Uri{Host: "nores.example.com", Port: 5071}, 503},
		{"OPTIONS to FreeSBC", sip.OPTIONS, sip.Uri{Host: "127.0.0.1", Port: privPort}, 200},
		{"OPTIONS to a stranger", sip.OPTIONS, sip.Uri{Host: "203.0.113.50"}, 404},
		{"NOTIFY to a carrier", sip.NOTIFY, sip.Uri{User: "x", Host: "127.0.0.1", Port: 5090}, 405},
		{"NOTIFY to a stranger", sip.NOTIFY, sip.Uri{User: "x", Host: "203.0.113.50"}, 404},
		{"MESSAGE to a carrier", sip.MESSAGE, sip.Uri{User: "x", Host: "127.0.0.1", Port: 5090}, 405},
	} {
		res := switchRequest(t, fs, c.method, c.ruri, priv)
		if res.StatusCode != c.want {
			t.Errorf("%s: got %d %s, want %d", c.name, res.StatusCode, res.Reason, c.want)
		}
	}
	if n := len(rig.cs.received(sip.INVITE)) + len(fs.received(sip.INVITE)); n != 0 {
		t.Errorf("a classified-away INVITE was forwarded (%d)", n)
	}
}

// Carrier sources are exempt from the per-source early-call cap that
// bounds registered clients (shield.carrier_rate_limit bounds them
// instead): one INVITE more than the cap is not refused.
func TestCarrierExemptFromEarlyCap(t *testing.T) {
	rig := startCarrierRig(t, "far: 198.51.100.7:5060", "127.0.0.1", nil)
	rig.cs.setInviteHook(rig.cs.silentHook())
	c := auditUDP(t)
	port := auditUDPPort(c)
	const n = maxEarlyPerSource + 1
	for i := 0; i < n; i++ {
		body := phoneOfferSDP(31000 + 2*i)
		auditRawRequest(t, c, rig.publicUDP, fmt.Sprintf("INVITE sip:2002@example.com SIP/2.0\r\n"+
			"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK-carrier-flood-%d;rport\r\n"+
			"Max-Forwards: 70\r\nFrom: <sip:1001@example.com>;tag=flood%d\r\nTo: <sip:2002@example.com>\r\n"+
			"Call-ID: carrier-flood-%d-%d\r\nCSeq: 1 INVITE\r\nContact: <sip:1001@127.0.0.1:%d>\r\n"+
			"Content-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s",
			port, i, i, i, time.Now().UnixNano(), port, len(body), body))
		time.Sleep(5 * time.Millisecond)
	}
	buf := make([]byte, 8192)
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		k, _, err := c.ReadFromUDP(buf)
		if err == nil && strings.HasPrefix(string(buf[:k]), "SIP/2.0 503") {
			t.Fatalf("a carrier INVITE was refused by the per-source cap: %q", strings.SplitN(string(buf[:k]), "\r\n", 2)[0])
		}
	}
	if got := len(rig.cs.waitFor(sip.INVITE, n, 3*time.Second)); got != n {
		t.Errorf("carrier port saw %d INVITEs, want %d", got, n)
	}
}
