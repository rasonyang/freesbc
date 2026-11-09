package edge

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// Carrier path on the shared socket (issue #320): the carrier is a public
// party at 127.0.0.1, the switch at 127.0.0.2 with its client port and its
// carrier port, and the one socket is 127.0.0.1:<udp> with public.ip
// 203.0.113.7. Timing-based over real UDP loopback: re-run once before
// treating a flake as failure.

type sharedCarrierRig struct {
	*harness
	cs *fakeSwitch // the switch's carrier port, at 127.0.0.2
}

// startSharedCarrierRig is startHarnessShared with edge.carriers = carriers
// (a YAML flow-map body) and a second fake switch as the switch's carrier
// port.
func startSharedCarrierRig(t *testing.T, carriers string) *sharedCarrierRig {
	t.Helper()
	requireLoopbackAlias(t, sharedSwitchIP)
	pubUDP, up, cp := freePort(t), freePort(t), freePort(t)
	mediaBase := nextMediaBase(t)
	yaml := harnessYAML(t, []string{fmt.Sprintf("%s:%d", sharedSwitchIP, up)}, pubUDP, 0, 0, mediaBase, "")
	const old = "public: {ip: 127.0.0.1}"
	if !strings.Contains(yaml, old) {
		t.Fatal("harness yaml changed")
	}
	yaml = strings.Replace(yaml, old, "public: {ip: 203.0.113.7, bind: 127.0.0.1}", 1)
	yaml = strings.Replace(yaml, "edge:\n", fmt.Sprintf("edge:\n  switch_carrier_port: %d\n  carriers: {%s}\n", cp, carriers), 1)
	h := newHarness(t, yaml, pubUDP)
	if !h.srv.shared {
		t.Fatal("not in shared mode")
	}
	h.upstream = fmt.Sprintf("%s:%d", sharedSwitchIP, up)
	h.fs = startFakeSwitch(t, h.upstream)
	cs := startFakeSwitch(t, fmt.Sprintf("%s:%d", sharedSwitchIP, cp))
	h.upstreams["carrier-port"] = cs
	h.run()
	return &sharedCarrierRig{harness: h, cs: cs}
}

// carrier -> switch: the INVITE of a carrier source reaches the switch's
// carrier port (not its client port) with X-FreeSBC-Carrier, 200, ACK and
// BYE work, media crosses both planes. byeBySwitch picks who hangs up.
func runSharedCarrierInbound(t *testing.T, byeBySwitch bool) {
	carrier := newUDPClient(t)
	rig := startSharedCarrierRig(t, fmt.Sprintf("alpha: 127.0.0.1:%d", portOf(carrier.local)))
	tags := make(chan string, 2)
	rig.cs.setInviteHook(auditTaggedAnswerHook(rig.cs, tags, nil))
	carRTP := listenRTPOn(t, "127.0.0.1", 0)
	swRTP := listenRTPOn(t, sharedSwitchIP, rig.cs.rtpPort)

	invite := carrier.buildInvite("+442071234567", "+15551230000", "example.com", phoneOfferSDP(carRTP.LocalAddr().(*net.UDPAddr).Port))
	res := carrier.do(t, invite, rig.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("carrier INVITE: %d", res.StatusCode)
	}
	if names := internalHeaderNames(res); len(names) != 0 {
		t.Errorf("internal headers on the response to the carrier: %v", names)
	}
	if got := rig.fs.received(sip.INVITE); len(got) != 0 {
		t.Fatalf("the switch's client port saw %d carrier INVITEs", len(got))
	}
	got := rig.cs.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(got) != 1 {
		t.Fatalf("the switch's carrier port saw %d INVITEs", len(got))
	}
	req := got[0]
	if hs := carrierHeaders(req); len(hs) != 1 || hs[0] != "alpha" {
		t.Errorf("X-FreeSBC-Carrier = %v, want [alpha]", hs)
	}
	if req.Recipient.User != "+15551230000" || req.Recipient.Host != "example.com" {
		t.Errorf("Request-URI = %s, want it unchanged", req.Recipient.String())
	}
	// The carrier is answered with the public address only.
	rrs := res.GetHeaders("Record-Route")
	if len(rrs) != 1 || rrs[0].(*sip.RecordRouteHeader).Address.Host != "203.0.113.7" {
		t.Errorf("response Record-Route = %v, want only the public entry", rrs)
	}
	if strings.Contains(res.String(), sharedSwitchIP) || portLeak(res.String(), rig.fs.addr, rig.cs.addr) != "" {
		t.Errorf("the switch leaked in the response to the carrier:\n%s", res.String())
	}

	upstream, err := parseLabSDP(req.Body())
	if err != nil {
		t.Fatal(err)
	}
	answer, err := parseLabSDP(res.Body())
	if err != nil {
		t.Fatal(err)
	}
	// One pair per leg, two per call, on the shared address (the layout the
	// owner chose; change here if that ever changes).
	if n := portsInUse(rig.harness); n != 2 || answer.Audio.Port == upstream.Audio.Port {
		t.Errorf("pairs in use = %d, ports %d/%d; want two distinct pairs", n, answer.Audio.Port, upstream.Audio.Port)
	}
	sbcPublic := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: answer.Audio.Port}
	sbcPrivate := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: upstream.Audio.Port}
	if !relayReaches(t, carRTP, sbcPublic, swRTP, rtpPacket(0, 1, 160)) {
		t.Fatal("carrier to switch audio never arrived")
	}
	if !relayReaches(t, swRTP, sbcPrivate, carRTP, rtpPacket(0, 2, 160)) {
		t.Fatal("switch to carrier audio never arrived")
	}

	sendAck(t, carrier, invite, res, rig.publicUDP)
	if acks := rig.cs.waitFor(sip.ACK, 1, 3*time.Second); len(acks) != 1 || len(carrierHeaders(acks[0])) != 1 {
		t.Errorf("ACK did not reach the carrier port with the carrier header: %v", acks)
	}
	d := waitForDialog(t, rig.harness, invite.CallID().Value())
	if d.carrierName() != "alpha" {
		t.Errorf("dialog carrier = %q", d.carrierName())
	}

	if byeBySwitch {
		tag := <-tags
		drain(carrier.inbound)
		if r := rig.cs.inDialog(t, sip.BYE, req, tag); r.StatusCode != 200 {
			t.Fatalf("switch BYE: %d", r.StatusCode)
		}
		select {
		case b := <-carrier.inbound:
			if b.Method != sip.BYE {
				t.Fatalf("the carrier received %s, want BYE", b.Method)
			}
			if strings.Contains(b.String(), sharedSwitchIP) || portLeak(b.String(), rig.fs.addr, rig.cs.addr) != "" {
				t.Errorf("the switch leaked in the BYE to the carrier:\n%s", b.String())
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the carrier never received the BYE")
		}
	} else {
		if r := carrier.do(t, buildBye(carrier, invite, res), rig.publicUDP); r.StatusCode != 200 {
			t.Fatalf("carrier BYE: %d", r.StatusCode)
		}
		byes := rig.cs.waitFor(sip.BYE, 1, 3*time.Second)
		if len(byes) != 1 || len(carrierHeaders(byes[0])) != 1 {
			t.Errorf("BYE did not reach the carrier port with the carrier header: %v", byes)
		}
	}
	waitForRelease(t, rig.harness)
}

func TestSharedSocketCarrierToSwitchByeByCarrier(t *testing.T) { runSharedCarrierInbound(t, false) }
func TestSharedSocketCarrierToSwitchByeBySwitch(t *testing.T)  { runSharedCarrierInbound(t, true) }

// switch -> carrier: the Request-URI naming an edge.carriers entry is proxied
// unchanged; the carrier sees public.ip in Via, Contact and Record-Route and
// neither the shared address nor the switch IP anywhere; the carrier's BYE
// gets back to the switch; media crosses both planes.
func TestSharedSocketSwitchToCarrier(t *testing.T) {
	cport := freePort(t)
	requireLoopbackAlias(t, sharedSwitchIP)
	carrier := startFakeSwitch(t, fmt.Sprintf("127.0.0.1:%d", cport))
	rig := startSharedCarrierRig(t, fmt.Sprintf("alpha: 127.0.0.1:%d", cport))
	rig.upstreams["carrier"] = carrier
	carrier.routeDest = rig.publicUDP // public.ip is not local on loopback
	tags := answerWithTag(carrier)
	swRTP := listenRTPOn(t, sharedSwitchIP, rig.fs.rtpPort)
	carRTP := listenRTPOn(t, "127.0.0.1", carrier.rtpPort)

	ruri := sip.Uri{User: "1000200030004", Host: "127.0.0.1", Port: cport}
	res := rig.fs.call(t, ruri, rig.privateSIP, rig.fs.answerSDP(&sip.Request{}))
	if res.StatusCode != 200 {
		t.Fatalf("switch INVITE: %d", res.StatusCode)
	}
	invs := carrier.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(invs) != 1 {
		t.Fatalf("carrier saw %d INVITEs", len(invs))
	}
	inv := invs[0]
	if inv.Recipient.String() != ruri.String() {
		t.Errorf("Request-URI = %s, want %s unchanged", inv.Recipient.String(), ruri.String())
	}
	pubPort := portOf(rig.publicUDP)
	if vias := inv.GetHeaders("Via"); len(vias) != 1 || inv.Via().Host != "203.0.113.7" || inv.Via().Port != pubPort {
		t.Errorf("Via = %v, want exactly 203.0.113.7:%d", vias, pubPort)
	}
	if c := inv.Contact(); c == nil || c.Address.Host != "203.0.113.7" || c.Address.Port != pubPort {
		t.Errorf("Contact = %v, want 203.0.113.7:%d", c, pubPort)
	}
	rrs := inv.GetHeaders("Record-Route")
	if len(rrs) != 1 || rrs[0].(*sip.RecordRouteHeader).Address.Host != "203.0.113.7" || rrs[0].(*sip.RecordRouteHeader).Address.Port != pubPort {
		t.Errorf("Record-Route = %v, want only 203.0.113.7:%d", rrs, pubPort)
	}
	// Neither the switch nor the shared (private) address:port is anywhere in
	// the INVITE, SDP included. 127.0.0.1 is the carrier's own address, so
	// the shared address is recognised by its port.
	raw := inv.String()
	if strings.Contains(raw, sharedSwitchIP) || strings.Contains(raw, fmt.Sprintf("127.0.0.1:%d", pubPort)) ||
		portLeak(raw, rig.fs.addr, rig.cs.addr) != "" {
		t.Errorf("a private address leaked to the carrier:\n%s", raw)
	}
	if names := internalHeaderNames(inv); len(names) != 0 {
		t.Errorf("internal headers reached the carrier: %v", names)
	}
	offer, err := parseLabSDP(inv.Body())
	if err != nil {
		t.Fatal(err)
	}
	if offer.Audio.Address.String() != "203.0.113.7" || strings.Contains(string(inv.Body()), "127.0.0.") {
		t.Errorf("SDP to the carrier names a non-public address:\n%s", inv.Body())
	}
	answer, err := parseLabSDP(res.Body())
	if err != nil {
		t.Fatal(err)
	}

	if n := portsInUse(rig.harness); n != 2 || offer.Audio.Port == answer.Audio.Port {
		t.Errorf("pairs in use = %d, ports %d/%d; want two distinct pairs", n, offer.Audio.Port, answer.Audio.Port)
	}
	sbcPublic := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: offer.Audio.Port}
	sbcPrivate := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: answer.Audio.Port}
	if !relayReaches(t, swRTP, sbcPrivate, carRTP, rtpPacket(0, 1, 160)) {
		t.Fatal("switch to carrier audio never arrived")
	}
	if !relayReaches(t, carRTP, sbcPublic, swRTP, rtpPacket(0, 2, 160)) {
		t.Fatal("carrier to switch audio never arrived")
	}

	rig.fs.sendAckTo2xx(t, res)
	acks := carrier.waitFor(sip.ACK, 1, 3*time.Second)
	if len(acks) != 1 || strings.Contains(acks[0].String(), sharedSwitchIP) {
		t.Fatalf("carrier ACKs = %v", acks)
	}
	tag := <-tags
	waitForDialog(t, rig.harness, inv.CallID().Value())
	if b := carrier.inDialog(t, sip.BYE, inv, tag); b.StatusCode != 200 {
		t.Fatalf("carrier BYE: %d", b.StatusCode)
	} else if strings.Contains(b.String(), sharedSwitchIP) || portLeak(b.String(), rig.fs.addr, rig.cs.addr) != "" {
		t.Errorf("the switch leaked in the response to the carrier's BYE:\n%s", b.String())
	}
	if got := rig.fs.waitFor(sip.BYE, 1, 3*time.Second); len(got) != 1 {
		t.Fatalf("the switch saw %d BYEs", len(got))
	}
	waitForRelease(t, rig.harness)
}
