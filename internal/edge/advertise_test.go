package edge

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/config"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// edge.advertise (issue #164): behind a NAT that translates the port, the
// public socket binds its edge.listen port while Via, Contact and
// Record-Route name the edge.advertise one.

// advTopoYAML is topoYAML with the udp port translated (16060 outside, 5060
// bound), ws left alone, and a tls carrier with no tls listener.
const advTopoYAML = `
public: {ip: 203.0.113.7, bind: 172.31.5.10}
private: {ip: 10.77.0.2}
edge:
  switch: [10.77.0.10:5060]
  listen: {udp: 5060, ws: 18080}
  advertise: {udp: 16060}
  carriers:
    t: {host: 198.51.100.20, transport: tls}
`

func TestTopologyAdvertisedPort(t *testing.T) {
	topo := buildTestTopology(t, advTopoYAML)
	udp, ok := topo.publicSide("udp")
	if !ok {
		t.Fatal("no udp public side")
	}
	if udp.advIP.String() != "203.0.113.7" || udp.advPort != 16060 {
		t.Errorf("udp side advertises %v:%d, want 203.0.113.7:16060", udp.advIP, udp.advPort)
	}
	// The outbound pin is the bound socket, never the advertised port.
	if udp.laddr.IP.String() != "172.31.5.10" || udp.laddr.Port != 5060 {
		t.Errorf("udp laddr = %+v, want 172.31.5.10:5060", udp.laddr)
	}
	if v := udp.via("z9hG4bKadv"); v.Port != 16060 {
		t.Errorf("Via port = %d, want 16060", v.Port)
	}
	if u := udp.uri(); u.Port != 16060 {
		t.Errorf("Contact URI port = %d, want 16060", u.Port)
	}
	if rr := udp.recordRoute(); rr.Address.Port != 16060 {
		t.Errorf("Record-Route port = %d, want 16060", rr.Address.Port)
	}
	// A transport left out of edge.advertise advertises its listen port.
	if ws, _ := topo.publicSide("ws"); ws.advPort != 18080 {
		t.Errorf("ws side advertises %d, want 18080", ws.advPort)
	}
	// A tls carrier with no tls listener keeps the synthetic default-port
	// side: edge.advertise applies only beside a listener.
	if tls, ok := topo.publicSide("tls"); !ok || !tls.outbound || tls.advPort != config.DefaultCarrierTLSPort {
		t.Errorf("tls synthetic side = %+v (ok %v), want outbound at %d", tls, ok, config.DefaultCarrierTLSPort)
	}
	// A carrier REGISTER's Contact names the advertised port.
	c := (&Server{}).carrierContactURI(udp, "line1", "tok")
	if c.Host != "203.0.113.7" || c.Port != 16060 {
		t.Errorf("carrier REGISTER Contact = %s, want 203.0.113.7:16060", c.String())
	}

	// Only the advertised pair is FreeSBC's own: it is the only one ever
	// written, and public.ip with the listen port is the router's.
	for _, u := range []sip.Uri{{Host: "203.0.113.7", Port: 16060}, {Host: "203.0.113.7", Port: 18080}} {
		if !topo.isSelf(u) {
			t.Errorf("%v not recognised as self", u)
		}
	}
	for _, u := range []sip.Uri{
		{Host: "203.0.113.7", Port: 5060},  // the listen port on public.ip
		{Host: "203.0.113.7"},              // portless: 5060
		{Host: "172.31.5.10", Port: 5060},  // the bind address is not advertised
		{Host: "172.31.5.10", Port: 16060}, // nor with the advertised port
	} {
		if topo.isSelf(u) {
			t.Errorf("%v wrongly recognised as self", u)
		}
	}
	if !topo.isSelfVia(&sip.ViaHeader{Transport: "UDP", Host: "203.0.113.7", Port: 16060}) {
		t.Error("the advertised Via is not recognised as ours")
	}
	if topo.isSelfVia(&sip.ViaHeader{Transport: "UDP", Host: "203.0.113.7", Port: 5060}) {
		t.Error("a Via naming the listen port on public.ip was taken as ours")
	}
}

// startAdvertiseHarness is the strict harness (no carrier_sources, so the
// phone is a client) with the public UDP socket bound on one port and
// another advertised. Nothing listens on the advertised port: every test
// request is sent to the bound one, as the NAT would deliver it.
func startAdvertiseHarness(t *testing.T) (h *harness, adv int) {
	t.Helper()
	pubUDP, adv, priv, up := nextPort(t), nextPort(t), nextPort(t), nextPort(t)
	yaml := harnessYAML(t, []string{fmt.Sprintf("127.0.0.1:%d", up)}, pubUDP, 0, 0, nextMediaBase(t), "")
	listen := fmt.Sprintf("  listen: {udp: %d}\n", pubUDP)
	if !strings.Contains(yaml, listen) {
		t.Fatalf("harness YAML has no %q", listen)
	}
	yaml = strings.Replace(yaml, listen, listen+fmt.Sprintf("  advertise: {udp: %d}\n", adv), 1)
	h = newHarness(t, yaml, priv)
	h.upstream = fmt.Sprintf("127.0.0.1:%d", up)
	h.fs = startFakeSwitch(t, h.upstream)
	h.run()
	if got := h.srv.ListenerInfos()[0]; got.Bind != h.publicUDP || got.Advertised != fmt.Sprintf("127.0.0.1:%d", adv) {
		t.Fatalf("listener info = %+v, want bind %s advertised 127.0.0.1:%d", got, h.publicUDP, adv)
	}
	return h, adv
}

// A client's call: the Record-Route the phone gets and the public entry the
// switch gets name the advertised port, and the phone's ACK and BYE, routed
// by a Route naming that port, are recognised as FreeSBC's and reach the
// switch.
//
// Timing-based over real UDP loopback: re-run once before treating a flake
// as failure.
func TestAdvertisedPortClientCall(t *testing.T) {
	h, adv := startAdvertiseHarness(t)
	phone := newUDPClient(t)
	auditRegisterPhone(t, h, phone, "1001")
	phoneRTP := listenRTP(t, freePort(t))

	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(udpPort(phoneRTP)))
	res := phone.do(t, invite, h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: got %d, want 200", res.StatusCode)
	}
	assertClientRecordRoute(t, "200 at the phone", res.GetHeaders("Record-Route"), adv)
	if c, ok := fsip.ContactURI(res); !ok || c.Host != "127.0.0.1" || c.Port != adv {
		t.Errorf("200 Contact at the phone = %v, want FreeSBC's 127.0.0.1:%d", c, adv)
	}

	invites := h.fs.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(invites) != 1 {
		t.Fatalf("the switch saw %d INVITEs", len(invites))
	}
	public := false
	for _, hdr := range invites[0].GetHeaders("Record-Route") {
		rr := hdr.(*sip.RecordRouteHeader)
		if rr.Address.Port == portOf(h.publicUDP) {
			t.Errorf("the switch's Record-Route %s names the listen port", rr.Address.String())
		}
		public = public || rr.Address.Port == adv
	}
	if !public {
		t.Errorf("no Record-Route at the switch names the advertised port %d", adv)
	}

	// Route: <sip:127.0.0.1:adv;lr>, delivered to the bound socket.
	ack := h.fs.received(sip.ACK)
	sendAck(t, phone, invite, res, h.publicUDP)
	if got := h.fs.waitFor(sip.ACK, len(ack)+1, 3*time.Second); len(got) != len(ack)+1 {
		t.Fatalf("the switch saw %d ACKs, want %d", len(got), len(ack)+1)
	}
	bye := buildBye(phone, invite, res)
	if r := bye.Route(); r == nil || r.Address.Port != adv {
		t.Fatalf("BYE Route = %v, want the advertised port %d", r, adv)
	}
	if r := phone.do(t, bye, h.publicUDP); r.StatusCode != 200 {
		t.Errorf("BYE: got %d, want 200", r.StatusCode)
	}
	byes := h.fs.waitFor(sip.BYE, 1, 3*time.Second)
	if len(byes) != 1 {
		t.Fatalf("the switch saw %d BYEs, want 1", len(byes))
	}
	for _, hdr := range byes[0].GetHeaders("Route") {
		if r := hdr.(*sip.RouteHeader); r.Address.Port == adv {
			t.Errorf("FreeSBC's own Route %s was forwarded to the switch", r.Address.String())
		}
	}
	waitForRelease(t, h)
}

// A call the switch places to the phone: the INVITE and the BYE that reach
// the phone carry FreeSBC's Via, and the INVITE its Record-Route and
// Contact, at the advertised port.
//
// Timing-based over real UDP loopback: re-run once before treating a flake
// as failure.
func TestAdvertisedPortSwitchCall(t *testing.T) {
	h, adv := startAdvertiseHarness(t)
	phone := newUDPClient(t)
	ruri := auditRegisterPhone(t, h, phone, "1001")
	phoneRTP := listenRTP(t, freePort(t))
	phone.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
		if req.Method != sip.INVITE {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
			return
		}
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(phoneOfferSDP(udpPort(phoneRTP))))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: phone.contactURI("1001")})
		res.To().Params.Add("tag", sip.GenerateTagN(12))
		_ = tx.Respond(res)
	})

	res := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort))
	if res.StatusCode != 200 {
		t.Fatalf("switch INVITE: got %d, want 200", res.StatusCode)
	}
	select {
	case got := <-phone.inbound:
		if got.Method != sip.INVITE {
			t.Fatalf("the phone received %s, want INVITE", got.Method)
		}
		if v := got.Via(); v == nil || v.Host != "127.0.0.1" || v.Port != adv {
			t.Errorf("INVITE top Via at the phone = %v, want 127.0.0.1:%d", v, adv)
		}
		assertClientRecordRoute(t, "INVITE at the phone", got.GetHeaders("Record-Route"), adv)
		if c, ok := fsip.ContactURI(got); !ok || c.Host != "127.0.0.1" || c.Port != adv {
			t.Errorf("INVITE Contact at the phone = %v, want 127.0.0.1:%d", c, adv)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the phone never received the INVITE")
	}
	// The switch keeps the pair, public (advertised) first.
	rrs := res.GetHeaders("Record-Route")
	assertSwitchRecordRoute(t, "200 at the switch", rrs, portOf(h.privateSIP))
	if first := rrs[0].(*sip.RecordRouteHeader); first.Address.Port != adv {
		t.Errorf("200 at the switch: public Record-Route %s, want port %d", first.Address.String(), adv)
	}

	h.fs.sendAckTo2xx(t, res)
	if r := h.fs.uacBye(t, res); r.StatusCode != 200 {
		t.Errorf("switch BYE: got %d, want 200", r.StatusCode)
	}
	deadline := time.After(5 * time.Second)
	for {
		select {
		case got := <-phone.inbound:
			if got.Method != sip.BYE {
				continue // the ACK
			}
			if v := got.Via(); v == nil || v.Port != adv {
				t.Errorf("BYE top Via at the phone = %v, want port %d", v, adv)
			}
			waitForRelease(t, h)
			return
		case <-deadline:
			t.Fatal("the phone never received the BYE")
		}
	}
}
