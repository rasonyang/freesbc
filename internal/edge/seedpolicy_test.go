package edge

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"

	"github.com/freesbc/freesbc/internal/media"
)

// Seed policy (issue #290): before a side latches, the SBC sends to the
// address the far end wrote in its SDP only within limits. A registered
// client's media goes to the IP its signalling came from, at the SDP port;
// a carrier keeps its SDP address minus the classes that cannot be a
// carrier's media. Observed through Session.SendTarget and, where the
// destination is on loopback, through real packets.
//
// The strict harness (no edge.carrier_sources) plus a registration makes
// 127.0.0.1 a client; the carrier rigs make it a carrier.
//
// Timing-based over real UDP loopback: re-run once before treating a flake
// as failure.

// natOfferSDP is phoneOfferSDP with a c= line naming ip: a phone behind NAT
// writing its private address, or a client writing someone else's.
func natOfferSDP(port int, ip string) string {
	return strings.Replace(phoneOfferSDP(port), "c=IN IP4 127.0.0.1", "c=IN IP4 "+ip, 1)
}

func ipv4Offer(sdpBody, ip string) string {
	return strings.Replace(sdpBody, "c=IN IP4 127.0.0.1", "c=IN IP4 "+ip, 1)
}

// awaitTarget waits for side A of d's media to send to want (or to nothing
// when want is the zero value) and fails with the last target otherwise.
func awaitTarget(t *testing.T, d *dialog, want netip.AddrPort) {
	t.Helper()
	var got netip.AddrPort
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		got = d.session().rtp.SendTarget(media.SideA)
		if got == want {
			return
		}
	}
	t.Fatalf("public side sends to %v, want %v", got, want)
}

func lo(port int) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
}

// clientSDPAddrs are the destinations a client's SDP must never steer
// media to: the private LAN, the switch's address, a third party.
var clientSDPAddrs = []string{"10.77.0.10", "192.168.44.44", "172.16.4.4", "100.64.1.1", "203.0.113.50"}

// A registered client as the caller, the NAT case: its c= is private and
// it has sent nothing, yet early media from the switch reaches its
// signalling IP at its SDP port, and no SDP address is ever the target.
func TestClientOfferSeedPinnedToSignallingSource(t *testing.T) {
	for _, ip := range clientSDPAddrs {
		t.Run(ip, func(t *testing.T) {
			h := startHarnessStrict(t, false, false)
			phone := newUDPClient(t)
			auditRegisterPhone(t, h, phone, "1001")
			phoneRTP := listenRTP(t, freePort(t))
			fsRTP := listenRTP(t, h.fs.rtpPort)

			invite := phone.buildInvite("1001", "2002", "example.com", natOfferSDP(udpPort(phoneRTP), ip))
			res := phone.do(t, invite, h.publicUDP)
			if res.StatusCode != 200 {
				t.Fatalf("INVITE: got %d, want 200", res.StatusCode)
			}
			sendAck(t, phone, invite, res, h.publicUDP)
			d := waitForDialog(t, h, fsip.CallID(invite))
			if d.carrierName() != "" {
				t.Fatalf("the call is a carrier call (%q), want a client's", d.carrierName())
			}
			awaitTarget(t, d, lo(udpPort(phoneRTP)))
			if !relayReaches(t, fsRTP, loopback(d.session().privatePort), phoneRTP, rtpPacket(0, 400, 160)) {
				t.Error("early media never reached the NAT'd client at its signalling IP")
			}
			if r := phone.do(t, buildBye(phone, invite, res), h.publicUDP); r.StatusCode != 200 {
				t.Errorf("BYE: %d", r.StatusCode)
			}
			waitForRelease(t, h)
		})
	}
}

// The re-INVITE and UPDATE paths (update.go, applyReInvite) apply the same
// pin in both directions: the phone's offer, and the phone's answer to the
// switch's.
func TestClientReInviteSeedPinned(t *testing.T) {
	r := startUpdRigOn(t, startHarnessStrict(t, false, false), true)
	d := waitForDialog(t, r.h, fsip.CallID(r.invite))

	// The phone's UPDATE offer.
	moved := listenRTP(t, freePort(t))
	if res := r.phoneUpdate(t, 2, natOfferSDP(udpPort(moved), "10.77.0.10")); res.StatusCode != 200 {
		t.Fatalf("UPDATE: got %d, want 200", res.StatusCode)
	}
	awaitTarget(t, d, lo(udpPort(moved)))
	if !relayReaches(t, r.fsRTP, loopback(r.privPort), moved, rtpPacket(0, 410, 160)) {
		t.Error("switch -> phone audio after the UPDATE never arrived")
	}

	// The phone's re-INVITE offer.
	moved2 := listenRTP(t, freePort(t))
	re := uacRequest(sip.INVITE, r.invite, r.res, 3, "127.0.0.1", 0)
	re.AppendHeader(&sip.ContactHeader{Address: r.phone.contactURI("1001")})
	re.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	re.SetBody([]byte(natOfferSDP(udpPort(moved2), "192.168.1.5")))
	if res := r.phone.do(t, re, r.h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("re-INVITE: got %d, want 200", res.StatusCode)
	}
	awaitTarget(t, d, lo(udpPort(moved2)))

	// The phone's answer to the switch's UPDATE.
	moved3 := listenRTP(t, freePort(t))
	r.phone.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
		res := sip.NewResponseFromRequest(req, 200, "OK", []byte(natOfferSDP(udpPort(moved3), "172.16.4.4")))
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.AppendHeader(&sip.ContactHeader{Address: r.phone.contactURI("1001")})
		_ = tx.Respond(res)
	})
	if res := r.switchUpdate(t, 2, sdpWith(r.h.fs.rtpPort, "sendrecv")); res.StatusCode != 200 {
		t.Fatalf("switch UPDATE: got %d, want 200", res.StatusCode)
	}
	awaitTarget(t, d, lo(udpPort(moved3)))
	r.end(t)
}

// Delayed offer: the phone's answer in the ACK of an offerless INVITE, and
// in the ACK of an offerless re-INVITE, is pinned too.
func TestClientDelayedOfferSeedPinned(t *testing.T) {
	t.Run("initial INVITE", func(t *testing.T) {
		h := startHarnessStrict(t, false, false)
		h.fs.setInviteHook(offerIn200(h.fs, "uas-pin-1", sdpWith(h.fs.rtpPort, "sendrecv")))
		phone := newUDPClient(t)
		auditRegisterPhone(t, h, phone, "1001")
		phoneRTP := listenRTP(t, freePort(t))
		fsRTP := listenRTP(t, h.fs.rtpPort)
		invite := phone.buildInvite("1001", "2002", "example.com", "")
		call := phoneUAC(t, h, phone, invite)
		res := call.final200(t)
		d := waitForDialog(t, h, fsip.CallID(invite))
		phoneAck(t, h, phone, invite, res, natOfferSDP(udpPort(phoneRTP), "10.77.0.10"))
		awaitTarget(t, d, lo(udpPort(phoneRTP)))
		if !relayReaches(t, fsRTP, loopback(d.session().privatePort), phoneRTP, rtpPacket(0, 420, 160)) {
			t.Error("early media never reached the client at its signalling IP")
		}
		if r := phone.do(t, buildBye(phone, invite, res), h.publicUDP); r.StatusCode != 200 {
			t.Errorf("BYE: %d", r.StatusCode)
		}
		waitForRelease(t, h)
	})
	t.Run("re-INVITE", func(t *testing.T) {
		r := startUpdRigOn(t, startHarnessStrict(t, false, false), true)
		d := waitForDialog(t, r.h, fsip.CallID(r.invite))
		fsMoved := listenRTP(t, freePort(t))
		phoneMoved := listenRTP(t, freePort(t))
		req, res := offerlessReInvite(t, r, udpPort(fsMoved))
		if res.StatusCode != 200 {
			t.Fatalf("re-INVITE: got %d, want 200", res.StatusCode)
		}
		phoneAck(t, r.h, r.phone, req, res, natOfferSDP(udpPort(phoneMoved), "192.168.1.5"))
		awaitTarget(t, d, lo(udpPort(phoneMoved)))
		if !relayReaches(t, fsMoved, loopback(r.privPort), phoneMoved, rtpPacket(0, 421, 160)) {
			t.Error("switch -> phone audio at the pinned address never arrived")
		}
		r.end(t)
	})
}

// A registered client as the callee: its answer (with an offer, in an
// offerless INVITE's 2xx) cannot steer the media either.
func TestClientCalleeSeedPinned(t *testing.T) {
	for _, offerless := range []bool{false, true} {
		t.Run(fmt.Sprintf("offerless=%v", offerless), func(t *testing.T) {
			h := startHarnessStrict(t, false, false)
			phone := newUDPClient(t)
			ruri := auditRegisterPhone(t, h, phone, "1001")
			phoneRTP := listenRTP(t, freePort(t))
			fsRTP := listenRTP(t, h.fs.rtpPort)
			phone.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
				if req.Method != sip.INVITE {
					_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
					return
				}
				res := sip.NewResponseFromRequest(req, 200, "OK", []byte(natOfferSDP(udpPort(phoneRTP), "10.77.0.10")))
				res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
				res.AppendHeader(&sip.ContactHeader{Address: phone.contactURI("1001")})
				res.To().Params.Add("tag", sip.GenerateTagN(12))
				_ = tx.Respond(res)
			})
			body := sdpWith(h.fs.rtpPort, "sendrecv")
			if offerless {
				body = ""
			}
			req := h.fs.callRequest(ruri, h.privateSIP, body)
			call := startUAC(t, h.fs.cli, req)
			res := call.final200(t)
			d := waitForDialog(t, h, fsip.CallID(req))
			if offerless {
				switchAck(t, h.fs, req, res, sdpWith(h.fs.rtpPort, "sendrecv"))
			} else {
				switchAck(t, h.fs, req, res, "")
			}
			awaitTarget(t, d, lo(udpPort(phoneRTP)))
			if !relayReaches(t, fsRTP, loopback(d.session().privatePort), phoneRTP, rtpPacket(0, 430, 160)) {
				t.Error("switch -> client early media never arrived at the signalling IP")
			}
			if bye := h.fs.uacBye(t, res); bye.StatusCode != 200 {
				t.Errorf("BYE: %d", bye.StatusCode)
			}
			waitForRelease(t, h)
		})
	}
}

// useProductionDestPolicy swaps the rig's public media pool for one with
// the policy a production plane gets (public.ip 203.0.113.7 on a 1:1 NAT
// host bound to 172.31.0.9, private.ip 10.77.0.2), still bound to
// loopback so the tests can run. The harness itself is a lab, whose
// policy lets private addresses through.
func useProductionDestPolicy(srv *Server) {
	pol := publicDestPolicy(netip.MustParseAddr("172.31.0.9"), &topology{
		publicMediaIP:  netip.MustParseAddr("203.0.113.7"),
		privateMediaIP: netip.MustParseAddr("10.77.0.2"),
	})
	r := srv.boot.RTP
	srv.pubPool = media.NewPlanePool("public", func() media.PlaneParams {
		return media.PlaneParams{
			MinPort: r.Min, MaxPort: r.Max,
			BindIP:        netip.MustParseAddr("127.0.0.1"),
			Timeout:       time.Minute,
			AllowLoopback: true,
			Dest:          pol,
		}
	})
}

// carrierMediaCases: what a carrier SDP's c= may steer, on a production
// plane. want is whether the address is seeded as the early-media target.
var carrierMediaCases = []struct {
	ip   string
	want bool
}{
	{"198.51.100.20", true}, // a media server that is not the signalling IP
	{"10.77.0.10", false},
	{"192.168.1.5", false},
	{"172.16.4.4", false},
	{"100.64.0.5", false},  // CGNAT
	{"203.0.113.7", false}, // public.ip
	{"172.31.0.9", false},  // public.bind
	{"10.77.0.2", false},   // private.ip
}

// A carrier calling in keeps its SDP address when it is a public one that
// differs from its signalling IP, and gets nothing sent to a private,
// CGNAT or FreeSBC address before its first packet.
func TestCarrierInboundOfferSeedClamped(t *testing.T) {
	phone := newUDPClient(t) // the carrier's gateway, 127.0.0.1
	rig := startCarrierRig(t, fmt.Sprintf("alpha: 127.0.0.1:%d", portOf(phone.local)), "", useProductionDestPolicy)
	answerWithEcho(rig.cs)
	for _, c := range carrierMediaCases {
		t.Run(c.ip, func(t *testing.T) {
			port := freePort(t)
			invite := phone.buildInvite("+442071234567", "+15551230000", "example.com", natOfferSDP(port, c.ip))
			res := phone.do(t, invite, rig.publicUDP)
			if res.StatusCode != 200 {
				t.Fatalf("carrier INVITE: got %d, want 200", res.StatusCode)
			}
			sendAck(t, phone, invite, res, rig.publicUDP)
			d := waitForDialog(t, rig.harness, fsip.CallID(invite))
			if d.carrierName() != "alpha" {
				t.Fatalf("carrier = %q, want alpha", d.carrierName())
			}
			var want netip.AddrPort
			if c.want {
				want = netip.AddrPortFrom(netip.MustParseAddr(c.ip), uint16(port))
			}
			awaitTarget(t, d, want)
			if r := phone.do(t, buildBye(phone, invite, res), rig.publicUDP); r.StatusCode != 200 {
				t.Errorf("BYE: %d", r.StatusCode)
			}
		})
	}
}

// A carrier answering the switch's call is clamped the same way.
func TestCarrierOutboundAnswerSeedClamped(t *testing.T) {
	cport := freePort(t)
	carrier := startFakeSwitch(t, fmt.Sprintf("127.0.0.1:%d", cport))
	rig := startCarrierRig(t, fmt.Sprintf("alpha: 127.0.0.1:%d", cport), "", useProductionDestPolicy)
	rig.upstreams["carrier"] = carrier
	o := &outboundRig{carrierRig: rig, carrier: carrier, cport: cport}
	for i, c := range carrierMediaCases {
		t.Run(c.ip, func(t *testing.T) {
			o.carrier.setInviteHook(offerIn200(o.carrier, fmt.Sprintf("car-pin-%d", i),
				ipv4Offer(sdpWith(o.carrier.rtpPort, "sendrecv"), c.ip)))
			req := o.fs.callRequest(o.ruri("+442071234567"), o.privateSIP, sdpWith(o.fs.rtpPort, "sendrecv"))
			call := startUAC(t, o.fs.cli, req)
			res := call.final200(t)
			switchAck(t, o.fs, req, res, "")
			d := waitForDialog(t, o.harness, fsip.CallID(req))
			var want netip.AddrPort
			if c.want {
				want = netip.AddrPortFrom(netip.MustParseAddr(c.ip), uint16(o.carrier.rtpPort))
			}
			awaitTarget(t, d, want)
			if bye := o.fs.uacBye(t, res); bye.StatusCode != 200 {
				t.Errorf("BYE: %d", bye.StatusCode)
			}
		})
	}
}

// The private classes pass on a plane whose ADVERTISED address is itself
// private (a lab), never because public.bind is: a 1:1 NAT host binds a
// private address behind a public public.ip. The private plane has no
// policy at all.
func TestPublicDestPolicyConstruction(t *testing.T) {
	cases := []struct {
		name          string
		bind, pub     string
		allowPrivate  bool
		ownRefused    []string
		ownNotRefused []string
	}{
		{"production", "203.0.113.7", "203.0.113.7", false, []string{"203.0.113.7", "10.77.0.2", "10.0.0.5"}, nil},
		{"1:1 NAT keeps the protection", "172.31.0.9", "203.0.113.7", false, []string{"172.31.0.9", "203.0.113.7", "10.77.0.2"}, nil},
		{"lab on RFC 1918", "10.0.0.5", "10.0.0.5", true, nil, []string{"10.0.0.5", "10.77.0.2"}},
		{"lab on CGNAT", "100.64.0.5", "100.64.0.5", true, nil, []string{"100.64.0.5", "10.77.0.2"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pol := publicDestPolicy(netip.MustParseAddr(c.bind), &topology{
				publicMediaIP:  netip.MustParseAddr(c.pub),
				privateMediaIP: netip.MustParseAddr("10.77.0.2"),
			})
			if !pol.Restrict || pol.AllowPrivate != c.allowPrivate {
				t.Fatalf("policy = %+v, want Restrict and AllowPrivate=%v", pol, c.allowPrivate)
			}
			// The decision itself is media's; exercise it through a seed.
			for _, ip := range c.ownRefused {
				if !seedRefused(t, pol, ip) {
					t.Errorf("%s is seeded, want refused", ip)
				}
			}
			for _, ip := range c.ownNotRefused {
				if seedRefused(t, pol, ip) {
					t.Errorf("%s is refused, want seeded", ip)
				}
			}
		})
	}
}

// seedRefused reports whether a side of a pool with pol sends nowhere
// after being seeded with ip.
func seedRefused(t *testing.T, pol media.DestPolicy, ip string) bool {
	t.Helper()
	port := nextMediaBase(t)
	pool := media.NewPlanePool("public", func() media.PlaneParams {
		return media.PlaneParams{MinPort: uint16(port), MaxPort: uint16(port + 9), BindIP: netip.MustParseAddr("127.0.0.1"),
			Timeout: time.Minute, AllowLoopback: true, Dest: pol}
	})
	s, err := media.AllocateAcross(pool, pool, media.SessionConfig{Latch: [2]media.LatchMode{media.LatchLoose, media.LatchStrict}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetRemote(media.SideA, netip.AddrPortFrom(netip.MustParseAddr(ip), 4000))
	return !s.SendTarget(media.SideA).IsValid()
}
