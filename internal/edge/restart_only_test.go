package edge

import (
	"net"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/config"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// audit: P2-CFG-002
// The PSTN gateways are topology, built once at startup. A reload that
// removes sip.pstn leaves them in place, and must not zero the attempt
// budget they run under: a bridged call still reaches the gateway and is
// answered, instead of being cancelled the instant it is dialed.
func TestReloadRemovingPSTNKeepsAttemptBudget(t *testing.T) {
	h, carrier := startHarnessPSTN(t)
	carrier.setInviteHook(carrier.answerHook(200, true))

	auditReplaceConfig(h, func(c *config.Config) { c.SIP.Pstn = config.PstnConfig{} })

	res := bridgePSTNCall(t, h, "12345")
	if got := len(carrier.waitFor(sip.INVITE, 1, 2*time.Second)); got != 1 || res.StatusCode != 200 {
		t.Fatalf("after a reload removing sip.pstn: FreeSWITCH got %d and the gateway saw %d INVITE(s); want 200 and 1",
			res.StatusCode, got)
	}
	hangupPSTN(t, h, res)
}

// audit: P2-EDG-025
// The public media plane's advertised address is topology, fixed at
// startup, so its bind address must be too. After a reload that moves
// rtp.public.bind_ip, the media port the phone is told to send to must
// still be bound on the advertised address.
func TestReloadRTPBindIPKeepsAdvertisedSocket(t *testing.T) {
	h := startHarness(t, false)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, nil, nil))
	settle()

	auditReplaceConfig(h, func(c *config.Config) { c.RTP.Public.BindIP = "127.0.0.3" })

	phone := newUDPClient(t)
	invite, res, _ := auditPhoneCall(t, h, phone)
	waitForDialog(t, h, fsip.CallID(invite))
	answer, err := parseLabSDP(res.Body())
	if err != nil {
		t.Fatalf("answer unparseable: %v\n%s", err, res.Body())
	}
	// The SBC's socket must hold the advertised address:port; if the
	// reload moved the bind, this address is free and the phone's RTP
	// goes nowhere.
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: answer.Audio.Port})
	if err == nil {
		_ = probe.Close()
		t.Errorf("SDP advertises 127.0.0.1:%d, but nothing is bound there after reloading rtp.public.bind_ip",
			answer.Audio.Port)
	}
	if r := phone.do(t, buildBye(phone, invite, res), h.publicUDP); r.StatusCode != 200 {
		t.Errorf("BYE: %d", r.StatusCode)
	}
}

// audit: P2-APP-005
// The admin call list and the active-call count describe the same set: a
// confirmed edge dialog is listed, not only counted.
func TestCallsListsWhatActiveCallsCounts(t *testing.T) {
	h := startHarness(t, false)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, nil, nil))
	settle()

	phone := newUDPClient(t)
	invite, res, _ := auditPhoneCall(t, h, phone)
	waitForDialog(t, h, fsip.CallID(invite))

	calls := h.srv.Calls()
	if n := h.srv.ActiveCalls(); n != 1 || len(calls) != 1 {
		t.Fatalf("ActiveCalls = %d, Calls lists %d; want 1 and 1", n, len(calls))
	}
	c := calls[0]
	if c.CallID != fsip.CallID(invite) || c.From != "edge:public" || c.To != "edge:private" || c.StartUnixNano == 0 {
		t.Errorf("call record = %+v, want the phone's Call-ID, edge:public → edge:private and a start time", c)
	}
	if r := phone.do(t, buildBye(phone, invite, res), h.publicUDP); r.StatusCode != 200 {
		t.Errorf("BYE: %d", r.StatusCode)
	}
	waitForRelease(t, h)
	if n := len(h.srv.Calls()); n != 0 {
		t.Errorf("after BYE Calls lists %d, want 0", n)
	}
}
