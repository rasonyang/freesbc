package edge

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// The "invite failed" line and freesbc_edge_invite_failures_total (issue
// #335): every out-of-dialog INVITE that ends without a confirmed dialog is
// reported once, with the far end's own status line, over real loopback
// sockets.
//
// Timing-based over real UDP loopback: re-run once before treating a flake
// as failure.

// failedLines are the "invite failed" records, in order.
func failedLines(rec *logRecorder) []recordedLog {
	var out []recordedLog
	for _, r := range rec.snapshot() {
		if r.msg == "invite failed" {
			out = append(out, r)
		}
	}
	return out
}

// waitFailedLine waits for the first "invite failed" record.
func waitFailedLine(t *testing.T, rec *logRecorder) recordedLog {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if l := failedLines(rec); len(l) > 0 {
			return l[0]
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(`no "invite failed" line`)
	return recordedLog{}
}

// assertOneFailure checks that exactly one INVITE was reported, after a
// settle time long enough for a duplicate to show, and that only counter
// key moved, by one.
func assertOneFailure(t *testing.T, h *harness, rec *logRecorder, key string) recordedLog {
	t.Helper()
	line := waitFailedLine(t, rec)
	time.Sleep(400 * time.Millisecond)
	if n := len(failedLines(rec)); n != 1 {
		t.Errorf(`"invite failed" logged %d times, want 1`, n)
	}
	for k, n := range h.srv.metrics.Snapshot().InviteFailures {
		want := uint64(0)
		if k == key {
			want = 1
		}
		if n != want {
			t.Errorf("invite_failures{%s} = %d, want %d", k, n, want)
		}
	}
	return line
}

func assertFailAttrs(t *testing.T, line recordedLog, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if got := line.attrs[k]; got != v {
			t.Errorf("invite failed %s = %q, want %q", k, got, v)
		}
	}
	if line.attrs["duration"] == "" {
		t.Error("invite failed has no duration")
	}
	if line.attrs["sip_call_id"] == "" {
		t.Error("invite failed has no sip_call_id")
	}
}

// startCarrierRigRec is startCarrierRig with the proxy's log recorded.
func startCarrierRigRec(t *testing.T, carriers string) (*carrierRig, *logRecorder) {
	t.Helper()
	pubUDP, priv, up, cp := freePort(t), freePort(t), freePort(t), freePort(t)
	mediaBase := nextMediaBase(t)
	yaml := harnessYAML(t, []string{fmt.Sprintf("127.0.0.1:%d", up)}, pubUDP, 0, 0, mediaBase, "")
	yaml = strings.Replace(yaml, "edge:\n",
		fmt.Sprintf("edge:\n  switch_carrier_port: %d\n  carriers: {%s}\n", cp, carriers), 1)
	rec := newLogRecorder()
	h := newHarnessLog(t, yaml, priv, rec)
	h.upstream = fmt.Sprintf("127.0.0.1:%d", up)
	h.fs = startFakeSwitch(t, h.upstream)
	cs := startFakeSwitch(t, fmt.Sprintf("127.0.0.1:%d", cp))
	h.upstreams["carrier-port"] = cs
	h.run()
	return &carrierRig{harness: h, cs: cs}, rec
}

// startOutboundRigRec is startOutboundRig with the proxy's log recorded.
func startOutboundRigRec(t *testing.T) (*outboundRig, *logRecorder) {
	t.Helper()
	cport := freePort(t)
	carrier := startFakeSwitch(t, fmt.Sprintf("127.0.0.1:%d", cport))
	rig, rec := startCarrierRigRec(t, fmt.Sprintf("alpha: 127.0.0.1:%d", cport))
	rig.upstreams["carrier"] = carrier
	return &outboundRig{carrierRig: rig, carrier: carrier, cport: cport}, rec
}

// startStrictRec is startHarnessStrict with the proxy's log recorded: a
// client is admitted only through its registration.
func startStrictRec(t *testing.T) (*harness, *logRecorder) {
	t.Helper()
	pubUDP, priv, up := freePort(t), freePort(t), freePort(t)
	rec := newLogRecorder()
	h := newHarnessLog(t, harnessYAML(t, []string{fmt.Sprintf("127.0.0.1:%d", up)},
		pubUDP, 0, 0, nextMediaBase(t), ""), priv, rec)
	h.upstream = fmt.Sprintf("127.0.0.1:%d", up)
	h.fs = startFakeSwitch(t, h.upstream)
	h.run()
	return h, rec
}

// refuseWith makes a fake far end answer every INVITE with code, a Reason
// header, and the reason phrase phrase.
func refuseWith(f *fakeSwitch, code int, phrase, reason string) {
	f.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		res := sip.NewResponseFromRequest(req, code, phrase, nil)
		res.To().Params.Add("tag", sip.GenerateTagN(12))
		for _, r := range strings.Split(reason, "\n") {
			res.AppendHeader(sip.NewHeader("Reason", r))
		}
		_ = tx.Respond(res)
		return true
	})
}

// The switch's call to a carrier is answered 480: one Info line names the
// carrier, the code, the carrier's own phrase and Reason header, and a
// duration, and the counter moves once.
func TestInviteFailedCarrierOutbound480(t *testing.T) {
	o, rec := startOutboundRigRec(t)
	refuseWith(o.carrier, 480, "Gateway Busy", `Q.850;cause=19;text="no answer"`)

	res := o.fs.call(t, o.ruri("+442071234567"), o.privateSIP, phoneOfferSDP(o.fs.rtpPort))
	if res.StatusCode != 480 {
		t.Fatalf("got %d, want the carrier's 480", res.StatusCode)
	}
	line := assertOneFailure(t, o.harness, rec, "carrier/outbound/4xx")
	if line.level != slog.LevelInfo {
		t.Errorf("logged at %s, want INFO", line.level)
	}
	assertFailAttrs(t, line, map[string]string{
		"direction": "private->public", "leg": "carrier", "carrier": "alpha", "code": "480",
		"reason_phrase": "Gateway Busy", "sip_reason": `Q.850;cause=19;text="no answer"`,
		"source": "far_end", "class": "4xx",
	})
	waitForReleaseEventually(t, o.harness)
}

// One Reason header per protocol (RFC 3326): both reach the log.
func TestInviteFailedKeepsEveryReasonHeader(t *testing.T) {
	o, rec := startOutboundRigRec(t)
	refuseWith(o.carrier, 486, "Busy", "SIP;cause=486;text=\"Busy Here\"\nQ.850;cause=17")
	if res := o.fs.call(t, o.ruri("+442071234567"), o.privateSIP, phoneOfferSDP(o.fs.rtpPort)); res.StatusCode != 486 {
		t.Fatalf("got %d, want 486", res.StatusCode)
	}
	line := waitFailedLine(t, rec)
	if got, want := line.attrs["sip_reason"], `SIP;cause=486;text="Busy Here", Q.850;cause=17`; got != want {
		t.Errorf("sip_reason = %q, want %q", got, want)
	}
}

// A far end's text is bounded in the log.
func TestInviteFailedTextIsBounded(t *testing.T) {
	o, rec := startOutboundRigRec(t)
	refuseWith(o.carrier, 486, "Busy", "SIP;cause=486;text="+strings.Repeat("x", 2000))
	if res := o.fs.call(t, o.ruri("+442071234567"), o.privateSIP, phoneOfferSDP(o.fs.rtpPort)); res.StatusCode != 486 {
		t.Fatalf("got %d, want 486", res.StatusCode)
	}
	line := waitFailedLine(t, rec)
	if n := len(line.attrs["sip_reason"]); n == 0 || n > maxFailText {
		t.Errorf("sip_reason is %d bytes, want 1..%d", n, maxFailText)
	}
}

// A carrier that rings and then goes silent: the INVITE's budget ends it,
// the switch gets 408 from FreeSBC, and one Warn line says it was a timeout
// (the pump returning unfinished and giveUp answering do not both report).
func TestInviteFailedCarrierTimeout(t *testing.T) {
	o, rec := startOutboundRigRec(t)
	o.srv.inviteBackstop.Store(int64(700 * time.Millisecond))
	o.carrier.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 180, "Ringing", nil))
		return o.carrier.silentHook()(req, tx)
	})

	res := o.fs.call(t, o.ruri("+442071234567"), o.privateSIP, phoneOfferSDP(o.fs.rtpPort))
	if res.StatusCode != 408 {
		t.Fatalf("got %d, want 408", res.StatusCode)
	}
	line := assertOneFailure(t, o.harness, rec, "carrier/outbound/timeout")
	if line.level != slog.LevelWarn {
		t.Errorf("logged at %s, want WARN", line.level)
	}
	assertFailAttrs(t, line, map[string]string{
		"direction": "private->public", "leg": "carrier", "carrier": "alpha", "code": "408",
		"reason_phrase": "Request Timeout", "source": "timeout", "class": "timeout",
	})
}

// A carrier that sends nothing at all, not even a 100 or 180, is the same
// timeout.
func TestInviteFailedCarrierSilent(t *testing.T) {
	o, rec := startOutboundRigRec(t)
	o.srv.inviteBackstop.Store(int64(700 * time.Millisecond))
	o.carrier.setInviteHook(o.carrier.silentHook())

	res := o.fs.call(t, o.ruri("+442071234567"), o.privateSIP, phoneOfferSDP(o.fs.rtpPort))
	if res.StatusCode != 408 {
		t.Fatalf("got %d, want 408", res.StatusCode)
	}
	line := assertOneFailure(t, o.harness, rec, "carrier/outbound/timeout")
	if line.level != slog.LevelWarn {
		t.Errorf("logged at %s, want WARN", line.level)
	}
	assertFailAttrs(t, line, map[string]string{
		"leg": "carrier", "carrier": "alpha", "code": "408", "source": "timeout", "class": "timeout",
	})
}

// A transport failure: the switch node cannot be reached (the send fails at
// once), so giveUp's default branch answers 503 for a far end that never
// spoke.
func TestInviteFailedTransportFailure(t *testing.T) {
	pubUDP, priv := freePort(t), freePort(t)
	rec := newLogRecorder()
	h := newHarnessLog(t, harnessYAML(t, []string{"192.0.2.1:5060"}, pubUDP, 0, 0, nextMediaBase(t), harnessCarrierSources), priv, rec)
	h.run()
	phone := newUDPClient(t)
	res := phone.do(t, phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30905)), h.publicUDP)
	if res.StatusCode != 503 {
		t.Fatalf("got %d, want 503", res.StatusCode)
	}
	// harnessCarrierSources admits the phone as a carrier source ("unknown").
	line := assertOneFailure(t, h, rec, "switch/inbound/timeout")
	if line.level != slog.LevelWarn {
		t.Errorf("logged at %s, want WARN", line.level)
	}
	assertFailAttrs(t, line, map[string]string{
		"leg": "switch", "code": "503", "reason_phrase": "Service Unavailable", "source": "timeout", "class": "timeout",
	})
}

// The report is made once per INVITE, and a code that is no failure does not
// use it up.
func TestInviteFailedReportsOnce(t *testing.T) {
	rec := newLogRecorder()
	srv := &Server{log: slog.New(rec), metrics: NewMetrics()}
	req := sip.NewRequest(sip.INVITE, sip.Uri{User: "x", Host: "example.com"})
	callID := sip.CallIDHeader("once-1")
	req.AppendHeader(&callID)
	fc := newInviteFlow(req, legCarrier, false, "alpha")

	srv.inviteFailed(fc, 302, "Moved", "", failFarEnd) // not a failure
	if n := len(failedLines(rec)); n != 0 {
		t.Fatalf("a 302 logged %d lines, want 0", n)
	}
	srv.inviteFailed(fc, 480, "Unavailable", "", failFarEnd)
	srv.inviteFailed(fc, 487, "Request Terminated", "", failCancel)
	srv.inviteFailed(fc, 503, "Service Unavailable", "", failTimeout)
	lines := failedLines(rec)
	if len(lines) != 1 || lines[0].attrs["code"] != "480" {
		t.Fatalf("lines = %v, want only the first (480)", lines)
	}
	total := uint64(0)
	for _, n := range srv.metrics.Snapshot().InviteFailures {
		total += n
	}
	if total != 1 {
		t.Errorf("invite_failures total = %d, want 1", total)
	}
}

// A carrier's call to the switch refused by the switch: leg switch, inbound,
// carrier named as X-FreeSBC-Carrier names it.
func TestInviteFailedCarrierInbound(t *testing.T) {
	phone := newUDPClient(t) // stands in for the carrier's gateway
	rig, rec := startCarrierRigRec(t, fmt.Sprintf("alpha: 127.0.0.1:%d", portOf(phone.local)))
	refuseWith(rig.cs, 503, "Service Unavailable", "SIP;cause=503")

	invite := phone.buildInvite("+442071234567", "+15551230000", "example.com", phoneOfferSDP(30901))
	if res := phone.do(t, invite, rig.publicUDP); res.StatusCode != 503 {
		t.Fatalf("got %d, want the switch's 503", res.StatusCode)
	}
	line := assertOneFailure(t, rig.harness, rec, "switch/inbound/5xx")
	if line.level != slog.LevelInfo {
		t.Errorf("logged at %s, want INFO", line.level)
	}
	assertFailAttrs(t, line, map[string]string{
		"direction": "public->private", "leg": "switch", "carrier": "alpha", "code": "503",
		"sip_reason": "SIP;cause=503", "source": "far_end", "class": "5xx",
	})
}

// The switch's call to a registered client refused by the client, and a
// registered client's call refused by the switch: no carrier name on
// either.
func TestInviteFailedClientLegs(t *testing.T) {
	t.Run("switch to client", func(t *testing.T) {
		h, rec := startStrictRec(t)
		phone := newUDPClient(t)
		ruri := auditRegisterPhone(t, h, phone, "1001")
		phone.setAnswer(func(req *sip.Request, tx sip.ServerTransaction) {
			res := sip.NewResponseFromRequest(req, 486, "Busy Here", nil)
			res.To().Params.Add("tag", sip.GenerateTagN(12))
			_ = tx.Respond(res)
		})
		if res := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort)); res.StatusCode != 486 {
			t.Fatalf("got %d, want the client's 486", res.StatusCode)
		}
		line := assertOneFailure(t, h, rec, "client/outbound/4xx")
		assertFailAttrs(t, line, map[string]string{
			"direction": "private->public", "leg": "client", "carrier": "", "code": "486",
			"reason_phrase": "Busy Here", "source": "far_end", "class": "4xx",
		})
		if line.level != slog.LevelInfo {
			t.Errorf("logged at %s, want INFO", line.level)
		}
	})
	t.Run("client to switch", func(t *testing.T) {
		h, rec := startStrictRec(t)
		phone := newUDPClient(t)
		auditRegisterPhone(t, h, phone, "1001")
		refuseWith(h.fs, 603, "Decline", "SIP;cause=603")
		invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30903))
		if res := phone.do(t, invite, h.publicUDP); res.StatusCode != 603 {
			t.Fatalf("got %d, want 603", res.StatusCode)
		}
		line := assertOneFailure(t, h, rec, "switch/inbound/6xx")
		assertFailAttrs(t, line, map[string]string{
			"direction": "public->private", "leg": "switch", "carrier": "", "code": "603",
			"source": "far_end", "class": "6xx",
		})
	})
	t.Run("no registration", func(t *testing.T) {
		// A final FreeSBC generates itself: source edge, from its code.
		h, rec := startStrictRec(t)
		ruri := sip.Uri{User: "1001", Host: "127.0.0.1", UriParams: sip.NewParams()}
		ruri.UriParams.Add("fsbc", "no-such-token")
		if res := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort)); res.StatusCode != 404 {
			t.Fatalf("got %d, want 404", res.StatusCode)
		}
		line := assertOneFailure(t, h, rec, "client/outbound/4xx")
		assertFailAttrs(t, line, map[string]string{"code": "404", "source": "edge", "leg": "client"})
	})
}

// A ringing call the switch hangs up with CANCEL is a normal end: no Info
// line, nothing counted, and the far end's 487 that follows is not a
// failure.
func TestInviteFailedCancelIsNotAFailure(t *testing.T) {
	o, rec := startOutboundRigRec(t)
	o.carrier.setInviteHook(o.carrier.silentHook())
	req, final := o.fs.callAsync(t, o.ruri("+442071234567"), o.privateSIP, phoneOfferSDP(o.fs.rtpPort))
	if got := o.carrier.waitFor(sip.INVITE, 1, 3*time.Second); len(got) != 1 {
		t.Fatalf("carrier saw %d INVITEs, want 1", len(got))
	}
	cancel := buildCancelFor(req)
	cancel.SetTransport("UDP")
	cancel.SetDestination(o.privateSIP)
	cancel.Laddr = req.Laddr
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	tx, err := o.fs.cli.TransactionRequest(ctx, cancel)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Terminate()
	select {
	case res := <-tx.Responses():
		if res.StatusCode != 200 {
			t.Fatalf("CANCEL: got %d, want 200", res.StatusCode)
		}
	case <-ctx.Done():
		t.Fatal("CANCEL got no response")
	}
	select {
	case res := <-final:
		if res == nil || res.StatusCode != 487 {
			t.Fatalf("INVITE final after CANCEL = %v, want 487", res)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no final response after CANCEL")
	}
	waitForReleaseEventually(t, o.harness)
	time.Sleep(400 * time.Millisecond)

	lines := failedLines(rec)
	if len(lines) != 1 {
		t.Fatalf(`"invite failed" logged %d times, want 1 (Debug, source=cancel)`, len(lines))
	}
	if lines[0].level != slog.LevelDebug || lines[0].attrs["source"] != "cancel" || lines[0].attrs["code"] != "487" {
		t.Errorf("cancel line = %v at %s, want Debug source=cancel code=487", lines[0].attrs, lines[0].level)
	}
	for k, n := range o.srv.metrics.Snapshot().InviteFailures {
		if n != 0 {
			t.Errorf("invite_failures{%s} = %d after a CANCEL, want 0", k, n)
		}
	}
}

// Every combination of the counter exists from the start, at zero.
func TestInviteFailuresStartAtZero(t *testing.T) {
	snap := NewMetrics().Snapshot()
	if len(snap.InviteFailures) != int(numFailLegs)*int(numFailDirs)*int(numFailClasses) {
		t.Fatalf("%d invite_failures label sets, want %d", len(snap.InviteFailures), int(numFailLegs)*int(numFailDirs)*int(numFailClasses))
	}
	for l := failLeg(0); l < numFailLegs; l++ {
		for d := 0; d < int(numFailDirs); d++ {
			for c := failClass(0); c < numFailClasses; c++ {
				key := failLegLabels[l] + "/" + failDirLabels[d] + "/" + failClassLabels[c]
				if n, ok := snap.InviteFailures[key]; !ok || n != 0 || strings.Contains(key, "//") || strings.HasPrefix(key, "/") {
					t.Errorf("invite_failures{%s} = %d, present %v; want 0, present", key, n, ok)
				}
			}
		}
	}
}
