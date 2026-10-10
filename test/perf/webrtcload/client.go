package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// wsClient is one WebSocket connection to FreeSBC carrying SIP for many users.
// A reader goroutine hands each incoming message to the waiter registered for
// its Call-ID.
type wsClient struct {
	ws    *wsConn
	proto string // WS or WSS
	via   string // sent-by host for Via

	mu      sync.Mutex
	waiters map[string]chan *sipMsg
}

func newWSClient(c config, u *url.URL) (*wsClient, error) {
	ws, err := dialWS(c.target, c.insecure, 10*time.Second)
	if err != nil {
		return nil, err
	}
	w := &wsClient{ws: ws, proto: strings.ToUpper(u.Scheme), waiters: map[string]chan *sipMsg{},
		via: randToken(6) + ".invalid"}
	go w.readLoop()
	return w, nil
}

func (w *wsClient) readLoop() {
	for {
		raw, err := w.ws.Read()
		if err != nil {
			w.mu.Lock()
			for id, ch := range w.waiters {
				close(ch)
				delete(w.waiters, id)
			}
			w.mu.Unlock()
			return
		}
		m, err := parseSIP(raw)
		if err != nil {
			continue
		}
		if m.status == 0 { // a request from the switch side (BYE, OPTIONS, NOTIFY): answer 200
			w.reply200(m)
			if m.method == "BYE" {
				w.deliver(m)
			}
			continue
		}
		w.deliver(m)
	}
}

func (w *wsClient) deliver(m *sipMsg) {
	w.mu.Lock()
	ch := w.waiters[m.callID()]
	w.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- m:
	default:
	}
}

func (w *wsClient) reply200(m *sipMsg) {
	var b strings.Builder
	b.WriteString("SIP/2.0 200 OK\r\n")
	for _, v := range m.hdr["via"] {
		b.WriteString("Via: " + v + "\r\n")
	}
	b.WriteString("From: " + m.first("from") + "\r\nTo: " + m.first("to") + "\r\n")
	b.WriteString("Call-ID: " + m.callID() + "\r\nCSeq: " + m.first("cseq") + "\r\nContent-Length: 0\r\n\r\n")
	_ = w.ws.Send(b.String())
}

func (w *wsClient) wait(callID string) chan *sipMsg {
	ch := make(chan *sipMsg, 16)
	w.mu.Lock()
	w.waiters[callID] = ch
	w.mu.Unlock()
	return ch
}

func (w *wsClient) forget(callID string) {
	w.mu.Lock()
	delete(w.waiters, callID)
	w.mu.Unlock()
}

// dlg is the client side of one SIP dialog or registration.
type dlg struct {
	user, domain string
	callID       string
	fromTag      string
	toTag        string
	toURI        string // To header URI
	target       string // Request-URI of in-dialog requests (remote target)
	routes       []string
	cseq         int
	authNC       int
}

func (w *wsClient) contact(user string) string {
	return fmt.Sprintf("<sip:%s@%s;transport=%s>", user, w.via, strings.ToLower(w.proto))
}

// build renders a request in d. extra headers are complete lines.
func (w *wsClient) build(d *dlg, method, ruri string, extra []string, body string) string {
	d.cseq++
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s SIP/2.0\r\n", method, ruri)
	fmt.Fprintf(&b, "Via: SIP/2.0/%s %s;branch=z9hG4bK%s\r\n", w.proto, w.via, randToken(8))
	b.WriteString("Max-Forwards: 70\r\n")
	for _, r := range d.routes {
		b.WriteString("Route: " + r + "\r\n")
	}
	to := "<" + d.toURI + ">"
	if d.toTag != "" {
		to += ";tag=" + d.toTag
	}
	fmt.Fprintf(&b, "From: <sip:%s@%s>;tag=%s\r\nTo: %s\r\nCall-ID: %s\r\nCSeq: %d %s\r\n",
		d.user, d.domain, d.fromTag, to, d.callID, d.cseq, method)
	for _, h := range extra {
		b.WriteString(h + "\r\n")
	}
	if body != "" {
		fmt.Fprintf(&b, "Content-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	} else {
		b.WriteString("Content-Length: 0\r\n\r\n")
	}
	return b.String()
}

var errTimeout = errors.New("timeout")

// final waits for a final response (>= 200) to the request with this CSeq
// method, skipping provisionals.
func final(ch chan *sipMsg, method string, d time.Duration) (*sipMsg, error) {
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		select {
		case m, ok := <-ch:
			if !ok {
				return nil, errors.New("connection closed")
			}
			if m.status == 0 || m.cseqMethod() != method || m.status < 200 {
				continue
			}
			return m, nil
		case <-t.C:
			return nil, errTimeout
		}
	}
}

// send sends one request and returns its final response, answering one
// digest challenge when a password is configured.
func (w *wsClient) send(c config, d *dlg, ch chan *sipMsg, method, ruri string, extra []string, body string, wait time.Duration) (*sipMsg, error) {
	if err := w.ws.Send(w.build(d, method, ruri, extra, body)); err != nil {
		return nil, err
	}
	res, err := final(ch, method, wait)
	if err != nil {
		return nil, err
	}
	if (res.status == 401 || res.status == 407) && c.password != "" {
		hn, an := "www-authenticate", "Authorization"
		if res.status == 407 {
			hn, an = "proxy-authenticate", "Proxy-Authorization"
		}
		ch2, ok := parseChallenge(res.first(hn))
		if !ok {
			return res, nil
		}
		d.authNC++
		auth := an + ": " + ch2.authorization(d.user, c.password, method, ruri, d.authNC)
		if method == "INVITE" { // ACK the 401/407 first, same branch-less ACK is enough for a proxy
			d.cseq-- // the ACK reuses the INVITE's CSeq number
			ack := w.build(d, "ACK", ruri, nil, "")
			_ = w.ws.Send(ack)
		}
		if err := w.ws.Send(w.build(d, method, ruri, append(extra, auth), body)); err != nil {
			return nil, err
		}
		return final(ch, method, wait)
	}
	return res, nil
}

// register REGISTERs user over this connection and returns the round trip.
func (w *wsClient) register(c config, user string) (time.Duration, error) {
	d := &dlg{user: user, domain: c.domain, callID: randToken(10) + "@webrtcload", fromTag: randToken(4),
		toURI: fmt.Sprintf("sip:%s@%s", user, c.domain)}
	ch := w.wait(d.callID)
	defer w.forget(d.callID)
	t0 := time.Now()
	res, err := w.send(c, d, ch, "REGISTER", "sip:"+c.domain,
		[]string{"Contact: " + w.contact(user), "Expires: 3600", "Supported: path, outbound, gruu"}, "", 10*time.Second)
	if err != nil {
		return 0, err
	}
	if res.status != 200 {
		return 0, fmt.Errorf("REGISTER answered %d", res.status)
	}
	return time.Since(t0), nil
}

// call places one WebRTC call as user and returns its measurements.
func (w *wsClient) call(ctx context.Context, c config, user string, loopback bool) (r result) {
	r.start = time.Now()
	r.user = user
	d := &dlg{user: user, domain: c.domain, callID: randToken(10) + "@webrtcload", fromTag: randToken(4),
		toURI: fmt.Sprintf("sip:%s@%s", c.number, c.domain)}
	r.callID = d.callID
	fail := func(kind string, err error) result {
		r.err = kind
		if err != nil && !errors.Is(err, errTimeout) {
			r.err = kind + ": " + shorten(err.Error())
		} else if err != nil {
			r.err = kind + ": timeout"
		}
		return r
	}

	lg, err := newLeg(loopback)
	if err != nil {
		return fail("ice gather", err)
	}
	closed := false
	defer func() {
		if !closed {
			lg.close()
		}
	}()
	ch := w.wait(d.callID)
	defer w.forget(d.callID)

	ruri := d.toURI
	t0 := time.Now()
	res, err := w.send(c, d, ch, "INVITE", ruri,
		[]string{"Contact: " + w.contact(user), "Supported: replaces, outbound, ice"}, lg.offerSDP(c.advertise), 15*time.Second)
	if err != nil {
		return fail("invite", err)
	}
	if res.status != 200 {
		return fail("invite", fmt.Errorf("answered %d", res.status))
	}
	r.setupMs = ms(time.Since(t0))
	d.toTag = res.toTag()
	d.routes = res.routeSet()
	if ct := res.contactURI(); ct != "" {
		d.target = ct
	} else {
		d.target = ruri
	}
	// ACK (CSeq of the INVITE).
	d.cseq--
	ackMsg := w.build(d, "ACK", d.target, nil, "")
	d.cseq++
	if err := w.ws.Send(ackMsg); err != nil {
		return fail("ack", err)
	}
	bye := func() {
		if m, err := w.send(c, d, ch, "BYE", d.target, nil, "", 5*time.Second); err == nil && m != nil {
			return
		}
	}

	ans, err := parseAnswer(res.body)
	if err != nil {
		bye()
		return fail("answer", err)
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := lg.connect(cctx, ans); err != nil {
		bye()
		kind := "media"
		if strings.HasPrefix(err.Error(), "ice") {
			kind = "ice"
		} else if strings.HasPrefix(err.Error(), "dtls") {
			kind = "dtls"
		}
		return fail(kind, err)
	}
	r.iceMs, r.dtlsMs = ms(lg.iceDur), ms(lg.dtlsDur)
	r.dtlsAt = time.Now()

	if c.noMedia {
		select {
		case <-time.After(c.hold):
		case <-ctx.Done():
		}
	} else {
		st := lg.exchange(ctx, c.hold)
		closed = true
		r.sent, r.recv, r.lostSeq, r.jitterMs = st.sent, st.recv, st.lostSeq, st.jitterMs
		r.rttP50, r.rttP99 = percentile(st.rtts, 50), percentile(st.rtts, 99)
		if st.recv == 0 {
			bye()
			return fail("media", errors.New("no echoed RTP received"))
		}
	}
	bye()
	return r
}

func shorten(s string) string {
	if len(s) > 80 {
		return s[:80]
	}
	return s
}
