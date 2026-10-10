package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// wsConn is a minimal RFC 6455 client carrying SIP (subprotocol "sip", one
// message per text frame, RFC 7118). It is small on purpose: the load client
// needs only the handshake, masked text frames out, and text/ping/close in.
type wsConn struct {
	c     net.Conn
	br    *bufio.Reader
	wmu   sync.Mutex
	local string // local IP the connection left from
}

func dialWS(rawURL string, insecure bool, timeout time.Duration) (*wsConn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	host := u.Host
	d := net.Dialer{Timeout: timeout}
	var c net.Conn
	switch u.Scheme {
	case "ws":
		if u.Port() == "" {
			host = net.JoinHostPort(u.Hostname(), "80")
		}
		c, err = d.Dial("tcp", host)
	case "wss":
		if u.Port() == "" {
			host = net.JoinHostPort(u.Hostname(), "443")
		}
		cfg := &tls.Config{InsecureSkipVerify: insecure, ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}
		c, err = tls.DialWithDialer(&d, "tcp", host, cfg)
	default:
		return nil, fmt.Errorf("unsupported scheme %q (want ws or wss)", u.Scheme)
	}
	if err != nil {
		return nil, err
	}
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	path := u.RequestURI()
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: sip\r\n\r\n",
		path, u.Host, base64.StdEncoding.EncodeToString(key))
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(c, req); err != nil {
		_ = c.Close()
		return nil, err
	}
	br := bufio.NewReaderSize(c, 64<<10)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("websocket upgrade: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = c.Close()
		return nil, fmt.Errorf("websocket upgrade: %s", resp.Status)
	}
	_ = c.SetDeadline(time.Time{})
	w := &wsConn{c: c, br: br}
	if a, ok := c.LocalAddr().(*net.TCPAddr); ok {
		w.local = a.IP.String()
	}
	return w, nil
}

func (w *wsConn) Close() error { return w.c.Close() }

// writeFrame sends one masked frame.
func (w *wsConn) writeFrame(opcode byte, p []byte) error {
	hdr := make([]byte, 0, 14)
	hdr = append(hdr, 0x80|opcode)
	switch n := len(p); {
	case n < 126:
		hdr = append(hdr, 0x80|byte(n))
	case n < 1<<16:
		hdr = append(hdr, 0x80|126, 0, 0)
		binary.BigEndian.PutUint16(hdr[len(hdr)-2:], uint16(n))
	default:
		hdr = append(hdr, 0x80|127, 0, 0, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint64(hdr[len(hdr)-8:], uint64(n))
	}
	var mask [4]byte
	_, _ = rand.Read(mask[:])
	hdr = append(hdr, mask[:]...)
	buf := make([]byte, len(hdr)+len(p))
	copy(buf, hdr)
	for i, b := range p {
		buf[len(hdr)+i] = b ^ mask[i&3]
	}
	w.wmu.Lock()
	defer w.wmu.Unlock()
	_ = w.c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := w.c.Write(buf)
	return err
}

// Send writes one SIP message as a text frame.
func (w *wsConn) Send(msg string) error { return w.writeFrame(0x1, []byte(msg)) }

// Read returns the next data message, answering pings and failing on close.
func (w *wsConn) Read() ([]byte, error) {
	var msg []byte
	for {
		var h [2]byte
		if _, err := io.ReadFull(w.br, h[:]); err != nil {
			return nil, err
		}
		fin := h[0]&0x80 != 0
		op := h[0] & 0x0f
		n := uint64(h[1] & 0x7f)
		switch n {
		case 126:
			var b [2]byte
			if _, err := io.ReadFull(w.br, b[:]); err != nil {
				return nil, err
			}
			n = uint64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			if _, err := io.ReadFull(w.br, b[:]); err != nil {
				return nil, err
			}
			n = binary.BigEndian.Uint64(b[:])
		}
		if n > 1<<20 {
			return nil, errors.New("websocket frame too large")
		}
		var mask [4]byte
		masked := h[1]&0x80 != 0
		if masked {
			if _, err := io.ReadFull(w.br, mask[:]); err != nil {
				return nil, err
			}
		}
		p := make([]byte, n)
		if _, err := io.ReadFull(w.br, p); err != nil {
			return nil, err
		}
		if masked {
			for i := range p {
				p[i] ^= mask[i&3]
			}
		}
		switch op {
		case 0x8:
			return nil, io.EOF
		case 0x9:
			_ = w.writeFrame(0xA, p)
		case 0xA:
		case 0x0, 0x1, 0x2:
			msg = append(msg, p...)
			if fin {
				return msg, nil
			}
		}
	}
}
