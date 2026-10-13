package hep

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var fastTiming = &timing{
	dial:       2 * time.Second,
	write:      2 * time.Second,
	backoffMin: 5 * time.Millisecond,
	backoffMax: 40 * time.Millisecond,
}

func testPacket(payload string) *Packet {
	return &Packet{
		Src:           netip.MustParseAddrPort("192.0.2.1:5060"),
		Dst:           netip.MustParseAddrPort("198.51.100.2:5060"),
		Proto:         17,
		Time:          time.Unix(1700000000, 5000),
		Type:          PayloadSIP,
		CorrelationID: "call-1",
		Payload:       []byte(payload),
	}
}

// collector is a loopback HEP receiver for one network.
type collector struct {
	t       *testing.T
	network string
	tlsCfg  *tls.Config
	addr    string
	out     chan decoded

	mu    sync.Mutex
	ln    net.Listener
	pc    net.PacketConn
	conns []net.Conn
	wg    sync.WaitGroup
}

// newCollector listens on addr ("127.0.0.1:0" or a previous address).
func newCollector(t *testing.T, network, addr string, cfg *tls.Config) *collector {
	t.Helper()
	c := &collector{t: t, network: network, tlsCfg: cfg, out: make(chan decoded, 1024)}
	c.listen(addr)
	t.Cleanup(c.close)
	return c
}

func (c *collector) listen(addr string) {
	c.t.Helper()
	var err error
	for i := 0; i < 100; i++ { // the port may linger briefly after a close
		switch c.network {
		case "udp":
			c.pc, err = net.ListenPacket("udp", addr)
			if err == nil {
				c.addr = c.pc.LocalAddr().String()
				c.wg.Add(1)
				go c.serveUDP(c.pc)
			}
		default:
			c.ln, err = net.Listen("tcp", addr)
			if err == nil {
				if c.network == "tls" {
					c.ln = tls.NewListener(c.ln, c.tlsCfg)
				}
				c.addr = c.ln.Addr().String()
				c.wg.Add(1)
				go c.serveTCP(c.ln)
			}
		}
		if err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	c.t.Fatalf("listen %s: %v", addr, err)
}

func (c *collector) serveUDP(pc net.PacketConn) {
	defer c.wg.Done()
	buf := make([]byte, 70000)
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if d, _, err := decodePacket(buf[:n]); err == nil {
			c.out <- d
		}
	}
}

func (c *collector) serveTCP(ln net.Listener) {
	defer c.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		c.mu.Lock()
		c.conns = append(c.conns, conn)
		c.mu.Unlock()
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			c.readStream(conn)
		}()
	}
}

// readStream splits back-to-back packets by the HEP length field alone.
func (c *collector) readStream(conn net.Conn) {
	r := bufio.NewReader(conn)
	for {
		hdr, err := r.Peek(headerLen)
		if err != nil {
			return
		}
		total := int(binary.BigEndian.Uint16(hdr[4:6]))
		pkt := make([]byte, total)
		if _, err := io.ReadFull(r, pkt); err != nil {
			return
		}
		d, _, err := decodePacket(pkt)
		if err != nil {
			c.t.Errorf("stream decode: %v", err)
			return
		}
		c.out <- d
	}
}

// stop closes the listener and every accepted connection.
func (c *collector) stop() {
	c.mu.Lock()
	if c.ln != nil {
		c.ln.Close()
	}
	if c.pc != nil {
		c.pc.Close()
	}
	for _, conn := range c.conns {
		conn.Close()
	}
	c.conns = nil
	c.mu.Unlock()
	c.wg.Wait()
}

func (c *collector) close() { c.stop() }

func (c *collector) recv(t *testing.T) decoded {
	t.Helper()
	select {
	case d := <-c.out:
		return d
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a packet")
		return decoded{}
	}
}

func newSender(t *testing.T, o Options) *Sender {
	t.Helper()
	o.timing = fastTiming
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		s.Close(ctx)
	})
	return s
}

// testCerts writes a self-signed cert usable as server and client identity.
func testCerts(t *testing.T) (certFile, keyFile string, cert tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "hep-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cert, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile, cert
}

func serverTLS(cert tls.Certificate, mutual bool) *tls.Config {
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if mutual {
		leaf, _ := x509.ParseCertificate(cert.Certificate[0])
		pool := x509.NewCertPool()
		pool.AddCert(leaf)
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg
}

func checkDelivered(t *testing.T, d decoded, payload string) {
	t.Helper()
	if string(d.Payload) != payload || d.Type != PayloadSIP || d.Proto != 17 ||
		d.Src != netip.MustParseAddrPort("192.0.2.1:5060") ||
		d.Dst != netip.MustParseAddrPort("198.51.100.2:5060") ||
		d.CorrelationID != "call-1" || d.CaptureID != 42 || d.Node != "edge-1" ||
		!d.Time.Equal(time.Unix(1700000000, 5000).Truncate(time.Microsecond)) {
		t.Errorf("unexpected packet %+v", d)
	}
}

func TestDelivery(t *testing.T) {
	certFile, keyFile, cert := testCerts(t)
	clientTLS, err := TLSConfig(certFile, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	mtlsClient, err := TLSConfig(certFile, certFile, keyFile, "")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, network string
		server        *tls.Config
		client        *tls.Config
	}{
		{"udp", "udp", nil, nil},
		{"tcp", "tcp", nil, nil},
		{"tls", "tls", serverTLS(cert, false), clientTLS},
		{"mutual tls", "tls", serverTLS(cert, true), mtlsClient},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			col := newCollector(t, tc.network, "127.0.0.1:0", tc.server)
			s := newSender(t, Options{Network: tc.network, Addr: col.addr, TLS: tc.client,
				CaptureID: 42, NodeName: "edge-1"})
			for _, want := range []string{"one", "two", "three"} {
				if !s.Send(testPacket(want)) {
					t.Fatal("Send refused")
				}
				checkDelivered(t, col.recv(t), want)
			}
			if st := s.Stats(); st.Sent != 3 || st.Dropped != 0 || st.WriteErrors != 0 {
				t.Errorf("stats %+v", st)
			}
		})
	}
}

func TestTLSRejectsUntrustedServer(t *testing.T) {
	_, _, cert := testCerts(t)
	col := newCollector(t, "tls", "127.0.0.1:0", serverTLS(cert, false))
	// No CA configured: the self-signed certificate must not verify.
	s := newSender(t, Options{Network: "tls", Addr: col.addr})
	s.Send(testPacket("x"))
	deadline := time.Now().Add(5 * time.Second)
	for s.Stats().WriteErrors == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if st := s.Stats(); st.WriteErrors == 0 || st.Sent != 0 {
		t.Errorf("stats %+v", st)
	}
	select {
	case d := <-col.out:
		t.Errorf("packet delivered over unverified TLS: %+v", d)
	default:
	}
}

func TestSendDropsWhenQueueFull(t *testing.T) {
	// Reserve a port, then close it: dials are refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	slow := *fastTiming
	slow.backoffMin, slow.backoffMax = time.Minute, time.Minute
	s, err := New(Options{Network: "tcp", Addr: addr, QueueSize: 2, timing: &slow})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	start := time.Now()
	refused := 0
	for i := 0; i < 100; i++ {
		if !s.Send(testPacket("x")) {
			refused++
		}
	}
	if time.Since(start) > time.Second {
		t.Errorf("Send blocked: %v", time.Since(start))
	}
	if refused < 90 {
		t.Errorf("refused %d of 100", refused)
	}
	st := s.Stats()
	if st.Dropped != uint64(refused) {
		t.Errorf("Dropped %d, refused %d", st.Dropped, refused)
	}
}

func TestOversizeIsNotDropped(t *testing.T) {
	col := newCollector(t, "udp", "127.0.0.1:0", nil)
	s := newSender(t, Options{Network: "udp", Addr: col.addr, CaptureID: 42, NodeName: "edge-1"})
	big := testPacket("")
	big.Payload = make([]byte, MaxPacketSize)
	s.Send(big)
	s.Send(testPacket("ok"))
	checkDelivered(t, col.recv(t), "ok")
	if st := s.Stats(); st.EncodeErrors != 1 || st.Dropped != 0 || st.Sent != 1 {
		t.Errorf("stats %+v", st)
	}
}

func TestReconnectAfterCollectorRestart(t *testing.T) {
	for _, network := range []string{"tcp", "tls"} {
		t.Run(network, func(t *testing.T) {
			certFile, _, cert2 := testCerts(t)
			var srv, cli *tls.Config
			if network == "tls" {
				srv = serverTLS(cert2, false)
				var err error
				if cli, err = TLSConfig(certFile, "", "", ""); err != nil {
					t.Fatal(err)
				}
			}
			col := newCollector(t, network, "127.0.0.1:0", srv)
			s := newSender(t, Options{Network: network, Addr: col.addr, TLS: cli, CaptureID: 42, NodeName: "edge-1"})
			s.Send(testPacket("before"))
			checkDelivered(t, col.recv(t), "before")

			addr := col.addr
			col.stop()
			col.listen(addr)

			deadline := time.Now().Add(10 * time.Second)
			for {
				s.Send(testPacket("after"))
				select {
				case d := <-col.out:
					checkDelivered(t, d, "after")
					if s.Stats().WriteErrors == 0 {
						t.Error("WriteErrors == 0 after a restart")
					}
					return
				case <-time.After(20 * time.Millisecond):
				}
				if time.Now().After(deadline) {
					t.Fatalf("no delivery after restart; stats %+v", s.Stats())
				}
			}
		})
	}
}

func TestCloseFlushes(t *testing.T) {
	col := newCollector(t, "tcp", "127.0.0.1:0", nil)
	s, err := New(Options{Network: "tcp", Addr: col.addr, CaptureID: 42, NodeName: "edge-1", timing: fastTiming})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		s.Send(testPacket("flush"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if s.Send(testPacket("late")) {
		t.Error("Send accepted after Close")
	}
	if err := s.Close(ctx); err != nil { // idempotent
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		checkDelivered(t, col.recv(t), "flush")
	}
	if st := s.Stats(); st.Sent != 20 || st.Dropped != 1 {
		t.Errorf("stats %+v", st)
	}
}

func TestCloseReturnsWhenCollectorNeverReads(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { // accept and hold, never read
		var held []net.Conn
		defer func() {
			for _, c := range held {
				c.Close()
			}
		}()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			held = append(held, c)
		}
	}()
	long := *fastTiming
	long.write = time.Minute
	s, err := New(Options{Network: "tcp", Addr: ln.Addr().String(), QueueSize: 4, timing: &long})
	if err != nil {
		t.Fatal(err)
	}
	p := testPacket("")
	p.Payload = make([]byte, 60000)
	// Fill the socket buffers until the writer blocks and the queue is full.
	deadline := time.Now().Add(20 * time.Second)
	for s.Stats().Dropped < 10 {
		if time.Now().After(deadline) {
			t.Fatal("writer never blocked")
		}
		s.Send(p)
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	s.Close(ctx)
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("Close took %v", d)
	}
}

func TestNewValidates(t *testing.T) {
	for _, o := range []Options{
		{Network: "sctp", Addr: "127.0.0.1:9060"},
		{Network: "udp", Addr: "nohostport"},
	} {
		if _, err := New(o); err == nil {
			t.Errorf("New(%+v) succeeded", o)
		}
	}
}

func TestTLSConfigErrors(t *testing.T) {
	if _, err := TLSConfig("/nonexistent", "", "", ""); err == nil {
		t.Error("missing ca_file accepted")
	}
	certFile, _, _ := testCerts(t)
	if _, err := TLSConfig("", certFile, "", ""); err == nil {
		t.Error("cert without key accepted")
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	os.WriteFile(bad, []byte("not pem"), 0o600)
	if _, err := TLSConfig(bad, "", "", ""); err == nil {
		t.Error("garbage ca_file accepted")
	}
}
