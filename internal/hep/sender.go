package hep

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const defaultQueueSize = 4096

// Options configures a [Sender].
type Options struct {
	Network string // "udp", "tcp" or "tls"
	Addr    string // collector host:port
	// TLS is used for Network "tls". Nil means system roots with the host
	// of Addr as server name. ServerName defaults to that host, and the
	// minimum version is raised to TLS 1.2. Build one with [TLSConfig].
	TLS       *tls.Config
	CaptureID uint32
	NodeName  string
	QueueSize int // default 4096
	Logger    *slog.Logger

	timing *timing // tests only
}

type timing struct {
	dial, write, backoffMin, backoffMax time.Duration
}

var defaultTiming = timing{
	dial:       5 * time.Second,
	write:      5 * time.Second,
	backoffMin: 100 * time.Millisecond,
	backoffMax: 30 * time.Second,
}

// TLSConfig builds a client TLS config. A non-empty caFile replaces the
// system roots; certFile and keyFile, when set, give the client certificate
// for mutual TLS. An empty serverName is filled from the dial address by
// [New]. Certificate verification is never disabled.
func TLSConfig(caFile, certFile, keyFile, serverName string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("hep: read ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("hep: ca_file holds no certificate")
		}
		cfg.RootCAs = pool
	}
	if (certFile == "") != (keyFile == "") {
		return nil, errors.New("hep: client cert and key must be set together")
	}
	if certFile != "" {
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("hep: client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{c}
	}
	return cfg, nil
}

// Stats are cumulative counters. Dropped counts packets refused by Send (queue
// full or closed) and packets still queued when Close gave up. WriteErrors
// counts packets lost to a dial or write failure. EncodeErrors counts packets
// the encoder refused (oversize, bad address); they are not in Dropped.
type Stats struct {
	Sent         uint64
	Dropped      uint64
	WriteErrors  uint64
	EncodeErrors uint64
}

// Sender queues packets and writes them from a single goroutine.
type Sender struct {
	opts   Options
	tm     timing
	log    *slog.Logger
	stream bool

	queue chan Packet

	closed    atomic.Bool
	stop      chan struct{} // closed by Close: stop accepting, flush
	abort     chan struct{} // closed when Close gives up flushing
	done      chan struct{} // closed when the writer has exited
	closeOnce sync.Once

	sent, dropped, writeErrs, encodeErrs atomic.Uint64

	mu   sync.Mutex // guards conn
	conn net.Conn

	// Writer goroutine only.
	buf      []byte
	backoff  time.Duration
	retryAt  time.Time
	failing  bool // last connection attempt or write failed (for logging)
	dialCtx  context.Context
	dialStop context.CancelFunc
}

// New starts a sender. It does not dial: the writer connects on the first
// packet, so a collector that is down never blocks the caller.
func New(opts Options) (*Sender, error) {
	switch opts.Network {
	case "udp", "tcp", "tls":
	default:
		return nil, fmt.Errorf("hep: network %q must be udp, tcp or tls", opts.Network)
	}
	host, _, err := net.SplitHostPort(opts.Addr)
	if err != nil {
		return nil, fmt.Errorf("hep: addr: %w", err)
	}
	if opts.Network == "tls" {
		var cfg *tls.Config
		if opts.TLS != nil {
			cfg = opts.TLS.Clone()
		} else {
			cfg = &tls.Config{}
		}
		if cfg.MinVersion < tls.VersionTLS12 {
			cfg.MinVersion = tls.VersionTLS12
		}
		if cfg.ServerName == "" {
			cfg.ServerName = host
		}
		cfg.InsecureSkipVerify = false
		opts.TLS = cfg
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = defaultQueueSize
	}
	s := &Sender{
		opts:   opts,
		tm:     defaultTiming,
		log:    opts.Logger,
		stream: opts.Network != "udp",
		queue:  make(chan Packet, opts.QueueSize),
		stop:   make(chan struct{}),
		abort:  make(chan struct{}),
		done:   make(chan struct{}),
	}
	if opts.timing != nil {
		s.tm = *opts.timing
	}
	if s.log == nil {
		s.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s.backoff = s.tm.backoffMin
	s.dialCtx, s.dialStop = context.WithCancel(context.Background())
	go s.run()
	return s, nil
}

// Send queues p without blocking and reports whether it was accepted. It
// returns false and counts a drop when the queue is full or the sender is
// closed.
//
// Send takes ownership of p.Payload: the caller must not modify it
// afterwards, because the packet is encoded later on the writer goroutine.
// The Packet struct itself is copied.
func (s *Sender) Send(p *Packet) bool {
	if s.closed.Load() {
		s.dropped.Add(1)
		return false
	}
	select {
	case s.queue <- *p:
		return true
	default:
		s.dropped.Add(1)
		return false
	}
}

// Stats returns a snapshot of the counters.
func (s *Sender) Stats() Stats {
	return Stats{
		Sent:         s.sent.Load(),
		Dropped:      s.dropped.Load(),
		WriteErrors:  s.writeErrs.Load(),
		EncodeErrors: s.encodeErrs.Load(),
	}
}

// Close stops accepting packets, tries to flush the queue until ctx is done,
// then closes the connection and returns. A write stuck on a blackholed
// collector is unblocked by closing the connection. Close is idempotent.
func (s *Sender) Close(ctx context.Context) error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.stop)
	})
	select {
	case <-s.done:
	case <-ctx.Done():
		s.giveUp()
		<-s.done
	}
	// A Send that passed the closed check just before Close may have queued
	// after the writer drained; count it rather than leave it uncounted.
	s.dropRest()
	s.closeConn()
	return nil
}

func (s *Sender) giveUp() {
	select {
	case <-s.abort:
	default:
		close(s.abort)
	}
	s.dialStop()
	s.closeConn()
}

func (s *Sender) closeConn() {
	s.mu.Lock()
	c := s.conn
	s.conn = nil
	s.mu.Unlock()
	if c != nil {
		c.Close()
	}
}

func (s *Sender) run() {
	defer close(s.done)
	defer s.dialStop()
	for {
		// While backing off the queue is left alone, so it fills and Send
		// drops instead of the writer burning packets on a dead peer.
		if s.stream && s.currentConn() == nil {
			if d := time.Until(s.retryAt); d > 0 {
				t := time.NewTimer(d)
				select {
				case <-t.C:
				case <-s.stop:
					t.Stop()
					s.drain()
					return
				}
			}
		}
		select {
		case p := <-s.queue:
			s.write(&p)
		case <-s.stop:
			s.drain()
			return
		}
	}
}

// drain flushes what is queued after Close, stopping at the first failure to
// connect or when Close gives up. Packets left behind count as dropped.
func (s *Sender) drain() {
	for {
		select {
		case <-s.abort:
			s.dropRest()
			return
		default:
		}
		select {
		case p := <-s.queue:
			if !s.write(&p) && s.currentConn() == nil && s.stream {
				s.dropRest()
				return
			}
		default:
			return
		}
	}
}

func (s *Sender) dropRest() {
	for {
		select {
		case <-s.queue:
			s.dropped.Add(1)
		default:
			return
		}
	}
}

func (s *Sender) currentConn() net.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn
}

// write encodes and sends one packet, reporting success.
func (s *Sender) write(p *Packet) bool {
	var err error
	s.buf, err = AppendPacket(s.buf[:0], p, s.opts.CaptureID, s.opts.NodeName)
	if err != nil {
		s.encodeErrs.Add(1)
		return true // handled: the connection state is unchanged
	}
	c := s.currentConn()
	if c == nil {
		if c, err = s.dial(); err != nil {
			s.fail("dial", err)
			s.writeErrs.Add(1)
			return false
		}
	}
	if s.stream {
		c.SetWriteDeadline(time.Now().Add(s.tm.write))
	}
	if _, err = c.Write(s.buf); err != nil {
		s.writeErrs.Add(1)
		if s.stream {
			s.closeConnIf(c)
			s.fail("write", err)
		} else {
			s.fail("write", err) // UDP: the socket stays
		}
		return false
	}
	s.sent.Add(1)
	s.backoff = s.tm.backoffMin
	if s.failing {
		s.failing = false
		s.log.Info("hep: collector reachable again", "addr", s.opts.Addr)
	}
	return true
}

func (s *Sender) closeConnIf(c net.Conn) {
	s.mu.Lock()
	if s.conn == c {
		s.conn = nil
	}
	s.mu.Unlock()
	c.Close()
}

// fail starts the backoff and logs only the first failure of a streak.
func (s *Sender) fail(what string, err error) {
	if s.stream {
		s.retryAt = time.Now().Add(s.backoff)
		s.backoff = min(s.backoff*2, s.tm.backoffMax)
	}
	if !s.failing {
		s.failing = true
		s.log.Warn("hep: collector unavailable", "addr", s.opts.Addr, "op", what, "err", err)
	}
}

func (s *Sender) dial() (net.Conn, error) {
	ctx, cancel := context.WithTimeout(s.dialCtx, s.tm.dial)
	defer cancel()
	var (
		c   net.Conn
		err error
	)
	switch s.opts.Network {
	case "tls":
		d := tls.Dialer{NetDialer: &net.Dialer{}, Config: s.opts.TLS}
		c, err = d.DialContext(ctx, "tcp", s.opts.Addr)
	default:
		var d net.Dialer
		c, err = d.DialContext(ctx, s.opts.Network, s.opts.Addr)
	}
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.dialCtx.Err() != nil {
		s.mu.Unlock()
		c.Close()
		return nil, context.Canceled
	}
	s.conn = c
	s.mu.Unlock()
	if s.stream {
		// The collector never replies; reading only notices a peer that
		// closed, so the next write reconnects instead of failing silently.
		go func() {
			io.Copy(io.Discard, c)
			c.Close()
		}()
	}
	return c, nil
}
