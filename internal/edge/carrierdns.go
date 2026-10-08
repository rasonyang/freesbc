package edge

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

// This file is the carrier directory: what edge.carriers resolves to, and
// with it the set of public source addresses an out-of-dialog INVITE is
// admitted from as a carrier's.
//
// A literal-IP entry is static. A DNS-name entry resolves on the PUBLIC
// side only (the switch is never asked, and the private leg does no DNS):
// without a port through SRV (_sip._udp, _sip._tcp or _sips._tcp.<host>
// by the carrier's transport) ordered by priority and weight (RFC 2782) and
// then A/AAAA per target; with an explicit port through A/AAAA only (RFC
// 3263 §4.2). With no SRV record the port is the transport's default (5060,
// 5061 for tls). There is no NAPTR and no failover across SRV targets. Go exposes no record TTL, so a good
// answer is cached for the carrierDNSTTL constant and a failed one for the
// much shorter carrierDNSNegTTL. A failed refresh keeps the last good set:
// a resolver outage must never turn a carrier's source address into
// "unknown". A DNS failure at startup is not fatal either; the carrier is
// simply unresolved (and its calls dropped by admission) until a lookup
// succeeds.
//
// A background goroutine (Run) refreshes entries as they expire and
// publishes an immutable snapshot through an atomic pointer, so the shield
// and the admission check read it without locking.

const (
	// carrierDNSTTL is how long a resolved carrier is cached.
	carrierDNSTTL = 300 * time.Second
	// carrierDNSNegTTL is how long a FAILED or EMPTY lookup is cached before
	// it is retried, so a transient fault is not pinned for the whole TTL.
	carrierDNSNegTTL = 10 * time.Second
	// carrierLookupTimeout bounds one DNS query.
	carrierLookupTimeout = 3 * time.Second
	// carrierUnknown is the name stamped on a request from a carrier source
	// that matches no edge.carriers entry by address.
	carrierUnknown = "unknown"
)

// carrierSnapshot is one immutable published view of the directory.
type carrierSnapshot struct {
	names []string                    // edge.carriers names, sorted
	addrs map[string][]netip.AddrPort // name → resolved destinations, in preference order
	nets  []netip.Prefix              // carrier source prefixes, sorted and deduplicated
	// extra is edge.carrier_sources alone: prefixes that match on any
	// public transport. nets also holds the carriers' own addresses, which
	// match by IP for the shield but are admitted only on their carrier's
	// transport (carrierFor).
	extra []netip.Prefix
	// transports is each carrier's transport by name.
	transports map[string]string
}

// isSource reports whether ip is inside a carrier-source prefix.
func (c *carrierSnapshot) isSource(ip netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	for _, p := range c.nets {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// carrierFor names the carrier a public source belongs to, for a request
// that arrived over network (udp, tcp, tls...). A carrier's resolved
// address counts only on that carrier's own transport: a tls carrier's IP
// over UDP is no carrier. An exact IP:port match wins; failing that the
// first entry (by sorted name) with that IP; a source inside
// edge.carrier_sources (any transport) that matches no entry is
// carrierUnknown. ok is false for a source that is no carrier source at
// all.
func (c *carrierSnapshot) carrierFor(src netip.AddrPort, network string) (name string, ok bool) {
	ip := src.Addr().Unmap().WithZone("")
	src = netip.AddrPortFrom(ip, src.Port())
	byIP := ""
	for _, n := range c.names {
		if c.transports[n] != network {
			continue
		}
		for _, a := range c.addrs[n] {
			if a == src {
				return n, true
			}
			if byIP == "" && a.Addr() == ip {
				byIP = n
			}
		}
	}
	if byIP != "" {
		return byIP, true
	}
	for _, p := range c.extra {
		if p.Contains(ip) {
			return carrierUnknown, true
		}
	}
	return "", false
}

// sourcesString renders the source set for the startup log.
func (c *carrierSnapshot) sourcesString() string {
	parts := make([]string, len(c.nets))
	for i, p := range c.nets {
		parts[i] = p.String()
	}
	return strings.Join(parts, ",")
}

// carrierEntry is the cached resolution of one DNS-name carrier.
type carrierEntry struct {
	addrs   []netip.AddrPort // last good set (empty until a lookup succeeded)
	expiry  time.Time
	failing bool
}

// carrierDirectory resolves edge.carriers and publishes the result.
type carrierDirectory struct {
	log      *slog.Logger
	carriers []config.Carrier // sorted by name
	static   []netip.Prefix   // carrier_sources plus literal-IP carriers
	extra    []netip.Prefix   // carrier_sources alone

	// lookupSRV and lookupIP are the DNS seams; tests replace them.
	lookupSRV func(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
	lookupIP  func(ctx context.Context, host string) ([]netip.Addr, error)
	now       func() time.Time

	mu      sync.Mutex // serialises refresh; guards entries and rnd
	entries map[string]*carrierEntry
	rnd     *rand.Rand

	snap atomic.Pointer[carrierSnapshot]
}

func newCarrierDirectory(cfg *config.Config, log *slog.Logger) *carrierDirectory {
	d := &carrierDirectory{
		log:      log,
		carriers: cfg.CarrierList(),
		static:   cfg.CarrierNets(),
		extra:    cfg.CarrierSourceNets(),
		lookupSRV: func(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
			return net.DefaultResolver.LookupSRV(ctx, service, proto, name)
		},
		lookupIP: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		now:     time.Now,
		entries: map[string]*carrierEntry{},
		rnd:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	d.publish()
	return d
}

// snapshot is the current published view.
func (d *carrierDirectory) snapshot() *carrierSnapshot { return d.snap.Load() }

// publish builds and stores a snapshot from the literal carriers, the
// static prefixes and the cached resolutions. The caller holds mu, or is
// the constructor.
func (d *carrierDirectory) publish() {
	snap := &carrierSnapshot{addrs: map[string][]netip.AddrPort{}, transports: map[string]string{}, extra: d.extra}
	seen := map[netip.Prefix]bool{}
	add := func(p netip.Prefix) {
		if !seen[p] {
			seen[p] = true
			snap.nets = append(snap.nets, p)
		}
	}
	for _, p := range d.static {
		add(p)
	}
	for _, c := range d.carriers {
		snap.names = append(snap.names, c.Name)
		snap.transports[c.Name] = config.CarrierUDP
		if c.Transport != "" {
			snap.transports[c.Name] = c.Transport
		}
		if c.Literal() {
			add(netip.PrefixFrom(c.Addr, c.Addr.BitLen()))
			snap.addrs[c.Name] = []netip.AddrPort{netip.AddrPortFrom(c.Addr, uint16(c.DialPort()))}
			continue
		}
		if e := d.entries[c.Name]; e != nil {
			snap.addrs[c.Name] = e.addrs
			for _, a := range e.addrs {
				add(netip.PrefixFrom(a.Addr(), a.Addr().BitLen()))
			}
		}
	}
	sort.Strings(snap.names)
	sort.Slice(snap.nets, func(i, j int) bool {
		if c := snap.nets[i].Addr().Compare(snap.nets[j].Addr()); c != 0 {
			return c < 0
		}
		return snap.nets[i].Bits() < snap.nets[j].Bits()
	})
	d.snap.Store(snap)
}

// refresh resolves every DNS-name carrier whose cache entry is missing or
// expired, then publishes a new snapshot.
func (d *carrierDirectory) refresh(ctx context.Context) {
	d.mu.Lock()
	defer d.mu.Unlock()
	changed := false
	for _, c := range d.carriers {
		if c.Literal() {
			continue
		}
		now := d.now()
		e := d.entries[c.Name]
		if e != nil && now.Before(e.expiry) {
			continue
		}
		addrs, err := d.resolve(ctx, c)
		if e == nil {
			e = &carrierEntry{}
			d.entries[c.Name] = e
		}
		if err != nil || len(addrs) == 0 {
			if err == nil {
				err = errors.New("no addresses")
			}
			// Keep the last good set; retry soon.
			e.expiry = now.Add(carrierDNSNegTTL)
			if !e.failing {
				d.log.Warn("carrier DNS lookup failed; keeping the last good addresses",
					"carrier", c.Name, "host", c.Host, "err", err, "have", len(e.addrs))
			} else {
				d.log.Debug("carrier DNS lookup still failing", "carrier", c.Name, "err", err)
			}
			e.failing = true
			continue
		}
		if e.failing || fmt.Sprint(e.addrs) != fmt.Sprint(addrs) {
			d.log.Info("carrier resolved", "carrier", c.Name, "host", c.Host, "addrs", fmt.Sprint(addrs))
		}
		e.addrs, e.expiry, e.failing = addrs, now.Add(carrierDNSTTL), false
		changed = true
	}
	if changed {
		d.publish()
	}
}

// Run refreshes the directory until ctx ends: once at once, then whenever
// an entry's cache window has passed (checked at half the negative TTL).
func (d *carrierDirectory) Run(ctx context.Context) {
	d.refresh(ctx)
	t := time.NewTicker(carrierDNSNegTTL / 2)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.refresh(ctx)
		}
	}
}

// resolve returns the destinations of one DNS-name carrier, in preference
// order.
func (d *carrierDirectory) resolve(ctx context.Context, c config.Carrier) ([]netip.AddrPort, error) {
	if c.ExplicitPort {
		return d.hostAddrs(ctx, c.Host, uint16(c.Port))
	}
	service, proto := srvName(c.Transport)
	sctx, cancel := context.WithTimeout(ctx, carrierLookupTimeout)
	_, recs, err := d.lookupSRV(sctx, service, proto, c.Host)
	cancel()
	if err != nil {
		var dnsErr *net.DNSError
		if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
			return nil, fmt.Errorf("srv lookup: %w", err)
		}
		recs = nil // no SRV record: fall back to the host itself
	}
	var out []netip.AddrPort
	var lastErr error
	for _, t := range orderSRV(recs, d.rnd) {
		addrs, err := d.hostAddrs(ctx, t.host, t.port)
		if err != nil {
			lastErr = err
			continue
		}
		out = append(out, addrs...)
	}
	if len(out) > 0 {
		return dedupeAddrPorts(out), nil
	}
	if len(recs) > 0 && lastErr != nil {
		return nil, lastErr // SRV exists but none of its targets resolved
	}
	return d.hostAddrs(ctx, c.Host, uint16(c.DialPort()))
}

// srvName is the SRV service and protocol of a carrier transport (RFC 3263
// §4.2): _sip._udp, _sip._tcp, and _sips._tcp for tls.
func srvName(transport string) (service, proto string) {
	switch transport {
	case config.CarrierTLS:
		return "sips", "tcp"
	case config.CarrierTCP:
		return "sip", "tcp"
	}
	return "sip", "udp"
}

// hostAddrs resolves host to A/AAAA addresses on port.
func (d *carrierDirectory) hostAddrs(ctx context.Context, host string, port uint16) ([]netip.AddrPort, error) {
	lctx, cancel := context.WithTimeout(ctx, carrierLookupTimeout)
	defer cancel()
	ips, err := d.lookupIP(lctx, host)
	if err != nil {
		return nil, fmt.Errorf("lookup %s: %w", host, err)
	}
	out := make([]netip.AddrPort, 0, len(ips))
	for _, ip := range ips {
		ip = ip.Unmap().WithZone("")
		if ip.IsUnspecified() {
			continue
		}
		out = append(out, netip.AddrPortFrom(ip, port))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("lookup %s: no addresses", host)
	}
	return out, nil
}

func dedupeAddrPorts(in []netip.AddrPort) []netip.AddrPort {
	seen := map[netip.AddrPort]bool{}
	out := in[:0]
	for _, a := range in {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

// srvTarget is one usable SRV record.
type srvTarget struct {
	host string
	port uint16
}

// orderSRV orders SRV records by priority ascending, then by RFC 2782
// weighted-random selection within each priority. Records whose target is
// "." (service unavailable) or whose port is 0 are skipped.
func orderSRV(recs []*net.SRV, rnd *rand.Rand) []srvTarget {
	byPrio := map[uint16][]*net.SRV{}
	var prios []uint16
	for _, rec := range recs {
		if rec.Target == "." || rec.Port == 0 {
			continue
		}
		if _, seen := byPrio[rec.Priority]; !seen {
			prios = append(prios, rec.Priority)
		}
		byPrio[rec.Priority] = append(byPrio[rec.Priority], rec)
	}
	sort.Slice(prios, func(i, j int) bool { return prios[i] < prios[j] })

	var out []srvTarget
	for _, p := range prios {
		// RFC 2782: weight-0 records go first, so they keep a small chance
		// of being picked.
		var zeros, nonzeros []*net.SRV
		for _, rec := range byPrio[p] {
			if rec.Weight == 0 {
				zeros = append(zeros, rec)
			} else {
				nonzeros = append(nonzeros, rec)
			}
		}
		group := append(zeros, nonzeros...)
		for len(group) > 0 {
			total := 0
			for _, rec := range group {
				total += int(rec.Weight)
			}
			pick := 0
			if total == 0 {
				pick = rnd.Intn(len(group))
			} else {
				target := rnd.Intn(total + 1) // 0..total inclusive
				acc := 0
				for i, rec := range group {
					acc += int(rec.Weight)
					if acc >= target {
						pick = i
						break
					}
				}
			}
			rec := group[pick]
			out = append(out, srvTarget{host: strings.TrimSuffix(rec.Target, "."), port: rec.Port})
			group = append(group[:pick], group[pick+1:]...)
		}
	}
	return out
}
