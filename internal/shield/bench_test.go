package shield

import (
	"net/netip"
	"testing"

	"github.com/freesbc/freesbc/internal/config"
)

// Micro-benchmarks for the shield hot path (issue #109). They run only
// under -bench.

// benchShield builds a shield with a rate limit high enough that no
// benchmark source is ever limited, so the figure is the admit path.
func benchShield(b *testing.B) *Shield {
	b.Helper()
	cfg, err := config.Parse([]byte(`
public: { ip: 203.0.113.7 }
private: { ip: 10.77.0.2 }
edge:
  switch: [10.77.0.10:5060]
  listen: { udp: 5060 }
shield:
  rate_limit: 1000000000/s per_ip
  carrier_rate_limit: 1000000000/s per_ip
  ban: 1h
`))
	if err != nil {
		b.Fatal(err)
	}
	s := New(config.NewStore(cfg), discard(), nil)
	b.Cleanup(func() { s.Close() })
	return s
}

func benchSources(n int) []netip.AddrPort {
	out := make([]netip.AddrPort, n)
	for i := range out {
		a := netip.AddrFrom4([4]byte{198, byte(18 + i>>16&1), byte(i >> 8), byte(i)})
		out[i] = netip.AddrPortFrom(a, uint16(5060+i%1000))
	}
	return out
}

func BenchmarkAllowRate(b *testing.B) {
	for _, tc := range []struct {
		name string
		n    int
	}{{"1src", 1}, {"10000src", 10000}} {
		b.Run(tc.name, func(b *testing.B) {
			s := benchShield(b)
			srcs := benchSources(tc.n)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !s.AllowRate(srcs[i%len(srcs)].Addr()) {
					b.Fatal("unexpectedly limited")
				}
			}
		})
	}
}

func BenchmarkAllowRateParallel(b *testing.B) {
	s := benchShield(b)
	srcs := benchSources(10000)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			i++
			s.AllowRate(srcs[i%len(srcs)].Addr())
		}
	})
}

func BenchmarkCheckFrom(b *testing.B) {
	for _, tc := range []struct {
		name string
		n    int
	}{{"1src", 1}, {"10000src", 10000}} {
		b.Run(tc.name, func(b *testing.B) {
			s := benchShield(b)
			srcs := benchSources(tc.n)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if s.CheckFrom(srcs[i%len(srcs)], "Zoiper rv2.10", "udp") != Allow {
					b.Fatal("unexpectedly dropped")
				}
			}
		})
	}
}

// BenchmarkCheckFromParallel exposes contention on the limiter and ban
// tables when many sources are checked at once.
func BenchmarkCheckFromParallel(b *testing.B) {
	s := benchShield(b)
	srcs := benchSources(10000)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			i++
			s.CheckFrom(srcs[i%len(srcs)], "Zoiper rv2.10", "udp")
		}
	})
}

// BenchmarkCheckFromParallelOneSource is the worst case for a single
// bucket: every worker charges the same source.
func BenchmarkCheckFromParallelOneSource(b *testing.B) {
	s := benchShield(b)
	src := benchSources(1)[0]
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.CheckFrom(src, "Zoiper rv2.10", "udp")
		}
	})
}
