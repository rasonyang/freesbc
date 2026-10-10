package edge

import (
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/emiago/sipgo/sip"
)

// Micro-benchmarks for the dialog table (issue #109). They run only under
// -bench. None of them binds a socket or allocates media, so they use no
// ports and cannot collide with the harness bands.

func benchInvite(i int) *sip.Request {
	req := sip.NewRequest(sip.INVITE, sip.Uri{User: "2002", Host: "example.com"})
	from := &sip.FromHeader{Address: sip.Uri{User: "1001", Host: "example.com"}, Params: sip.NewParams()}
	from.Params.Add("tag", fmt.Sprintf("c%d", i))
	req.AppendHeader(from)
	req.AppendHeader(&sip.ToHeader{Address: sip.Uri{User: "2002", Host: "example.com"}, Params: sip.NewParams()})
	callID := sip.CallIDHeader(fmt.Sprintf("bench-call-%d@203.0.113.50", i))
	req.AppendHeader(&callID)
	req.AppendHeader(&sip.CSeqHeader{SeqNo: 1, MethodName: sip.INVITE})
	return req
}

func benchTable() *dialogTable {
	return newDialogTable(NewMetrics(), slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// benchConfirmed fills a table with n confirmed dialogs and returns the
// keys lookup needs: Call-ID, caller tag, callee tag.
func benchConfirmed(b *testing.B, n int) (*dialogTable, [][3]string) {
	b.Helper()
	tab := benchTable()
	keys := make([][3]string, n)
	for i := 0; i < n; i++ {
		req := benchInvite(i)
		d, res := tab.begin(req, planePublic, 0)
		if res != beginOK {
			b.Fatalf("begin %d: %v", i, res)
		}
		callee := fmt.Sprintf("s%d", i)
		tab.mu.Lock()
		d.state = dialogConfirmed
		d.calleeTag = callee
		tab.mu.Unlock()
		keys[i] = [3]string{d.callID, d.callerTag, callee}
	}
	return tab, keys
}

// BenchmarkDialogBeginEnd opens and ends one dialog in a table that already
// holds 10000 confirmed dialogs.
func BenchmarkDialogBeginEnd(b *testing.B) {
	tab, _ := benchConfirmed(b, 10000)
	reqs := make([]*sip.Request, 1024)
	for i := range reqs {
		reqs[i] = benchInvite(1_000_000 + i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d, res := tab.begin(reqs[i%len(reqs)], planePublic, 0)
		if res != beginOK {
			b.Fatalf("begin: %v", res)
		}
		d.end(endShutdown)
	}
}

// BenchmarkDialogBeginEndParallel is the same cycle from many goroutines on
// distinct Call-IDs; it exposes the table-wide mutex.
func BenchmarkDialogBeginEndParallel(b *testing.B) {
	tab, _ := benchConfirmed(b, 10000)
	reqs := make([]*sip.Request, 4096)
	for i := range reqs {
		reqs[i] = benchInvite(1_000_000 + i)
	}
	var worker atomic.Int64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// Each worker owns a disjoint slice of the request pool, so no
		// two workers ever hold the same Call-ID open.
		w := int(worker.Add(1)-1) % 64
		per := len(reqs) / 64
		i := 0
		for pb.Next() {
			i++
			d, res := tab.begin(reqs[w*per+i%per], planePublic, 0)
			if res != beginOK {
				b.Errorf("begin: %v", res)
				return
			}
			d.end(endShutdown)
		}
	})
}

// BenchmarkDialogLookup finds a confirmed dialog among 10000 by Call-ID and
// both tags.
func BenchmarkDialogLookup(b *testing.B) {
	tab, keys := benchConfirmed(b, 10000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k := keys[i%len(keys)]
		if _, _, ok := tab.lookup(k[0], k[1], k[2]); !ok {
			b.Fatal("lookup missed")
		}
	}
}

// BenchmarkDialogLookupParallel is the lookup from many goroutines; every
// in-dialog request takes the same mutex, so this is the contention figure.
func BenchmarkDialogLookupParallel(b *testing.B) {
	tab, keys := benchConfirmed(b, 10000)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			i++
			k := keys[i%len(keys)]
			if _, _, ok := tab.lookup(k[0], k[1], k[2]); !ok {
				b.Error("lookup missed")
				return
			}
		}
	})
}
