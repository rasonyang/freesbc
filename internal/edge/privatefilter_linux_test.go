//go:build linux

package edge

import (
	"context"
	"net"
	"testing"
	"time"
)

// The BPF program must accept datagrams received on an accepted interface
// and drop every other one.
func TestPrivateSocketFilterProgram(t *testing.T) {
	loop, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	delivered := func(ifindexes ...int) bool {
		prog, err := ifindexFilter(ifindexes...)
		if err != nil {
			t.Fatal(err)
		}
		lc := net.ListenConfig{Control: attachFilter(prog)}
		pc, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen with filter: %v", err)
		}
		defer pc.Close()
		peer, err := net.Dial("udp", pc.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer peer.Close()
		if _, err := peer.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		if err := pc.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 8)
		_, _, err = pc.ReadFrom(buf)
		return err == nil
	}

	if !delivered(loop.Index) {
		t.Error("a datagram received on the accepted interface was dropped")
	}
	if !delivered(999999, loop.Index) {
		t.Error("the second accepted interface was not honoured")
	}
	if delivered(999999) {
		t.Error("a datagram was delivered although its ingress interface was not accepted")
	}
}
