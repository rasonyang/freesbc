package edge

import (
	"testing"

	"github.com/freesbc/freesbc/internal/sip/sdp"
)

// filterCodecs is the proxy plane's relay policy; the sdp package
// deliberately has no opinion about it, so it is pinned here.
func TestFilterCodecs(t *testing.T) {
	in := []sdp.Codec{
		{PayloadType: 111, Name: "opus", ClockRate: 48000, Channels: 2},
		{PayloadType: 0, Name: "PCMU", ClockRate: 8000, Channels: 1},
		{PayloadType: 97, Name: "G722", ClockRate: 8000, Channels: 1},
		{PayloadType: 8, Name: "PCMA", ClockRate: 8000, Channels: 1},
		{PayloadType: 110, Name: "telephone-event", ClockRate: 48000, Channels: 1},
	}
	got := filterCodecs(in)
	if len(got) != 4 {
		t.Fatalf("filtered = %v, want the four relayable codecs", sdp.Describe(got))
	}
	// Offer order and payload numbers must survive the filter.
	want := []uint8{111, 0, 8, 110}
	for i, pt := range want {
		if got[i].PayloadType != pt {
			t.Errorf("codec %d = pt %d, want %d (%v)", i, got[i].PayloadType, pt, sdp.Describe(got))
		}
	}
	if len(filterCodecs(nil)) != 0 {
		t.Error("filtering nothing must yield nothing")
	}
}
