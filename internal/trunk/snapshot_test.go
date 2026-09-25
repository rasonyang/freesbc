package trunk

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

// audit: P2-TRK-005
// A call takes one config snapshot. A reload that lands after the INVITE
// was identified (here: re-pointing the carrier peer at another address)
// must not reach the rest of that call: the route, the targets and the
// media range all come from the snapshot the call started with.
//
// Ports: SIP 13780-13782, media 14780-14789.
func TestCallUsesOneConfigSnapshot(t *testing.T) {
	oldCarrier := auditStartCarrier(t, "127.0.0.1:13781", 0)
	newCarrier := auditStartCarrier(t, "127.0.0.1:13782", 0)

	cfg, err := config.Parse([]byte(auditTrunkCfg(13780, 13781, 14780, 14789, "")))
	if err != nil {
		t.Fatal(err)
	}
	next, err := config.Parse([]byte(auditTrunkCfg(13780, 13782, 14780, 14789, "")))
	if err != nil {
		t.Fatal(err)
	}
	store := config.NewStore(cfg)
	srv := NewServer(store, NewMediaPool(store), slog.New(slog.NewTextHandler(io.Discard, nil)))
	var once sync.Once
	srv.onSnapshot = func() { once.Do(func() { store.Replace(next) }) }
	bound := make(chan struct{}, 1)
	srv.onListening = func(config.SIPListen) { bound <- struct{}{} }
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-runErr:
		case <-time.After(10 * time.Second):
			t.Errorf("server did not stop within 10s")
		}
	})
	select {
	case <-bound:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not bind within 5s")
	}

	u := newAuditUAC(t, 13780, "one-snapshot")
	u.establish()
	u.hangup()
	if got, stray := oldCarrier.invites.Load(), newCarrier.invites.Load(); got != 1 || stray != 0 {
		t.Errorf("reload after the call's snapshot: carrier from the snapshot got %d INVITE(s), the reloaded one %d; want 1 and 0",
			got, stray)
	}
}
