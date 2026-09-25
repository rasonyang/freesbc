package admin

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/freesbc/freesbc/internal/config"
)

// syncBuffer is a bytes.Buffer safe for the logger's concurrent writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// audit: P2-ADM-006
// A recovered handler panic is answered 500 without a stack in the body,
// but the log line must carry the stack: without it the panic site is
// lost.
func TestRecoverMWLogsStack(t *testing.T) {
	var logs syncBuffer
	s := New(&config.AdminConfig{Listen: "127.0.0.1:0"}, config.NewStore(mustCfg(t)), emptyDeps(),
		slog.New(slog.NewTextHandler(&logs, nil)), "")
	h := s.recoverMW(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		auditPanickingHandler()
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", rr.Code)
	}
	body, _ := io.ReadAll(rr.Body)
	if strings.Contains(string(body), "goroutine") {
		t.Errorf("500 body leaks a stack: %s", body)
	}
	if got := logs.String(); !strings.Contains(got, "auditPanickingHandler") {
		t.Errorf("panic log has no stack naming the panic site:\n%s", got)
	}
}

func auditPanickingHandler() { panic("audit: admin handler bug") }
