package proxy

import (
	"sync"
	"time"
)

// call is one proxied dialog and the media anchored for it.
//
// The proxy does not own the dialog — the endpoints do — so this record
// holds only what the proxy needs: enough identity to match an in-dialog
// request, and the media session whose lifetime must follow the dialog's.
type call struct {
	// CallID, FromTag and ToTag are the RFC 3261 §12 dialog identifier.
	// ToTag is empty until a 2xx (or a provisional with a tag) arrives.
	CallID  string
	FromTag string
	ToTag   string

	// Inbound is true when the call came FROM FreeSWITCH toward a
	// registered client; false when a client called in.
	Inbound bool

	// PublicRemote and PrivateRemote are the two endpoints' signaling
	// addresses, for logs and for routing in-dialog requests.
	PublicRemote  string
	PrivateRemote string
	Transport     string

	Media     *mediaSession
	StartedAt time.Time
}

// callTable indexes live calls by Call-ID.
//
// One entry per Call-ID rather than per full dialog identifier: FreeSBC
// anchors one media session per call, and a forking upstream that produced
// two dialogs on one Call-ID would need two media sessions — which is a
// B2BUA's problem, not a proxy's. The limitation is real and documented;
// what matters here is that the table can never grow without bound,
// because every entry is removed when its media session ends.
type callTable struct {
	mu    sync.Mutex
	calls map[string]*call
}

func newCallTable() *callTable { return &callTable{calls: map[string]*call{}} }

func (t *callTable) put(c *call) {
	t.mu.Lock()
	prev := t.calls[c.CallID]
	t.calls[c.CallID] = c
	t.mu.Unlock()
	// Replacing an entry (a re-INVITE-shaped retry, or a client that
	// reused a Call-ID) must not orphan the previous media session.
	if prev != nil && prev != c && prev.Media != nil {
		_ = prev.Media.Close()
	}
}

func (t *callTable) get(callID string) (*call, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.calls[callID]
	return c, ok
}

// remove deletes a call and returns it, so the caller can close its media
// exactly once.
func (t *callTable) remove(callID string) (*call, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.calls[callID]
	if ok {
		delete(t.calls, callID)
	}
	return c, ok
}

func (t *callTable) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.calls)
}

// closeAll tears down every call's media. Called at shutdown so no socket,
// port reservation or relay goroutine outlives the process's SIP plane.
func (t *callTable) closeAll() {
	t.mu.Lock()
	calls := make([]*call, 0, len(t.calls))
	for id, c := range t.calls {
		calls = append(calls, c)
		delete(t.calls, id)
	}
	t.mu.Unlock()
	for _, c := range calls {
		if c.Media != nil {
			_ = c.Media.Close()
		}
	}
}
