package sig

import "sync"

// callSDPStore remembers each established call's A-leg offer SDP, keyed by
// Call-ID, so a later in-dialog INVITE can be recognized as a session-timer
// refresh (isRefreshReInvite compares its body against this stored value)
// without ever touching dialogSrv/aLeg for the re-INVITE itself — see
// bridge.onInvite's in-dialog branch.
//
// Deliberately a separate map in package sig rather than a field on
// callstate.Call: callstate must stay free of SDP/sig-specific concerns, so
// it can be reused (or read) without pulling in signaling internals.
type callSDPStore struct {
	mu   sync.Mutex
	sdps map[string][]byte
}

func newCallSDPStore() *callSDPStore {
	return &callSDPStore{sdps: make(map[string][]byte)}
}

// set stores sdp as callID's established SDP, overwriting any prior value.
func (c *callSDPStore) set(callID string, sdp []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sdps[callID] = sdp
}

// delete removes callID's entry, e.g. at call teardown.
func (c *callSDPStore) delete(callID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.sdps, callID)
}

// get returns callID's stored SDP, or ok=false if none is on record (no
// established call with that Call-ID, or it already tore down).
func (c *callSDPStore) get(callID string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	sdp, ok := c.sdps[callID]
	return sdp, ok
}
