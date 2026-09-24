package edge

// Test-only views of the dialog table. Production code never looks a call
// up by Call-ID alone — every in-dialog path matches both tags — but a
// test that placed one call knows its Call-ID and nothing else.

// confirmed returns the confirmed record for a Call-ID, if there is one.
func (t *dialogTable) confirmed(callID string) (*dialog, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, d := range t.byCallID[callID] {
		if d.state == dialogConfirmed {
			return d, true
		}
	}
	return nil, false
}

// routeFor is confirmed plus the routing snapshot.
func (t *dialogTable) routeFor(callID string) (dialogRoute, bool) {
	d, ok := t.confirmed(callID)
	if !ok {
		return dialogRoute{}, false
	}
	return d.routeSnapshot(), true
}
