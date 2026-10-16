//go:build !linux

package media

// batchRelayAvailable is false where the kernel has no recvmmsg/sendmmsg:
// every loop uses relayPlain, whatever batchRelay says.
const batchRelayAvailable = false

// relayBatched is never called here (forward checks batchRelayAvailable);
// it exists so relay.go compiles on every platform.
func (l *relayLoop) relayBatched() { l.relayPlain() }
