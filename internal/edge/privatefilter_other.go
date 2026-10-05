//go:build !linux

package edge

import "syscall"

// privateSocketFilter is a no-op where the kernel has no SO_ATTACH_FILTER:
// the private socket keeps the previous behaviour, the host settings
// (strict rp_filter or a firewall rule) remain the mitigation, and Run logs
// a warning.
var privateSocketFilter = func(string) (func(network, address string, c syscall.RawConn) error, error) {
	return nil, nil
}
