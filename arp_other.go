//go:build !linux

package main

import "time"

// arpAvailable reports whether ARP discovery is supported on this platform.
// ARP ping is implemented for Linux only (raw AF_PACKET sockets); everywhere
// else the caller falls back to ICMP/TCP discovery.
func arpAvailable() bool { return false }

// arpDiscover is a no-op on non-Linux platforms; ok=false signals the caller to
// use another discovery method.
func arpDiscover(hosts []string, timeout time.Duration) (map[string]bool, bool) {
	return nil, false
}
