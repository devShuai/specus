//go:build !linux && !windows && !darwin

package client

import "syscall"

// Everywhere else the outbound socket is left to the operating system. None of these platforms can
// be an egress consumer (egressRouteTakeoverSupported is false), so this node installs no tunnel
// routes for the socket to follow.
func newEgressSocketBinder(tunnel func() string) *egressSocketBinder {
	return &egressSocketBinder{tunnel: tunnel}
}

func (binder *egressSocketBinder) control(_ string, _ string, _ syscall.RawConn) error { return nil }
