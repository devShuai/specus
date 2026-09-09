//go:build !linux

package client

import "syscall"

// Everywhere but Linux the outbound socket is left to the operating system.
//
// The Linux build marks it so a policy routing rule can keep the egress's forwarded traffic on a
// physical interface. Windows and macOS have no equivalent that works without the elevated
// privileges the whole user-space design exists to avoid, so the loop-back risk there is handled by
// the forced-deny list refusing this node's own interface networks instead.
func bindEgressSocket(_ string, _ string, _ syscall.RawConn) error { return nil }
