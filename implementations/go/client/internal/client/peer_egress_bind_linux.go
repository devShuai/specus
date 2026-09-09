//go:build linux

package client

import "syscall"

// Keeping the egress's own forwarded traffic off the tunnel.
//
// The egress sends a consumer's traffic to the real internet. If the outbound socket picked up this
// node's own tunnel route, that traffic would go back into the mesh instead of out, and on a node
// that is both an egress and a consumer of another egress it would loop. Marking the socket lets a
// policy routing rule steer it to the physical interface regardless of what the tunnel did to the
// main table.
//
// Set best-effort. A node without the matching rule, or without permission to set a mark, still
// works whenever the tunnel did not claim the default route, so failing the connect here would
// break the common case in order to protect the uncommon one. Only the standard library is used,
// because the client module carries no third-party dependencies.
const egressSocketMark = 0x5350

func bindEgressSocket(_ string, _ string, connection syscall.RawConn) error {
	if connection == nil {
		return nil
	}
	_ = connection.Control(func(handle uintptr) {
		_ = syscall.SetsockoptInt(int(handle), syscall.SOL_SOCKET, syscall.SO_MARK, egressSocketMark)
	})
	return nil
}
