//go:build darwin

package client

import (
	"fmt"
	"net"
	"syscall"
)

// egressBoundInterface reads IP_BOUND_IF back from a connected socket.
func egressBoundInterface(conn net.Conn) (int, error) {
	source, ok := conn.(syscall.Conn)
	if !ok {
		return 0, fmt.Errorf("%T exposes no socket", conn)
	}
	raw, err := source.SyscallConn()
	if err != nil {
		return 0, err
	}
	var value int
	var getErr error
	if err := raw.Control(func(handle uintptr) {
		value, getErr = syscall.GetsockoptInt(int(handle), syscall.IPPROTO_IP, macosIPBoundIf)
	}); err != nil {
		return 0, err
	}
	return value, getErr
}
