//go:build !windows

package peermesh

import (
	"net"

	"golang.org/x/sys/unix"
)

func setUDPTrafficClass(conn *net.UDPConn, trafficClass int) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS, trafficClass)
	}); err != nil {
		return err
	}
	return optionErr
}
