//go:build windows

package peermesh

import (
	"net"

	"golang.org/x/sys/windows"
)

func setUDPTrafficClass(conn *net.UDPConn, trafficClass int) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		optionErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_TOS, trafficClass)
	}); err != nil {
		return err
	}
	return optionErr
}
