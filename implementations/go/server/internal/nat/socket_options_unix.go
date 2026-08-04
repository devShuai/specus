//go:build !windows

package nat

import "golang.org/x/sys/unix"

func setReuseAddress(fd uintptr, enabled bool) error {
	value := 0
	if enabled {
		value = 1
	}
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, value)
}
