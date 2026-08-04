//go:build windows

package control

import "golang.org/x/sys/windows"

func setReuseAddress(fd uintptr, enabled bool) error {
	value := 0
	if enabled {
		value = 1
	}
	return windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, value)
}
