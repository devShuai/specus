//go:build windows

package nat

import "golang.org/x/sys/windows"

func setReuseAddress(fd uintptr, enabled bool) error {
	value := 0
	if enabled {
		value = 1
	}
	return windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, value)
}
