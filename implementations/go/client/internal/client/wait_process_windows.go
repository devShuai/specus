//go:build windows

package client

import (
	"errors"
	"fmt"
	"syscall"
	"time"
)

const (
	processSynchronize = 0x00100000
	waitObject0        = 0x00000000
	waitTimeout        = 0x00000102
	waitFailed         = 0xFFFFFFFF
)

var (
	kernel32WaitProcess = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess     = kernel32WaitProcess.NewProc("OpenProcess")
	procWaitSingle      = kernel32WaitProcess.NewProc("WaitForSingleObject")
	procCloseHandle     = kernel32WaitProcess.NewProc("CloseHandle")
)

func waitForProcessExitPlatform(pid int, timeout time.Duration) error {
	if pid <= 0 {
		return errors.New("invalid process id")
	}
	handle, _, openErr := procOpenProcess.Call(processSynchronize, 0, uintptr(uint32(pid)))
	if handle == 0 {
		// ERROR_INVALID_PARAMETER means the PID no longer exists, which is exactly the state the
		// helper needs. Other errors (notably access denied) must fail closed.
		if errors.Is(openErr, syscall.Errno(87)) { // ERROR_INVALID_PARAMETER
			return nil
		}
		return fmt.Errorf("open client process %d for synchronization: %w", pid, openErr)
	}
	defer procCloseHandle.Call(handle)
	milliseconds := timeout.Milliseconds()
	if milliseconds < 1 {
		milliseconds = 1
	}
	if milliseconds > int64(^uint32(0)-1) {
		milliseconds = int64(^uint32(0) - 1)
	}
	result, _, waitErr := procWaitSingle.Call(handle, uintptr(uint32(milliseconds)))
	switch uint32(result) {
	case waitObject0:
		return nil
	case waitTimeout:
		return fmt.Errorf("timed out waiting for client process %d to exit", pid)
	case waitFailed:
		return fmt.Errorf("wait for client process %d to exit: %w", pid, waitErr)
	default:
		return fmt.Errorf("wait for client process %d returned status 0x%x", pid, result)
	}
}
