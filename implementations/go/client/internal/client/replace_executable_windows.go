//go:build windows

package client

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const replaceFileWriteThrough = 0x00000001

var (
	kernel32ReplaceFile = syscall.NewLazyDLL("kernel32.dll")
	procReplaceFileW    = kernel32ReplaceFile.NewProc("ReplaceFileW")
)

func replaceExecutablePlatform(executable, candidate, backup string) error {
	if _, err := os.Lstat(backup); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			err = errors.New("reserved client update backup path already exists")
		}
		return err
	}
	if err := replaceFileWindows(executable, candidate, backup); err != nil {
		return fmt.Errorf("atomically install client update: %w", err)
	}
	return nil
}

func rollbackExecutablePlatform(executable, backup string) error {
	if err := replaceFileWindows(executable, backup, ""); err != nil {
		return fmt.Errorf("atomically restore client update backup: %w", err)
	}
	return nil
}

func replaceFileWindows(replaced, replacement, backup string) error {
	replacedPath, err := syscall.UTF16PtrFromString(replaced)
	if err != nil {
		return err
	}
	replacementPath, err := syscall.UTF16PtrFromString(replacement)
	if err != nil {
		return err
	}
	var backupPointer uintptr
	if backup != "" {
		backupPath, err := syscall.UTF16PtrFromString(backup)
		if err != nil {
			return err
		}
		backupPointer = uintptr(unsafe.Pointer(backupPath))
	}
	result, _, callErr := procReplaceFileW.Call(
		uintptr(unsafe.Pointer(replacedPath)),
		uintptr(unsafe.Pointer(replacementPath)),
		backupPointer,
		replaceFileWriteThrough,
		0,
		0,
	)
	if result == 0 {
		return callErr
	}
	return nil
}
