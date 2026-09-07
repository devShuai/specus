//go:build !windows

package main

import (
	"os"
	"syscall"
)

func checkPrivate(path string, created bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return errUnsafeState
	}
	return nil
}
func processAlive(pid int) bool { return pid > 0 && syscall.Kill(pid, 0) == nil }
