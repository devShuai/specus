//go:build !windows

package client

import (
	"errors"
	"fmt"
	"io"
	"os"
)

func replaceExecutablePlatform(executable, candidate, backup string) error {
	if _, err := os.Lstat(backup); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			err = errors.New("reserved client update backup path already exists")
		}
		return err
	}
	if err := os.Link(executable, backup); err != nil {
		if err := copyExecutableBackup(executable, backup); err != nil {
			return fmt.Errorf("backup current client executable: %w", err)
		}
	}
	// On POSIX rename replaces the destination atomically. The old inode remains reachable from
	// the backup hard link (or fallback copy), leaving no crash window with a missing executable.
	if err := os.Rename(candidate, executable); err != nil {
		_ = os.Remove(backup)
		return fmt.Errorf("atomically install client update: %w", err)
	}
	return nil
}

func rollbackExecutablePlatform(executable, backup string) error {
	// POSIX rename atomically replaces the failed image; a running failed child, if any, keeps its
	// already-open inode and cannot prevent restoration of the path.
	if err := os.Rename(backup, executable); err != nil {
		return fmt.Errorf("atomically restore client update backup: %w", err)
	}
	return nil
}

func copyExecutableBackup(sourcePath, targetPath string) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("current executable is not a regular file")
	}
	target, err := os.OpenFile(targetPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(target, source)
	syncErr := target.Sync()
	closeErr := target.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(targetPath)
		return fmt.Errorf("copy=%v sync=%v close=%v", copyErr, syncErr, closeErr)
	}
	return nil
}
