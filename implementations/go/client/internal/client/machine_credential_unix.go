//go:build !windows

package client

import (
	"fmt"
	"os"
)

// assertSecretFilePrivate refuses a credential file that group or others can read.
//
// This is the check that actually protects the secret on disk, so it is a refusal rather than a
// warning: a warning on a file every other local account can read is a credential leak that
// scrolled past.
func assertSecretFilePrivate(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat secret file: %w", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("%w: %s has mode %04o, expected 0600; run chmod 600 %s",
			ErrSecretFileTooOpen, path, mode, path)
	}
	return nil
}
