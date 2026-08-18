//go:build !windows

package client

import (
	"fmt"
	"os"
)

// restrictSecretFile narrows the mode after the rename. The temporary file was already created
// with it; this covers the case where an existing destination carried looser permissions.
func restrictSecretFile(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("restrict secret file: %w", err)
	}
	return nil
}
