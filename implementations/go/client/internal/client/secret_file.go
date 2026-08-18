package client

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// writeSecretFile stores a secret so no other local account can read it and no reader can observe a
// half-written file.
//
// Writing straight to the destination has two failure modes. If the process dies mid-write the
// client is left with a truncated private key and silently loses its peer identity on next start.
// And the file exists, briefly, before anything narrows its permissions. Writing to a temporary
// file created with the restrictive mode and renaming it into place closes both: the permissions
// are never wrong even for an instant, and the rename is atomic, so a reader sees either the old
// file or the complete new one.
func writeSecretFile(path string, content []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create secret directory: %w", err)
	}
	// The temporary file shares the destination directory so the rename stays on one filesystem,
	// which is what makes it atomic.
	temporary, err := os.CreateTemp(directory, ".secret-*.tmp")
	if err != nil {
		return fmt.Errorf("create secret temp file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if err := temporary.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		temporary.Close()
		return fmt.Errorf("restrict secret temp file: %w", err)
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return fmt.Errorf("write secret temp file: %w", err)
	}
	// Durability before the rename: a rename that outlives its own contents would leave an empty
	// file that reads as a corrupt key.
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync secret temp file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close secret temp file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace secret file: %w", err)
	}
	if err := restrictSecretFile(path); err != nil {
		return err
	}
	return nil
}
