package client

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWriteSecretFileCreatesTheFileWithItsContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "peer-private.x25519")

	if err := writeSecretFile(path, []byte("secret-material\n")); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(stored) != "secret-material\n" {
		t.Fatalf("stored %q, want the exact content", stored)
	}
}

// A private key readable by other local accounts is the same as no protection at all.
func TestWriteSecretFileRestrictsPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not the access control mechanism on Windows")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "keys", "peer-private.x25519")

	if err := writeSecretFile(path, []byte("secret")); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("file mode = %o, want 600", mode)
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat parent: %v", err)
	}
	if mode := parent.Mode().Perm(); mode != 0o700 {
		t.Fatalf("directory mode = %o, want 700", mode)
	}
}

// Replacing an existing key must not widen its permissions or leave the old content behind.
func TestWriteSecretFileReplacesAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer-private.x25519")

	if err := writeSecretFile(path, []byte("first")); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := writeSecretFile(path, []byte("second-and-longer")); err != nil {
		t.Fatalf("second write: %v", err)
	}

	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(stored) != "second-and-longer" {
		t.Fatalf("stored %q, want the replacement content", stored)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Fatalf("file mode after replace = %o, want 600", mode)
		}
	}
}

// No temporary file may survive a successful write; a stray copy of the key is still the key.
func TestWriteSecretFileLeavesNoTemporaryBehind(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "peer-private.x25519")

	if err := writeSecretFile(path, []byte("secret")); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			t.Fatalf("temporary file survived: %s", entry.Name())
		}
	}
	if len(entries) != 1 {
		t.Fatalf("directory holds %d entries, want only the secret", len(entries))
	}
}
