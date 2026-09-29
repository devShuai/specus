//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// A new file or directory is made owner-only and then passes the read-only check; one that still
// carries the ACL it inherited from the temporary directory does not.
func TestCheckPrivateMakesNewObjectsOwnerOnly(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "state")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := checkPrivate(directory, true); err != nil {
		t.Fatalf("a new directory was not made private: %v", err)
	}
	if err := checkPrivate(directory, false); err != nil {
		t.Fatalf("a private directory failed the check: %v", err)
	}

	inherited := filepath.Join(root, "inherited.json")
	if err := os.WriteFile(inherited, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkPrivate(inherited, false); !errors.Is(err, errUnsafeState) {
		t.Fatalf("a file with the temporary directory's inherited ACL passed: %v", err)
	}
	if err := checkPrivate(inherited, true); err != nil {
		t.Fatalf("a new file was not made private: %v", err)
	}
	if err := checkPrivate(inherited, false); err != nil {
		t.Fatalf("a private file failed the check: %v", err)
	}
}

// An allow entry for anyone else is refused, however it got there.
func TestCheckPrivateRefusesAnotherPrincipal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkPrivate(path, true); err != nil {
		t.Fatal(err)
	}
	// S-1-1-0 is Everyone; the SID form does not depend on the system language.
	if output, err := exec.Command("icacls", path, "/grant", "*S-1-1-0:(R)").CombinedOutput(); err != nil {
		t.Skipf("icacls could not add an entry: %v %s", err, output)
	}
	if err := checkPrivate(path, false); !errors.Is(err, errUnsafeState) {
		t.Fatalf("a file readable by Everyone passed: %v", err)
	}
}

func TestCheckPrivateRefusesALink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links need a privilege this account lacks: %v", err)
	}
	if err := checkPrivate(target, true); err != nil {
		t.Fatal(err)
	}
	if err := checkPrivate(link, false); !errors.Is(err, errUnsafeState) {
		t.Fatalf("a link to a private file passed: %v", err)
	}
}

// The state file is rewritten and checked every second. A check that starts a process costs a
// quarter of a second and failed outright on a busy machine; this one must stay far below that.
func TestCheckPrivateIsCheap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	for index := 0; index < 50; index++ {
		if err := checkPrivate(path, index == 0); err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("50 checks took %s", elapsed)
	}
}
