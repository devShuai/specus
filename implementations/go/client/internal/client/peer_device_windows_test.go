//go:build windows

package client

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBundledWintunCanBeExtracted(t *testing.T) {
	t.Setenv("SPECUS_PEER_MESH_NATIVE_CACHE_DIR", t.TempDir())

	extracted, err := extractBundledWintun()
	if err != nil {
		t.Fatalf("extractBundledWintun() error = %v", err)
	}
	if extracted == "" {
		t.Fatal("extractBundledWintun() returned empty path")
	}
	if filepath.Base(extracted) != "wintun.dll" {
		t.Fatalf("extracted path = %q, want wintun.dll", extracted)
	}
	info, err := os.Stat(extracted)
	if err != nil {
		t.Fatalf("stat extracted wintun.dll: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("extracted wintun.dll is empty")
	}
}

func TestWintunCandidatesPreferConfiguredThenBundled(t *testing.T) {
	cacheDir := t.TempDir()
	t.Setenv("SPECUS_PEER_MESH_NATIVE_CACHE_DIR", cacheDir)
	t.Setenv("SPECUS_PEER_MESH_WINTUN_DLL", `C:\custom\wintun.dll`)

	candidates, candidateErrors := wintunCandidates()
	if len(candidateErrors) != 0 {
		t.Fatalf("wintunCandidates() errors = %v", candidateErrors)
	}
	if len(candidates) < 2 {
		t.Fatalf("wintunCandidates() too short: %v", candidates)
	}
	if candidates[0] != `C:\custom\wintun.dll` {
		t.Fatalf("first candidate = %q, want configured dll", candidates[0])
	}
	wantBundled := filepath.Join(cacheDir, "windows", wintunArchDir(), "wintun.dll")
	if candidates[1] != wantBundled {
		t.Fatalf("second candidate = %q, want bundled %q", candidates[1], wantBundled)
	}
}
