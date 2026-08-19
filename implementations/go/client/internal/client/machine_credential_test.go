package client

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// An existing configuration carries the secret inline; that has to keep working.
func TestPlainSecretIsUsedAsIs(t *testing.T) {
	secret, err := resolveSecret("  s3cret-value  ")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if secret != "s3cret-value" {
		t.Fatalf("secret = %q, want the trimmed literal", secret)
	}
	if secretIsIndirect("s3cret-value") {
		t.Fatal("an inline secret is not indirect")
	}
}

// Naming the secret indirectly is what keeps it out of a file that gets copied around.
func TestSecretCanComeFromTheEnvironment(t *testing.T) {
	t.Setenv("SPECUS_TEST_SECRET", "from-the-environment")

	secret, err := resolveSecret("env:SPECUS_TEST_SECRET")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if secret != "from-the-environment" {
		t.Fatalf("secret = %q", secret)
	}
	if !secretIsIndirect("env:SPECUS_TEST_SECRET") {
		t.Fatal("an env reference is indirect")
	}

	// An unset or empty variable must fail rather than authenticate as the empty string.
	if _, err := resolveSecret("env:SPECUS_TEST_ABSENT"); err == nil {
		t.Fatal("an unset variable must be an error")
	}
	t.Setenv("SPECUS_TEST_BLANK", "   ")
	if _, err := resolveSecret("env:SPECUS_TEST_BLANK"); err == nil {
		t.Fatal("a blank variable must be an error")
	}
	if _, err := resolveSecret("env:"); err == nil {
		t.Fatal("a reference naming no variable must be an error")
	}
}

func TestSecretCanComeFromItsOwnFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("from-the-file\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	secret, err := resolveSecret("file:" + path)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if secret != "from-the-file" {
		t.Fatalf("secret = %q, want the trimmed file content", secret)
	}
	if !secretIsIndirect("file:" + path) {
		t.Fatal("a file reference is indirect")
	}

	if _, err := resolveSecret("file:"); err == nil {
		t.Fatal("a reference naming no path must be an error")
	}
	if _, err := resolveSecret("file:" + filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("a missing secret file must be an error")
	}

	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, []byte("  \n"), 0o600); err != nil {
		t.Fatalf("write empty: %v", err)
	}
	if _, err := resolveSecret("file:" + empty); err == nil {
		t.Fatal("an empty secret file must be an error, not an empty credential")
	}
}

// A credential every other local account can read is already leaked. Refusing it is the point:
// a warning here would just scroll past.
func TestSecretFileReadableByOthersIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not the access control mechanism on Windows")
	}
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("exposed"), 0o644); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	_, err := resolveSecret("file:" + path)
	if !errors.Is(err, ErrSecretFileTooOpen) {
		t.Fatalf("err = %v, want ErrSecretFileTooOpen", err)
	}
	// The message has to say how to fix it, or the refusal is just an obstacle.
	if !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("error should tell the operator how to fix it: %v", err)
	}

	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := resolveSecret("file:" + path); err != nil {
		t.Fatalf("an owner-only file must be accepted: %v", err)
	}
}

// A secret written by this client must be readable by it afterwards: the writer and the checker
// have to agree on what counts as private.
func TestWrittenSecretFilesPassTheirOwnCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "written", "secret")
	if err := writeSecretFile(path, []byte("round-trip")); err != nil {
		t.Fatalf("write: %v", err)
	}

	secret, err := resolveSecret("file:" + path)
	if err != nil {
		t.Fatalf("a file this client wrote must pass its own check: %v", err)
	}
	if secret != "round-trip" {
		t.Fatalf("secret = %q", secret)
	}
}

// Rotation has to take effect on the next reconnect, not the next restart. The client keeps the
// reference rather than the resolved value precisely so it can re-read the source.
func TestRotatingAnIndirectSecretIsPickedUpWithoutRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := writeSecretFile(path, []byte("original")); err != nil {
		t.Fatalf("write: %v", err)
	}
	reference := "file:" + path

	first, err := resolveSecret(reference)
	if err != nil || first != "original" {
		t.Fatalf("first resolve = %q, %v", first, err)
	}

	// The operator rotates the credential on the server and writes the new one here.
	if err := writeSecretFile(path, []byte("rotated")); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	second, err := resolveSecret(reference)
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if second != "rotated" {
		t.Fatalf("secret = %q, want the rotated value; the client would still be using the old one",
			second)
	}
}

// The same for an environment-sourced credential, which a supervisor can replace on restart of the
// unit without the config file changing.
func TestRotatingAnEnvironmentSecretIsPickedUp(t *testing.T) {
	t.Setenv("SPECUS_ROTATION_TEST", "before")
	if secret, _ := resolveSecret("env:SPECUS_ROTATION_TEST"); secret != "before" {
		t.Fatalf("secret = %q", secret)
	}

	t.Setenv("SPECUS_ROTATION_TEST", "after")
	secret, err := resolveSecret("env:SPECUS_ROTATION_TEST")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if secret != "after" {
		t.Fatalf("secret = %q, want the rotated value", secret)
	}
}

// A configuration that fails to resolve must be rejected at startup, where an operator sees it,
// rather than at the first login attempt in the field.
func TestLoadConfigRejectsAnUnresolvableSecretReference(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.jsonc")
	config := `{"serverBaseUrl":"https://example.test","apiKey":"key","secret":"env:SPECUS_ABSENT_VAR"}`
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := LoadConfig(path); err == nil {
		t.Fatal("an unresolvable secret reference must fail at load")
	} else if !strings.Contains(err.Error(), "resolve secret") {
		t.Fatalf("error should name the failure: %v", err)
	}
}

// The reference must survive loading, or rotation silently stops working.
func TestLoadConfigKeepsTheSecretReference(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "secret")
	if err := writeSecretFile(secretPath, []byte("stored")); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	configPath := filepath.Join(t.TempDir(), "client.jsonc")
	// Encoded rather than hand-escaped: a Windows temp path is full of backslashes, and getting
	// that wrong makes the test fail for a reason that has nothing to do with the behaviour.
	reference, err := json.Marshal("file:" + secretPath)
	if err != nil {
		t.Fatalf("encode reference: %v", err)
	}
	config := `{"serverBaseUrl":"https://example.test","apiKey":"key","secret":` +
		string(reference) + `}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	loaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !loaded.SecretIsIndirect {
		t.Fatal("an indirect secret must be recorded as such")
	}
	if !strings.HasPrefix(loaded.Secret, "file:") {
		t.Fatalf("Secret = %q, want the reference kept so rotation can re-read it", loaded.Secret)
	}
}
